//! Tearing down a mount whose NAS has stopped answering.
//!
//! The disconnect that hung. `umount_and_join` unmounts and then *joins* the
//! session's threads, and both halves stick together: a worker inside a
//! callback the NAS is not answering keeps the kernel counting the mount as
//! busy, so `fusermount -u` fails — and the session then never sees the end of
//! `/dev/fuse`, so the join waits for a thread waiting for the unmount that
//! just failed. The volume stayed mounted and the caller never returned, which
//! is why a disconnect hung until somebody ran `umount` by hand.
//!
//! Ignored by default: it needs a real FUSE mount, which CI containers do not
//! have. Run it deliberately with `--ignored`, on a machine with `/dev/fuse`.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use synology_filestation_core::SynologyClient;
use synology_filestation_fuse::{spawn_mount, MountOptions};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Longer than any deadline inside the client, so a request that reaches this
/// server hangs until something else gives up on it.
const FOREVER: Duration = Duration::from_secs(600);

/// How long the directory may stay unusable. This is the half that needed
/// somebody with `sudo`.
const FREED_BY: Duration = Duration::from_secs(30);

/// How long the whole teardown may take. Longer on purpose: it waits for the
/// outstanding request, because the worker inside it is still using the
/// runtime.
const EVENTUALLY: Duration = Duration::from_secs(240);

fn is_mounted(mountpoint: &Path) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|m| {
            m.lines()
                .any(|l| l.contains(&*mountpoint.to_string_lossy()))
        })
        .unwrap_or(false)
}

#[test]
#[ignore = "needs a real FUSE mount; run with --ignored"]
fn a_disconnect_finishes_and_leaves_nothing_mounted() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");

    let server = rt.block_on(async {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webapi/auth.cgi"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true, "data": {"sid": "abc"}
            })))
            .mount(&server)
            .await;
        // Everything else takes longer than anybody is prepared to wait, which
        // is what a NAS does when the route to it disappears.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_delay(FOREVER))
            .mount(&server)
            .await;
        server
    });

    let url = server.uri();
    let hostport = url.strip_prefix("http://").expect("http").to_string();
    let (host, port) = hostport.split_once(':').expect("host:port");
    let client = Arc::new(SynologyClient::new(
        host,
        port.parse().expect("a port"),
        false,
    ));
    rt.block_on(client.login("someone", "", None))
        .expect("logged in");

    let dir = tempfile::tempdir().expect("a mountpoint");
    let mountpoint = dir.path().to_path_buf();
    let handle = spawn_mount(
        client,
        rt.handle().clone(),
        mountpoint.clone(),
        MountOptions::default(),
    )
    .expect("mounted");

    // Something asking the filesystem a question the NAS will not answer. This
    // is what makes the mount busy, and it never returns.
    let looking = mountpoint.clone();
    std::thread::spawn(move || {
        let _ = std::fs::read_dir(&looking).map(Iterator::count);
    });
    std::thread::sleep(Duration::from_millis(500));

    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let started = Instant::now();
        handle.stop();
        let _ = done.send(started.elapsed());
    });

    // What has to be prompt is the *mountpoint*. That is the half that needed
    // somebody with `sudo`: a volume that will not come down leaves the
    // directory unusable, and the next connection fails on it with "Transport
    // endpoint is not connected".
    let freed = Instant::now();
    while is_mounted(&mountpoint) {
        assert!(
            freed.elapsed() < FREED_BY,
            "{} is still mounted after {:?} — this is the one that needed sudo",
            mountpoint.display(),
            freed.elapsed()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    eprintln!("mountpoint freed in {:?}", freed.elapsed());

    // The call itself takes as long as the outstanding request does, and that
    // is deliberate: the worker inside it is still using the Tokio runtime, and
    // returning before it finishes is what lets a caller drop the runtime under
    // it — which panics rather than failing quietly. Nobody is watching this
    // one, so it can afford to be right.
    let took = finished
        .recv_timeout(EVENTUALLY)
        .unwrap_or_else(|_| panic!("teardown never finished, even after {EVENTUALLY:?}"));
    eprintln!("teardown finished in {took:?}");
}
