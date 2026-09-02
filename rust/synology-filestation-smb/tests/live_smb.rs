//! Live integration test against a real NAS — `#[ignore]`d by default because
//! it needs credentials + reachability that CI doesn't have.
//!
//! Run it (mirrors `spikes/smb-spike`):
//!
//! ```text
//! SMB2_HOST=e4e-nas.ucsd.edu SMB2_DOMAIN=KRG \
//! SMB2_USER=c.crutchfield.642 SMB2_PASS='…' \
//! SMB2_LOGICAL='/fishsense_data/REEF/.../P8010001.ORF' \
//! nix develop ../.. -c cargo test -p synology-filestation-smb -- --ignored --nocapture
//! ```
//!
//! It proves the transport end-to-end: connect + AD auth, stat, a ranged read,
//! and a whole-file pipelined read, and checks the two read paths agree on the
//! leading bytes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use synology_filestation_core::SynoFsError;
use synology_filestation_smb::{BoxedStream, SmbConfig, SmbTransport};

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Require the three connection env vars plus a fourth (a path), or panic.
fn require4(fourth: &str) -> (String, String, String, String) {
    match (
        env("SMB2_HOST"),
        env("SMB2_USER"),
        env("SMB2_PASS"),
        env(fourth),
    ) {
        (Some(h), Some(u), Some(p), Some(x)) => (h, u, p, x),
        _ => panic!("set SMB2_HOST, SMB2_USER, SMB2_PASS, {fourth}"),
    }
}

async fn connect_from_env(host: String, user: String, pass: String) -> SmbTransport {
    let mut cfg = SmbConfig::new(host, user, pass);
    cfg.domain = env("SMB2_DOMAIN").unwrap_or_default();
    SmbTransport::connect(&cfg)
        .await
        .expect("connect + auth should succeed")
}

/// A per-run-unique path under the temp dir, so concurrent/repeated runs (or a
/// leftover file from a crashed run) never collide.
fn scratch_local(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("smb-live-{}-{}-{name}", std::process::id(), nanos))
}

fn report_throughput(label: &str, bytes: u64, elapsed: std::time::Duration) {
    let mib = bytes as f64 / (1024.0 * 1024.0);
    let rate = if elapsed.as_secs_f64() > 0.0 {
        mib / elapsed.as_secs_f64()
    } else {
        f64::INFINITY
    };
    println!("  {label}: {bytes} bytes in {elapsed:.2?}  ({rate:.1} MiB/s)");
}

#[tokio::test]
#[ignore = "needs a reachable NAS + credentials; run with --ignored"]
async fn live_read_over_smb() {
    let (host, user, pass, logical) = match (
        env("SMB2_HOST"),
        env("SMB2_USER"),
        env("SMB2_PASS"),
        env("SMB2_LOGICAL"),
    ) {
        (Some(h), Some(u), Some(p), Some(l)) => (h, u, p, l),
        _ => panic!("set SMB2_HOST, SMB2_USER, SMB2_PASS, SMB2_LOGICAL"),
    };

    let mut cfg = SmbConfig::new(host, user, pass);
    cfg.domain = env("SMB2_DOMAIN").unwrap_or_default();

    let smb = SmbTransport::connect(&cfg)
        .await
        .expect("connect + auth should succeed");

    let meta = smb.stat(&logical).await.expect("stat should succeed");
    assert!(!meta.is_directory, "expected a file");
    assert!(meta.size > 0, "expected a non-empty file");
    println!("stat: {} bytes", meta.size);

    // Ranged read (the transport's core operation).
    let want = 262_144.min(meta.size);
    let ranged = smb.read(&logical, 0, want).await.expect("ranged read");
    assert_eq!(ranged.len() as u64, want, "ranged read length");

    // Whole-file read (pipelined; handles files past MaxReadSize).
    let full = smb.read_full(&logical).await.expect("whole-file read");
    assert_eq!(
        full.len() as u64,
        meta.size,
        "whole-file length matches stat"
    );

    // The two paths must agree on the overlapping prefix.
    assert_eq!(
        &full[..want as usize],
        &ranged[..],
        "ranged and whole-file reads disagree on the prefix"
    );
    println!(
        "OK: ranged + whole-file reads agree; {} bytes total",
        full.len()
    );
}

/// Write-path validation — separate and doubly-gated so it never writes to the
/// NAS by accident. Provide `SMB2_WRITE_LOGICAL` pointing at a **scratch** file
/// you don't mind being created/overwritten/deleted (e.g. a temp share):
///
/// ```text
/// SMB2_HOST=e4e-nas.ucsd.edu SMB2_DOMAIN=KRG SMB2_USER=… SMB2_PASS='…' \
/// SMB2_WRITE_LOGICAL='/scratch/smb-spike-write-test.bin' \
/// nix develop ../.. -c cargo test -p synology-filestation-smb -- --ignored --nocapture write_
/// ```
///
/// Exercises both `write_atomic` paths: the create case (single rename) and the
/// overwrite case (move-aside), reading the bytes back each time, then cleans up.
#[tokio::test]
#[ignore = "writes to the NAS; set SMB2_WRITE_LOGICAL to a scratch path and run with --ignored"]
async fn write_roundtrip_over_smb() {
    let (host, user, pass, logical) = match (
        env("SMB2_HOST"),
        env("SMB2_USER"),
        env("SMB2_PASS"),
        env("SMB2_WRITE_LOGICAL"),
    ) {
        (Some(h), Some(u), Some(p), Some(l)) => (h, u, p, l),
        _ => panic!("set SMB2_HOST, SMB2_USER, SMB2_PASS, SMB2_WRITE_LOGICAL (a scratch path)"),
    };

    let mut cfg = SmbConfig::new(host, user, pass);
    cfg.domain = env("SMB2_DOMAIN").unwrap_or_default();
    let smb = SmbTransport::connect(&cfg).await.expect("connect + auth");

    // 1. Create case: target should not exist → single-rename fast path.
    let first = b"smb write roundtrip: create".to_vec();
    smb.write_atomic(&logical, &first)
        .await
        .expect("create write");
    let back = smb.read_full(&logical).await.expect("read back create");
    assert_eq!(back.as_ref(), first.as_slice(), "create bytes round-trip");

    // 2. Overwrite case: target now exists → move-aside replace path.
    let second = b"smb write roundtrip: overwrite (longer than the first payload)".to_vec();
    smb.write_atomic(&logical, &second)
        .await
        .expect("overwrite write");
    let back = smb.read_full(&logical).await.expect("read back overwrite");
    assert_eq!(
        back.as_ref(),
        second.as_slice(),
        "overwrite bytes round-trip"
    );

    // 3. stat agrees, then clean up the scratch file.
    let meta = smb.stat(&logical).await.expect("stat after write");
    assert_eq!(meta.size, second.len() as u64);
    let _ = smb.delete(&logical).await; // best-effort cleanup

    println!("OK: write create + overwrite round-trip; scratch cleaned up");
}

/// Streaming write (`write_from_path`) — the path Python `upload` /
/// `upload_from_path` actually use. Streams a local file larger than the 8 MiB
/// MaxWriteSize (so the writer chunks) to `SMB2_WRITE_LOGICAL`, reads it back,
/// verifies the bytes, and cleans up both ends. Prints throughput.
#[tokio::test]
#[ignore = "streams a file to the NAS; set SMB2_WRITE_LOGICAL to a scratch path and run with --ignored"]
async fn write_from_path_stream_over_smb() {
    let (host, user, pass, logical) = require4("SMB2_WRITE_LOGICAL");
    let smb = connect_from_env(host, user, pass).await;

    // Deterministic payload, > MaxWriteSize so the streaming write chunks.
    let len = 12 * 1024 * 1024usize;
    let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let src = scratch_local("stream-src.bin");
    std::fs::write(&src, &payload).expect("write local source file");

    let start = std::time::Instant::now();
    let write_res = smb.write_from_path(&logical, &src).await;
    let elapsed = start.elapsed();
    let readback = smb.read_full(&logical).await;

    // Best-effort cleanup BEFORE asserting, so a failed assertion never leaves
    // the NAS scratch file or the local temp behind.
    let _ = smb.delete(&logical).await;
    let _ = std::fs::remove_file(&src);

    write_res.expect("streaming write to NAS");
    report_throughput("write_from_path", len as u64, elapsed);
    let back = readback.expect("read back");
    assert_eq!(back.len(), len, "size round-trip");
    assert_eq!(back.as_ref(), payload.as_slice(), "bytes round-trip");
    println!(
        "OK: streaming write ({} MiB) round-trip; cleaned up",
        len / (1024 * 1024)
    );
}

/// Streaming read (`read_to_path`) — the path Python `download_to` /
/// `download_to_path` actually use. Streams `SMB2_LOGICAL` to a local temp file
/// and verifies it matches both `stat` and a whole-file read. Prints throughput.
#[tokio::test]
#[ignore = "streams a NAS file to disk; set SMB2_LOGICAL and run with --ignored"]
async fn read_to_path_stream_over_smb() {
    let (host, user, pass, logical) = require4("SMB2_LOGICAL");
    let smb = connect_from_env(host, user, pass).await;

    let meta = smb.stat(&logical).await.expect("stat");
    let dest = scratch_local("stream-dst.bin");

    let start = std::time::Instant::now();
    let read_res = smb.read_to_path(&logical, &dest).await;
    let elapsed = start.elapsed();
    let on_disk = std::fs::read(&dest);
    let whole = smb.read_full(&logical).await;

    // Best-effort cleanup BEFORE asserting, so a failure leaves nothing behind.
    let _ = std::fs::remove_file(&dest);

    read_res.expect("streaming read to disk");
    report_throughput("read_to_path", meta.size, elapsed);
    let on_disk = on_disk.expect("read local dest");
    assert_eq!(on_disk.len() as u64, meta.size, "size matches stat");
    let whole = whole.expect("whole-file read");
    assert_eq!(
        on_disk,
        whole.as_ref(),
        "streamed-to-disk bytes match the whole-file read"
    );
    println!(
        "OK: streaming read ({} bytes) to disk matches whole-file read; cleaned up",
        meta.size
    );
}

/// The tunnelled mount's recovery, exercised on a plain TCP stream because the
/// shape is what matters: a transport running on a stream somebody else opened.
///
/// Off campus that stream comes out of an in-process OpenVPN tunnel, and when
/// it ended the mount had no way back — `SmbClient` will not dial the address
/// at the far end of a tunnel behind the caller's back, so the transport was
/// built unable to reconnect at all. Every later operation then failed
/// `Disconnected` against a session nothing would rebuild, the
/// transport-selection breaker re-probed the same corpse every 30 s, and the
/// mount served the rest of its life off the HTTP fallback.
///
/// So: kill the socket underneath a live session and require the transport to
/// come back on a stream the redial closure opens.
///
/// ```text
/// SMB2_HOST=e4e-nas.ucsd.edu SMB2_DOMAIN=KRG SMB2_USER=… SMB2_PASS='…' \
/// SMB2_LOGICAL='/fishsense_data/…/P8010001.ORF' \
/// nix develop ../.. -c cargo test -p synology-filestation-smb -- --ignored --nocapture reopens
/// ```
#[tokio::test]
#[ignore = "requires a reachable NAS + credentials; run with --ignored"]
async fn a_dead_stream_reopens_itself() {
    let (host, user, pass, logical) = require4("SMB2_LOGICAL");
    let mut cfg = SmbConfig::new(host.clone(), user, pass);
    cfg.domain = env("SMB2_DOMAIN").unwrap_or_default();
    let addr = cfg.addr();

    // The stream the session runs on, plus a second descriptor onto the same
    // socket — the only way to end it from outside once the transport owns it.
    let dialled = std::net::TcpStream::connect(&addr).expect("dial the NAS");
    let killer = dialled.try_clone().expect("a second handle on the socket");
    dialled
        .set_nonblocking(true)
        .expect("nonblocking for tokio");
    let stream = tokio::net::TcpStream::from_std(dialled).expect("adopt the socket");

    let redials = Arc::new(AtomicUsize::new(0));
    let counted = redials.clone();
    let redial_addr = addr.clone();
    let smb = SmbTransport::over_with_redial(stream, &cfg, move || {
        let counted = counted.clone();
        let addr = redial_addr.clone();
        Box::pin(async move {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::net::TcpStream::connect(&addr)
                .await
                .map(|s| Box::new(s) as BoxedStream)
                .map_err(|e| SynoFsError::Io(format!("redial: {e}")))
        })
    })
    .await
    .expect("connect + auth over the supplied stream");

    let before = smb.stat(&logical).await.expect("stat on the first session");
    assert_eq!(redials.load(Ordering::SeqCst), 0, "nothing to redial yet");

    // End the socket under the live session.
    killer
        .shutdown(std::net::Shutdown::Both)
        .expect("close the socket out from under the session");

    // The operation that meets the dead link fails and flags it. That failure
    // is the ordinary one — what used to be wrong is everything after it.
    let met_it = smb.stat(&logical).await;
    assert!(met_it.is_err(), "the session it was using is gone");

    // And the next one rebuilds on a stream the closure opened.
    let after = smb
        .stat(&logical)
        .await
        .expect("the transport reopened its own stream");
    assert_eq!(
        redials.load(Ordering::SeqCst),
        1,
        "recovery went through the caller's redial, once"
    );
    assert_eq!(after.size, before.size, "same file, rebuilt session");
    println!("OK: a dead stream was reopened and the session rebuilt");
}
