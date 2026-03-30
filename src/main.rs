mod client;
mod error;
mod types;

#[cfg(target_os = "linux")]
mod cache;
#[cfg(target_os = "linux")]
mod fs;

#[cfg(target_os = "macos")]
mod webdav;

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::info;

use client::SynologyClient;

#[cfg(target_os = "linux")]
use cache::{InodeCache, ReadCache, READ_BLOCK_SIZE};
#[cfg(target_os = "linux")]
use fs::SynologyFS;
#[cfg(target_os = "linux")]
use fuser::MountOption;

#[derive(Parser, Debug)]
#[command(
    name = "synology-fuse",
    about = "Mount a Synology FileStation share as a local filesystem"
)]
struct Args {
    /// Synology NAS hostname or IP address
    #[arg(long)]
    host: String,

    /// HTTPS port (5001 by default; use 5000 for HTTP)
    #[arg(long, default_value_t = 5001)]
    port: u16,

    /// Use HTTPS (disable to use plain HTTP)
    #[arg(long, default_value_t = true)]
    https: bool,

    /// NAS account username
    #[arg(long, short = 'u')]
    username: String,

    /// NAS account password (or set SYNO_PASSWORD env var; prompted if omitted)
    #[arg(long, short = 'p', env = "SYNO_PASSWORD")]
    password: Option<String>,

    /// TOTP code for two-factor authentication (or set SYNO_OTP env var).
    /// If 2FA is enabled and this is not provided, you will be prompted interactively.
    #[arg(long, env = "SYNO_OTP")]
    otp: Option<String>,

    /// Local directory to mount the filesystem on
    mountpoint: PathBuf,

    /// Metadata cache TTL in seconds (Linux/FUSE only)
    #[arg(long, default_value_t = 30)]
    cache_ttl: u64,

    /// Read cache size in MiB (Linux/FUSE only)
    #[arg(long, default_value_t = 256)]
    read_cache_mb: u64,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn is_otp_required(e: &error::SynoFsError) -> bool {
    matches!(e, error::SynoFsError::ApiError(403 | 404))
}

fn prompt(label: &str) -> anyhow::Result<String> {
    eprint!("{}: ", label);
    io::stderr().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_string())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&args.log_level)
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // On macOS we mount via Finder which always places volumes under /Volumes/.
    // Require that the user provides a path there so they get a predictable name.
    #[cfg(target_os = "macos")]
    if !args.mountpoint.starts_with("/Volumes/") {
        anyhow::bail!(
            "On macOS the mountpoint must be under /Volumes/ (e.g. /Volumes/nas), \
             got: {}",
            args.mountpoint.display()
        );
    }

    info!(
        "Connecting to Synology NAS at {}://{}:{}",
        if args.https { "https" } else { "http" },
        args.host,
        args.port
    );

    let client = Arc::new(SynologyClient::new(&args.host, args.port, args.https));

    let password = match args.password {
        Some(p) => p,
        None => rpassword::prompt_password("Password: ")?,
    };

    let otp = args.otp.as_deref();
    let login_result = rt.block_on(client.login(&args.username, &password, otp));

    match login_result {
        Ok(()) => {}
        Err(ref e) if is_otp_required(e) => {
            let code = prompt("Two-factor authentication code")?;
            rt.block_on(client.login(&args.username, &password, Some(&code)))?;
        }
        Err(e) => return Err(e.into()),
    }

    info!("Logged in successfully");

    #[cfg(target_os = "linux")]
    {
        let cache = Arc::new(InodeCache::new(args.cache_ttl));
        let max_blocks = (args.read_cache_mb * 1024 * 1024) / READ_BLOCK_SIZE;
        let read_cache = Arc::new(ReadCache::new(READ_BLOCK_SIZE, max_blocks.max(1)));
        let handle = rt.handle().clone();
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };

        info!(
            "Read cache: {} MiB ({} blocks × {} MiB)",
            args.read_cache_mb,
            max_blocks,
            READ_BLOCK_SIZE / (1024 * 1024)
        );

        let fs = SynologyFS::new(client.clone(), cache, read_cache, handle, uid, gid);

        let options = vec![
            MountOption::RW,
            MountOption::FSName("synology-fuse".to_string()),
            MountOption::AllowOther,
            MountOption::AutoUnmount,
        ];

        info!("Mounting shares on {}", args.mountpoint.display());
        fuser::mount2(fs, &args.mountpoint, &options)?;
    }

    #[cfg(target_os = "macos")]
    {
        info!("Mounting shares on {} via WebDAV", args.mountpoint.display());
        rt.block_on(serve_and_mount(client.clone(), &args.mountpoint))?;
    }

    info!("Unmounted, logging out");
    rt.block_on(client.logout())?;

    Ok(())
}

/// Start a local WebDAV server, then ask macOS Finder to mount it via
/// AppleScript `mount volume`.  This works for regular users on any modern
/// macOS version without root or kernel extensions.
///
/// The WebDAV server advertises the last path component of `mountpoint` as its
/// `DAV:displayname`, which macOS Finder uses as the volume name.  The volume
/// therefore appears at exactly the `/Volumes/<name>` path the user requested.
#[cfg(target_os = "macos")]
async fn serve_and_mount(
    client: Arc<SynologyClient>,
    mountpoint: &std::path::Path,
) -> anyhow::Result<()> {
    use std::convert::Infallible;

    use dav_server::{fakels::FakeLs, DavHandler};
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use webdav::SynologyDavFs;

    // Extract the desired volume name from the last component of the path
    // (e.g. "/Volumes/nas" → "nas") and use it as a URL path prefix so that
    // macOS names the mounted volume correctly.
    let volume_name = mountpoint
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "mountpoint '{}' has no final path component; \
                 please provide a path like '/Volumes/nas' rather than a root or trailing-slash path",
                mountpoint.display()
            )
        })?;
    let path_prefix = format!("/{}", volume_name);

    let handler = Arc::new(
        DavHandler::builder()
            .filesystem(Box::new(SynologyDavFs::new(client, path_prefix.clone())))
            .locksystem(FakeLs::new())
            .build_handler(),
    );

    // Bind to a kernel-assigned port on localhost.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    // Include the volume name as a path component so macOS uses it as the
    // volume name when mounting (e.g. http://127.0.0.1:PORT/nas/ → /Volumes/nas).
    let url = format!("http://127.0.0.1:{}{}/", port, path_prefix);

    info!("WebDAV server listening on {}", url);

    // Start the accept loop BEFORE calling osascript so that Finder's probe
    // requests are answered immediately.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let handler_srv = handler.clone();
    let server_task = tokio::spawn(async move {
        let mut shutdown_rx = shutdown_rx;
        loop {
            tokio::select! {
                result = listener.accept() => {
                    let (stream, _addr) = match result {
                        Ok(r) => r,
                        Err(e) => { tracing::debug!("accept error: {}", e); break; }
                    };
                    let io = TokioIo::new(stream);
                    let h = handler_srv.clone();
                    tokio::spawn(async move {
                        let svc = hyper::service::service_fn(move |req| {
                            let h = h.clone();
                            async move { Ok::<_, Infallible>(h.handle(req).await) }
                        });
                        if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                            tracing::debug!("WebDAV connection closed: {}", e);
                        }
                    });
                }
                _ = &mut shutdown_rx => {
                    info!("WebDAV server shutting down");
                    break;
                }
            }
        }
    });

    // Remove a stale mount-point directory left over from a previous run.
    // If the directory is actually still mounted this will fail (EBUSY/EPERM),
    // which is fine — we leave it alone and let osascript fail with a clear message.
    if mountpoint.is_dir() && !mountpoint.is_symlink() {
        let _ = std::fs::remove_dir(mountpoint);
    }

    // Ask Finder to mount the volume via AppleScript.
    let script = format!("mount volume \"{}\"", url);
    let out = tokio::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
        .await?;

    if !out.status.success() {
        let _ = shutdown_tx.send(());
        server_task.await.ok();
        anyhow::bail!(
            "osascript mount failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    info!("Mounted at {}", mountpoint.display());

    // Ctrl-C → unmount and stop serving.
    let mp = mountpoint.to_path_buf();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Signal received, unmounting {}…", mp.display());
        let _ = tokio::process::Command::new("diskutil")
            .args(["unmount", &mp.to_string_lossy()])
            .status()
            .await;
        // macOS does not always remove the /Volumes/<name> directory after
        // unmounting a WebDAV volume.  Remove it ourselves if it is now empty.
        let _ = std::fs::remove_dir(&mp);
        let _ = shutdown_tx.send(());
    });

    server_task.await.ok();
    Ok(())
}
