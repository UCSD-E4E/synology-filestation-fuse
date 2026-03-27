mod cache;
mod client;
mod error;
mod fs;
mod types;

use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use fuser::MountOption;
use tracing::info;

use cache::{InodeCache, ReadCache, READ_BLOCK_SIZE};
use client::SynologyClient;
use fs::SynologyFS;

#[derive(Parser, Debug)]
#[command(
    name = "synology-fuse",
    about = "Mount a Synology FileStation share as a local FUSE filesystem"
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

    /// Metadata cache TTL in seconds
    #[arg(long, default_value_t = 30)]
    cache_ttl: u64,

    /// Read cache size in MiB (file data blocks cached in memory for fast re-reads)
    #[arg(long, default_value_t = 256)]
    read_cache_mb: u64,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Use the macFUSE FSKit backend instead of the kernel extension.
    /// Requires macOS 15.4+ and macFUSE 5.0+. No kernel extension approval needed.
    /// The mount point must be a directory inside /Volumes.
    #[cfg(target_os = "macos")]
    #[arg(long, default_value_t = false)]
    fskit: bool,
}

/// Synology API error 403 = "Account disabled" or "Incorrect password", but in the context of
/// a valid password it means OTP is required. Error 404 = "Permission denied" can also indicate
/// a missing OTP on some DSM versions. We treat both as "OTP needed".
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

    // Build a multi-thread Tokio runtime.
    // The FUSE dispatch loop runs synchronously on the main thread via fuser::mount2.
    // All async HTTP I/O is dispatched to the Tokio worker pool via handle.block_on().
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    info!(
        "Connecting to Synology NAS at {}://{}:{}",
        if args.https { "https" } else { "http" },
        args.host,
        args.port
    );

    let client = Arc::new(SynologyClient::new(&args.host, args.port, args.https));

    // Synology API error code 403 means an OTP code is required.
    // If the user didn't supply one via --otp / SYNO_OTP, prompt interactively.
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

    let cache = Arc::new(InodeCache::new(args.cache_ttl));
    let max_blocks = (args.read_cache_mb * 1024 * 1024) / READ_BLOCK_SIZE;
    let read_cache = Arc::new(ReadCache::new(READ_BLOCK_SIZE, max_blocks.max(1)));
    let handle = rt.handle().clone();
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    info!("Read cache: {} MiB ({} blocks × {} MiB)",
          args.read_cache_mb, max_blocks, READ_BLOCK_SIZE / (1024 * 1024));

    let fs = SynologyFS::new(client.clone(), cache, read_cache, handle, uid, gid);

    // AutoUnmount is Linux-only; macFUSE unmounts automatically when the process exits.
    #[cfg(target_os = "linux")]
    let options = vec![
        MountOption::RW,
        MountOption::FSName("synology-fuse".to_string()),
        MountOption::AllowOther,
        MountOption::AutoUnmount,
    ];
    #[cfg(not(target_os = "linux"))]
    let mut options = vec![
        MountOption::RW,
        MountOption::FSName("synology-fuse".to_string()),
        MountOption::AllowOther,
    ];
    // FSKit backend: no kernel extension required, but needs macOS 15.4+ and macFUSE 5.0+.
    // Mount point must be inside /Volumes.
    #[cfg(target_os = "macos")]
    if args.fskit {
        if !args.mountpoint.starts_with("/Volumes") {
            eprintln!("warning: --fskit requires the mount point to be inside /Volumes");
        }
        options.push(MountOption::CUSTOM("backend=fskit".to_string()));
    }

    info!("Mounting shares on {}", args.mountpoint.display());

    // mount2 blocks until the filesystem is unmounted (e.g. via `fusermount -u <mountpoint>`)
    fuser::mount2(fs, &args.mountpoint, &options)?;

    info!("Unmounted, logging out");
    rt.block_on(client.logout())?;

    Ok(())
}
