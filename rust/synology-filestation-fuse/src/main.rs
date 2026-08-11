use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::info;

use synology_filestation_core::client::SynologyClient;
use synology_filestation_fuse::{is_otp_required, spawn_mount, MountOptions};

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

    /// Accept any TLS certificate, including self-signed, expired, or
    /// wrong-hostname ones.
    ///
    /// A DSM appliance ships with a self-signed certificate, so this is often
    /// needed — but it means the encrypted connection is not authenticated:
    /// anything able to intercept it can present its own certificate and read
    /// your password. Prefer installing the NAS's certificate in the system
    /// trust store.
    #[arg(long, env = "SYNO_INSECURE")]
    insecure: bool,

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

    info!(
        "Connecting to Synology NAS at {}://{}:{}",
        if args.https { "https" } else { "http" },
        args.host,
        args.port
    );

    let client = SynologyClient::new(&args.host, args.port, args.https);
    let client = if args.insecure {
        if args.https {
            tracing::warn!(
                "--insecure: TLS certificate verification is OFF; the connection \
                 is encrypted but not authenticated"
            );
        }
        client.with_insecure_tls()
    } else {
        client
    };

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
        // A TLS failure here is almost always a self-signed NAS certificate, and
        // the fix is a flag the user has no reason to know exists. Name it.
        Err(e) if args.https && !args.insecure && e.is_tls_error() => {
            return Err(anyhow::anyhow!(
                "could not verify the TLS certificate for {}:{} ({e}).\n\
                 \n\
                 If this NAS uses a self-signed certificate, either install it in \
                 your system trust store, or re-run with --insecure to accept any \
                 certificate (encrypted, but not authenticated).",
                args.host,
                args.port
            ));
        }
        Err(e) => return Err(e.into()),
    }

    info!("Logged in successfully");

    // Transparently prefer SMB for the mount's reads/writes when the NAS's SMB
    // service is reachable — this bypasses synoscgi entirely. Silently HTTP-only
    // otherwise. Injected before the client is shared, since it consumes it.
    let client = Arc::new(rt.block_on(synology_filestation_smb::auto_attach(
        client,
        &args.host,
        &args.username,
        &password,
    )));

    let opts = MountOptions {
        cache_ttl: args.cache_ttl,
        read_cache_mb: args.read_cache_mb,
    };
    let handle = spawn_mount(client.clone(), rt.handle().clone(), args.mountpoint, opts)?;

    // Block until Ctrl-C, then unmount and log out — preserving the previous
    // foreground CLI behaviour now that the mount itself runs in the background.
    rt.block_on(tokio::signal::ctrl_c())?;
    info!("Signal received, unmounting…");
    handle.stop();

    info!("Logging out");
    rt.block_on(client.logout())?;

    Ok(())
}
