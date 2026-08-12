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

    /// Read the password from the first line of stdin.
    ///
    /// Prefer this in scripts. A password passed as `--password` sits in this
    /// process's argv, which every other account on the machine can read via
    /// `ps` (and `/proc/<pid>/cmdline` on Linux) for as long as the mount runs.
    #[arg(long, conflicts_with = "password")]
    password_stdin: bool,
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

    /// FUSE event-loop threads; 0 picks a default from the CPU count.
    /// Bounds the callbacks that still hold a thread — a read that misses the
    /// cache, a listing, a metadata call — not file transfers, which run on the
    /// async runtime (Linux/FUSE only)
    #[arg(long, default_value_t = 0)]
    fuse_threads: usize,

    /// Owner reported for every mounted entry; defaults to the mounting user.
    /// DSM's own uids name accounts on the appliance and are never used
    /// (Linux/FUSE only)
    #[arg(long)]
    uid: Option<u32>,

    /// Group reported for every mounted entry; defaults to the mounting user's
    /// group (Linux/FUSE only)
    #[arg(long)]
    gid: Option<u32>,

    /// Umask for the synthetic permissions the mount reports. The default 0o022
    /// gives 0755 directories and 0644 files (Linux/FUSE only)
    #[arg(long, value_parser = parse_umask, default_value = "022")]
    umask: u16,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,
}

/// Parse a umask the way `umask(1)` and every mount helper do: octal, with no
/// `0o` prefix required. Base 10 would silently turn the near-universal `022`
/// into 0o026.
fn parse_umask(raw: &str) -> Result<u16, String> {
    let value = u16::from_str_radix(raw.trim_start_matches("0o"), 8)
        .map_err(|_| format!("`{raw}` is not an octal umask"))?;
    if value > 0o777 {
        return Err(format!("umask `{raw}` is out of range (max 777)"));
    }
    Ok(value)
}

fn prompt(label: &str) -> anyhow::Result<String> {
    eprint!("{}: ", label);
    io::stderr().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_string())
}

/// Whether the password was typed on the command line rather than coming from
/// the environment. argv is readable by any local account; `SYNO_PASSWORD` is
/// not, so only the former deserves a warning.
fn password_came_from_argv() -> bool {
    std::env::args().any(|a| a == "-p" || a == "--password" || a.starts_with("--password="))
}

/// Resolve the password from stdin, argv/environment, or an interactive prompt.
fn resolve_password(args: &Args) -> anyhow::Result<String> {
    if args.password_stdin {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }
    match &args.password {
        Some(p) => {
            if password_came_from_argv() {
                tracing::warn!(
                    "--password puts the password in this process's argv, where every \
                     other account on this machine can read it with `ps`. Prefer \
                     SYNO_PASSWORD, --password-stdin, or the interactive prompt."
                );
            }
            Ok(p.clone())
        }
        None => Ok(rpassword::prompt_password("Password: ")?),
    }
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

    let password = resolve_password(&args)?;

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
        io_threads: args.fuse_threads,
        uid: args.uid,
        gid: args.gid,
        umask: args.umask,
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

#[cfg(test)]
mod tests {
    use super::parse_umask;

    /// `--umask 022` must mean 0o022. Parsed as decimal it would be 0o026,
    /// quietly stripping group/other permissions the user never asked to drop.
    #[test]
    fn umask_is_parsed_as_octal() {
        assert_eq!(parse_umask("022"), Ok(0o022));
        assert_eq!(parse_umask("077"), Ok(0o077));
        assert_eq!(parse_umask("0o027"), Ok(0o027));
        assert_eq!(parse_umask("0"), Ok(0));
    }

    #[test]
    fn a_umask_outside_the_permission_bits_is_rejected() {
        assert!(parse_umask("1777").is_err());
        assert!(parse_umask("088").is_err(), "8 is not an octal digit");
        assert!(parse_umask("rwx").is_err());
    }
}
