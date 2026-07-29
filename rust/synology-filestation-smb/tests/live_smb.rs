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

use synology_filestation_smb::{SmbConfig, SmbTransport};

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
    let src = std::env::temp_dir().join("smb-stream-src-DELETEME.bin");
    std::fs::write(&src, &payload).expect("write local source file");

    let start = std::time::Instant::now();
    smb.write_from_path(&logical, &src)
        .await
        .expect("streaming write to NAS");
    report_throughput("write_from_path", len as u64, start.elapsed());

    // Read back and verify the whole payload round-tripped.
    let back = smb.read_full(&logical).await.expect("read back");
    assert_eq!(back.len(), len, "size round-trip");
    assert_eq!(back.as_ref(), payload.as_slice(), "bytes round-trip");

    let _ = smb.delete(&logical).await;
    let _ = std::fs::remove_file(&src);
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
    let dest = std::env::temp_dir().join("smb-stream-dst-DELETEME.bin");

    let start = std::time::Instant::now();
    smb.read_to_path(&logical, &dest)
        .await
        .expect("streaming read to disk");
    report_throughput("read_to_path", meta.size, start.elapsed());

    // On-disk size matches stat, and bytes match the whole-file read path.
    let on_disk = std::fs::read(&dest).expect("read local dest");
    assert_eq!(on_disk.len() as u64, meta.size, "size matches stat");
    let whole = smb.read_full(&logical).await.expect("whole-file read");
    assert_eq!(
        on_disk,
        whole.as_ref(),
        "streamed-to-disk bytes match the whole-file read"
    );

    let _ = std::fs::remove_file(&dest);
    println!(
        "OK: streaming read ({} bytes) to disk matches whole-file read; cleaned up",
        meta.size
    );
}
