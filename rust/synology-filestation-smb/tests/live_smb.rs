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
