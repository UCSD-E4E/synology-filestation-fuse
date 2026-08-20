//! The SMB write paths, against a real SMB server.
//!
//! Everything else in this crate is mocked or pure, because SMB has no useful
//! in-process fake. These two operations are the ones that most need a server:
//! both are single round trips whose whole value is what the *server* does with
//! them, so a mock asserting we sent the right bytes proves the less
//! interesting half.
//!
//! `#[ignore]`d because they need Docker, which CI does not have. Run them with:
//!
//! ```text
//! cargo test -p synology-filestation-smb --test samba -- --ignored --nocapture
//! ```
//!
//! The containers are Samba, not DSM, so they prove the operations are correct
//! SMB — not that this particular NAS accepts them. That still wants the live
//! pass against e4e-nas.

use std::time::Duration;

use smb2::testing::TestServers;
use synology_filestation_core::MetadataTransport;
use synology_filestation_smb::{SmbConfig, SmbTransport};

/// Connect our transport to the auth container, which is the credentialed
/// NTLMv2 path the NAS uses — not the guest one.
async fn connect(servers: &TestServers) -> SmbTransport {
    let cfg = SmbConfig {
        host: "127.0.0.1".to_string(),
        port: smb2::testing::auth_port(),
        username: "testuser".to_string(),
        password: "testpass".to_string(),
        domain: String::new(),
        timeout: Duration::from_secs(10),
    };
    let _ = servers;
    SmbTransport::connect(&cfg)
        .await
        .expect("the auth container should accept these credentials")
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn a_second_write_replaces_the_first_under_the_same_name() {
    // The replacing rename. Before the fork this needed four operations with a
    // window where the name resolved to nothing; the point of the test is that
    // the *server* accepts one operation and the name never stops resolving.
    let servers = TestServers::start().await.expect("docker compose up");
    let smb = connect(&servers).await;

    let path = "/private/replace-me.txt";
    smb.write_atomic(path, b"first").await.expect("first write");
    assert_eq!(&smb.read_full(path).await.unwrap()[..], b"first");

    smb.write_atomic(path, b"second")
        .await
        .expect("second write");
    assert_eq!(
        &smb.read_full(path).await.unwrap()[..],
        b"second",
        "the second write replaced the first"
    );

    smb.delete(path).await.ok();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn truncate_shortens_a_file_without_rewriting_it() {
    let servers = TestServers::start().await.expect("docker compose up");
    let smb = connect(&servers).await;

    let path = "/private/truncate-me.bin";
    let original: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    smb.write_atomic(path, &original).await.expect("write");

    MetadataTransport::truncate(&smb, path, 100)
        .await
        .expect("set end of file");

    let after = smb.read_full(path).await.unwrap();
    assert_eq!(after.len(), 100, "the length is what we set");
    assert_eq!(
        &after[..],
        &original[..100],
        "and the bytes it kept are the ones that were already there"
    );

    smb.delete(path).await.ok();
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn truncate_can_also_extend_a_file() {
    // The same call grows: the server materialises the gap, and on a sparse
    // filesystem that costs nothing until something writes there.
    let servers = TestServers::start().await.expect("docker compose up");
    let smb = connect(&servers).await;

    let path = "/private/extend-me.bin";
    smb.write_atomic(path, b"abcd").await.expect("write");

    MetadataTransport::truncate(&smb, path, 8)
        .await
        .expect("set end of file");

    let after = smb.read_full(path).await.unwrap();
    assert_eq!(&after[..], b"abcd\0\0\0\0", "old bytes, then zeroes");

    smb.delete(path).await.ok();
}
