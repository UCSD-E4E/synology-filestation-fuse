//! Client construction: the TLS crypto provider and certificate verification.

use super::*;

// ── TLS crypto provider ────────────────────────────────────────────────────

/// reqwest 0.13 is built with `rustls-no-provider`, so rustls ships no
/// compiled-in crypto provider. `SynologyClient::new` must install one (ring)
/// as the process default, otherwise the first HTTPS handshake to the NAS
/// panics/fails. The wiremock tests only speak HTTP and would not catch this,
/// so pin it directly: after constructing an HTTPS client a default provider
/// must be present.
#[test]
fn https_client_installs_default_crypto_provider() {
    let _client = SynologyClient::new("nas.example.invalid", 5001, true);
    assert!(
        rustls::crypto::CryptoProvider::get_default().is_some(),
        "SynologyClient::new must install a default rustls CryptoProvider"
    );
}

// ── TLS verification ─────────────────────────────────────────────────────

/// A one-shot HTTPS listener presenting a self-signed certificate for
/// `localhost` — i.e. exactly the NAS setup that made someone reach for
/// `danger_accept_invalid_certs` in the first place. Answers any request
/// with a successful login envelope, so the only thing that can fail a test
/// against it is the TLS handshake.
///
/// Hand-rolled because wiremock speaks plain HTTP; the response is a canned
/// HTTP/1.1 message rather than a real server.
async fn self_signed_https_server() -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    install_crypto_provider();

    let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = issued.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return; // handshake refused by the client — the point of the test
                };
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;
                let body = r#"{"success":true,"data":{"sid":"tls_ok"}}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tls.write_all(resp.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    port
}

/// Regression: the client called `danger_accept_invalid_certs(true)`
/// unconditionally, so `https` bought encryption against a passive observer
/// and nothing else — any machine able to intercept the connection could
/// present its own certificate and read the password. Verification is now
/// on by default.
#[tokio::test]
async fn https_rejects_a_self_signed_certificate_by_default() {
    let port = self_signed_https_server().await;
    let client = SynologyClient::new("localhost", port, true);

    let err = client
        .login("alice", "secret", None)
        .await
        .expect_err("an unverifiable certificate must not be silently accepted");

    assert!(
        matches!(err, SynoFsError::Io(_)),
        "expected a transport/TLS failure, got {err:?}"
    );
}

/// The escape hatch has to actually work: a self-signed NAS certificate is
/// the normal case for this appliance, and `--insecure` is what those users
/// are told to pass.
#[tokio::test]
async fn with_insecure_tls_accepts_a_self_signed_certificate() {
    let port = self_signed_https_server().await;
    let client = SynologyClient::new("localhost", port, true).with_insecure_tls();

    client
        .login("alice", "secret", None)
        .await
        .expect("--insecure must accept a self-signed certificate");
    assert_eq!(client.sid(), "tls_ok");
}

/// The CLI and GUI turn a rejected certificate into "…re-run with
/// --insecure", which only works if the error is recognisable as a TLS
/// failure. Pin `is_tls_error` against a real handshake so it tracks the
/// string rustls actually produces.
#[tokio::test]
async fn a_rejected_certificate_is_recognisable_as_a_tls_failure() {
    let port = self_signed_https_server().await;
    let err = SynologyClient::new("localhost", port, true)
        .login("alice", "secret", None)
        .await
        .unwrap_err();

    assert!(
        err.is_tls_error(),
        "a rejected certificate must be recognisable so the user can be \
         pointed at --insecure; got: {err}"
    );
}

/// The flag is inspectable so the CLI/GUI/bindings can report which mode
/// they are in, and so a future change cannot silently invert the default.
#[test]
fn tls_verification_is_on_unless_explicitly_disabled() {
    let strict = SynologyClient::new("nas.example.invalid", 5001, true);
    assert!(!strict.insecure_tls());
    assert!(strict.with_insecure_tls().insecure_tls());
}
