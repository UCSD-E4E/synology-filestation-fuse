//! Ranged reads, DSM's JSON-error-in-a-200 envelope, and atomic downloads.

use super::*;

// ── download ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn download_returns_bytes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello world".to_vec()))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let data = client.download("/share/file.txt", 0, 11).await.unwrap();
    assert_eq!(data.as_ref(), b"hello world");
}

#[tokio::test]
async fn download_416_returns_empty_bytes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(ResponseTemplate::new(416))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let data = client.download("/share/file.txt", 9999, 10).await.unwrap();
    assert!(data.is_empty());
}

#[tokio::test]
async fn download_http_error_returns_io_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client.download("/share/file.txt", 0, 10).await.unwrap_err();
    assert!(matches!(err, SynoFsError::Io(_)));
}

// ── download JSON-error envelope detection ───────────────────────────────
//
// The fishsense bug: DSM returns 200 OK with body
// {"success":false,"error":{"code":119}} on a download when the SID is
// expired. The synology-api PyPI lib treats this as success (because HTTP
// is 200), opens the destination file with 'wb' (truncating), reads zero
// file bytes, and silently corrupts the output. We must surface this as
// ApiError(code).

#[tokio::test]
async fn download_returns_api_error_when_body_is_dsm_json_error_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json; charset=UTF-8")
                .set_body_string(r#"{"success":false,"error":{"code":119}}"#),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client.download("/share/file.bin", 0, 0).await.unwrap_err();
    assert!(
        matches!(err, SynoFsError::ApiError(119)),
        "expected ApiError(119), got {err:?}"
    );
}

#[tokio::test]
async fn download_with_octet_stream_content_type_returns_bytes_not_parsed() {
    // Sanity-check that real binary downloads aren't accidentally caught
    // by the JSON-envelope detection. The body happens to start with `{`
    // but Content-Type is binary, so we should pass it through.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(b"{not really json}".to_vec()),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let bytes = client.download("/share/x", 0, 0).await.unwrap();
    assert_eq!(bytes.as_ref(), b"{not really json}");
}

// ── atomic download_to_path ──────────────────────────────────────────────
//
// download_to_path must guarantee that the destination file is either
// (a) absent, or (b) complete and correct — never a 0-byte stub or a
// partial download. Implementation detail: write to "<path>.part", fsync,
// rename. The fishsense regression is the central case here.

#[tokio::test]
async fn download_to_path_writes_atomically_then_renames() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(b"hello atomic world".to_vec()),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let dest = unique_tmp_path("happy.bin");
    let part = {
        let mut p = dest.as_os_str().to_os_string();
        p.push(".part");
        std::path::PathBuf::from(p)
    };

    client.download_to_path("/share/file", &dest).await.unwrap();

    let on_disk = std::fs::read(&dest).unwrap();
    assert_eq!(on_disk, b"hello atomic world");
    assert!(!part.exists(), "tmp file should be gone after rename");

    std::fs::remove_file(&dest).ok();
}

#[tokio::test]
async fn download_to_path_does_not_create_final_file_on_dsm_json_error() {
    // **The fishsense regression test.** DSM replies 200 OK with a JSON
    // error envelope; the destination must NOT exist on disk afterward
    // (no 0-byte stub), and neither must the .part tmp file.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"success":false,"error":{"code":119}}"#),
        )
        .mount(&server)
        .await;

    let client = client_for(&server); // no auto-relogin — 119 surfaces
    let dest = unique_tmp_path("regression.bin");
    let part = {
        let mut p = dest.as_os_str().to_os_string();
        p.push(".part");
        std::path::PathBuf::from(p)
    };

    let err = client
        .download_to_path("/share/missing", &dest)
        .await
        .unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(119)));
    assert!(
        !dest.exists(),
        "destination must not exist after failed download (no zero-byte stub)"
    );
    assert!(!part.exists(), ".part tmp file must be cleaned up");
}

#[tokio::test]
async fn download_to_path_with_auto_relogin_recovers_from_119() {
    // End-to-end fishsense fix: SID expires mid-script, auto-relogin
    // kicks in, retry succeeds, file lands on disk correctly.
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/webapi/auth.cgi"))
        .and(body_string_contains("method=login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"sid": "fresh"}
        })))
        .mount(&server)
        .await;

    // First download: 119. Second: real bytes.
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"success":false,"error":{"code":119}}"#),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(b"recovered payload".to_vec()),
        )
        .mount(&server)
        .await;

    let client = client_auto_for(&server);
    client.login("alice", "secret", None).await.unwrap();
    let dest = unique_tmp_path("recovered.bin");
    client.download_to_path("/share/x", &dest).await.unwrap();

    let on_disk = std::fs::read(&dest).unwrap();
    assert_eq!(on_disk, b"recovered payload");
    std::fs::remove_file(&dest).ok();
}

#[tokio::test]
async fn download_to_path_cleans_tmp_when_rename_target_is_unwritable() {
    // Force a rename failure by pointing at a path under a directory
    // that doesn't exist. The .part tmp won't even be created (parent
    // dir missing), so we should get an Io error and no leftover state.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(b"data".to_vec()),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let bogus_dir = unique_tmp_path("nonexistent-parent-dir");
    let dest = bogus_dir.join("file.bin");

    let err = client
        .download_to_path("/share/x", &dest)
        .await
        .unwrap_err();
    assert!(matches!(err, SynoFsError::Io(_)));
    assert!(!dest.exists());
}

// ── streaming download (download_to_path) selection ──────────────────────

#[tokio::test]
async fn download_to_path_prefers_stream_backend_and_skips_http() {
    let backend = FakeBackend::new(Behave::Ok(b"streamed to disk"));
    let client = offline_client().with_stream_read_transport(backend.clone());
    let dest = unique_tmp_path("stream-dl.bin");
    client.download_to_path("/share/f", &dest).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"streamed to disk");
    assert_eq!(backend.call_count(), 1);
    std::fs::remove_file(&dest).ok();
}

#[tokio::test]
async fn download_to_path_falls_back_to_http_on_transient() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"from-http".to_vec()))
        .mount(&server)
        .await;
    let backend = FakeBackend::new(Behave::Transient);
    let client = client_for(&server).with_stream_read_transport(backend.clone());
    let dest = unique_tmp_path("stream-dl-fallback.bin");
    client.download_to_path("/share/f", &dest).await.unwrap();
    assert_eq!(
        std::fs::read(&dest).unwrap(),
        b"from-http",
        "fell back to HTTP"
    );
    assert_eq!(backend.call_count(), 1);
    std::fs::remove_file(&dest).ok();
}

#[tokio::test]
async fn download_to_path_propagates_definitive_backend_error() {
    let backend = FakeBackend::new(Behave::NotFound);
    let client = offline_client().with_stream_read_transport(backend.clone());
    let dest = unique_tmp_path("stream-dl-missing.bin");
    let err = client
        .download_to_path("/share/missing", &dest)
        .await
        .unwrap_err();
    assert!(matches!(err, SynoFsError::NotFound));
    assert_eq!(backend.call_count(), 1);
    assert!(!dest.exists(), "definitive failure leaves no file");
}
