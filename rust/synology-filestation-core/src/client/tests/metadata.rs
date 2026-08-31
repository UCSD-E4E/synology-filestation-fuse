//! Listings, stat, namespace operations, and the metadata backend ladder.

use super::*;

// ── list_shares ──────────────────────────────────────────────────────────

#[tokio::test]
async fn list_shares_returns_shares() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list_share"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"shares": [
                {"name": "photos", "path": "/photos", "isdir": true, "additional": null},
                {"name": "docs",   "path": "/docs",   "isdir": true, "additional": null}
            ]}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let shares = client.list_shares().await.unwrap();
    assert_eq!(shares.len(), 2);
    assert_eq!(shares[0].name, "photos");
    assert_eq!(shares[1].name, "docs");
}

#[tokio::test]
async fn list_shares_returns_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list_share"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 408}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client.list_shares().await.unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(408)));
}

// ── list_dir ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_dir_returns_files() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"files": [
                {"name": "file.txt", "path": "/share/file.txt", "isdir": false, "additional": null}
            ]}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let files = client.list_dir("/share").await.unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "file.txt");
}

#[tokio::test]
async fn list_dir_null_data_returns_empty_vec() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let files = client.list_dir("/empty").await.unwrap();
    assert!(files.is_empty());
}

// ── list pagination ──────────────────────────────────────────────────────

/// Build a `list`/`list_share` page: `count` synthetic entries plus the
/// server-reported `total` for the whole directory.
fn page_body(
    key: &str,
    prefix: &str,
    start: usize,
    count: usize,
    total: usize,
) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = (start..start + count)
        .map(|i| {
            serde_json::json!({
                "name": format!("f{i}"),
                "path": format!("{prefix}/f{i}"),
                "isdir": false,
                "additional": null
            })
        })
        .collect();
    serde_json::json!({
        "success": true,
        "data": { "total": total, "offset": start, key: entries }
    })
}

/// Regression: `list_dir` sent a single request with a hardcoded limit and
/// `offset=0`, then returned whatever came back. A directory with more
/// entries than one page was silently listed short — through FUSE that
/// presents as files that simply do not exist. Every page must be fetched.
#[tokio::test]
async fn list_dir_pages_until_the_server_total_is_reached() {
    let server = MockServer::start().await;
    let page = LIST_PAGE_SIZE;
    let total = page + 37;

    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list"))
        .and(query_param("offset", "0"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_body("files", "/share", 0, page, total)),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list"))
        .and(query_param("offset", page.to_string().as_str()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_body("files", "/share", page, 37, total)),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let files = client.list_dir("/share").await.unwrap();
    assert_eq!(files.len(), total, "every page must be collected");
    assert_eq!(files[0].name, "f0");
    assert_eq!(files[total - 1].name, format!("f{}", total - 1));
}

/// Same defect on the share listing, which had an even smaller cap (500).
#[tokio::test]
async fn list_shares_pages_until_the_server_total_is_reached() {
    let server = MockServer::start().await;
    let page = LIST_PAGE_SIZE;
    let total = page + 5;

    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list_share"))
        .and(query_param("offset", "0"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_body("shares", "", 0, page, total)),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list_share"))
        .and(query_param("offset", page.to_string().as_str()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_body("shares", "", page, 5, total)),
        )
        .mount(&server)
        .await;

    let client = client_for(&server);
    let shares = client.list_shares().await.unwrap();
    assert_eq!(shares.len(), total);
}

/// A directory that fits in one page must still cost exactly one request —
/// paging must not add a speculative second round trip to every listing.
#[tokio::test]
async fn list_dir_stops_after_a_short_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(page_body("files", "/share", 0, 3, 3)),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let files = client.list_dir("/share").await.unwrap();
    assert_eq!(files.len(), 3);
    // `expect(1)` is asserted when the server drops at end of scope.
}

/// A server that reports a `total` it never delivers (or keeps returning
/// full pages forever) must not spin the client indefinitely: paging stops
/// as soon as a page comes back empty.
#[tokio::test]
async fn list_dir_stops_when_a_page_comes_back_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list"))
        .and(query_param("offset", "0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page_body(
            "files",
            "/share",
            0,
            LIST_PAGE_SIZE,
            999_999,
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list"))
        .and(query_param("offset", LIST_PAGE_SIZE.to_string().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"total": 999_999, "files": []}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let files = client.list_dir("/share").await.unwrap();
    assert_eq!(files.len(), LIST_PAGE_SIZE);
}

// ── get_info ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_info_returns_file_metadata() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"files": [{
                "name": "notes.txt",
                "path": "/share/notes.txt",
                "isdir": false,
                "additional": {"size": 512, "owner": null, "time": null, "perm": null}
            }]}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let info = client.get_info("/share/notes.txt").await.unwrap();
    assert_eq!(info.name, "notes.txt");
    assert_eq!(info.additional.unwrap().size, Some(512));
}

#[tokio::test]
async fn get_info_per_entry_error_returns_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"files": [{"code": 408, "path": "/share/missing"}]}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client.get_info("/share/missing").await.unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(408)));
}

#[tokio::test]
async fn get_info_envelope_error_returns_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 119}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client.get_info("/share/restricted").await.unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(119)));
}

// ── delete ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    client.delete("/share/file.txt").await.unwrap();
}

#[tokio::test]
async fn delete_returns_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 414}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client.delete("/share/missing.txt").await.unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(414)));
}

// ── create_folder ────────────────────────────────────────────────────────

#[tokio::test]
async fn create_folder_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "create"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"folders": [
                {"name": "newdir", "path": "/share/newdir", "isdir": true, "additional": null}
            ]}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let info = client.create_folder("/share", "newdir").await.unwrap();
    assert_eq!(info.name, "newdir");
    assert!(info.isdir);
}

#[tokio::test]
async fn create_folder_returns_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "create"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 1101}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .create_folder("/share", "existing")
        .await
        .unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(1101)));
}

// ── rename ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn rename_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "rename"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"files": [
                {"name": "new.txt", "path": "/share/new.txt", "isdir": false, "additional": null}
            ]}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let info = client.rename("/share/old.txt", "new.txt").await.unwrap();
    assert_eq!(info.name, "new.txt");
}

#[tokio::test]
async fn rename_returns_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "rename"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 418}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .rename("/share/old.txt", "existing.txt")
        .await
        .unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(418)));
}

// ── metadata backends ────────────────────────────────────────────────────
//
// Listings and namespace changes follow the same selection rules as bytes:
// a healthy backend answers, a transport failure falls back to HTTP, a
// definitive answer is the answer, and an operation the backend cannot
// promise is declined without counting against it.

#[tokio::test]
async fn a_listing_prefers_the_metadata_backend() {
    let backend = FakeMeta::new(Behave::Ok(b""));
    // No HTTP server at all: if the backend didn't answer, this would fail.
    let client = offline_client().with_metadata_transport(backend.clone());
    let entries = client.list_dir("/share").await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "from-backend");
    assert_eq!(backend.call_count(), 1);
}

#[tokio::test]
async fn a_listing_falls_back_to_http_when_the_backend_is_down() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"files": [{
                "name": "from-http", "path": "/share/from-http", "isdir": false,
                "additional": {"size": 1, "owner": null, "time": null, "perm": null}
            }], "total": 1, "offset": 0}
        })))
        .mount(&server)
        .await;
    let backend = FakeMeta::new(Behave::Transient);
    let client = client_for(&server).with_metadata_transport(backend.clone());
    let entries = client.list_dir("/share").await.unwrap();
    assert_eq!(entries[0].name, "from-http", "HTTP served the listing");
    assert_eq!(backend.call_count(), 1, "the backend was tried first");
}

#[tokio::test]
async fn a_definitive_answer_from_the_backend_is_not_second_guessed() {
    // NotFound from a reachable backend is the truth about the namespace.
    // Asking HTTP for a second opinion would be slower and no more correct.
    let server = MockServer::start().await;
    let backend = FakeMeta::new(Behave::NotFound);
    let client = client_for(&server).with_metadata_transport(backend.clone());
    let err = client.get_info("/share/gone").await.unwrap_err();
    assert!(matches!(err, SynoFsError::NotFound), "got {err:?}");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no HTTP second opinion"
    );
}

#[tokio::test]
async fn an_operation_the_backend_declines_goes_to_http() {
    // FakeMeta implements only listings, stat and delete; `create_folder`
    // falls through to the trait default, which declines.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "create"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"folders": [{"name": "new", "path": "/share/new", "isdir": true}]}
        })))
        .mount(&server)
        .await;
    let backend = FakeMeta::new(Behave::Ok(b""));
    let client = client_for(&server).with_metadata_transport(backend.clone());
    let made = client.create_folder("/share", "new").await.unwrap();
    assert_eq!(made.name, "new");
    assert_eq!(backend.call_count(), 0, "declined without being charged");

    // And the decline left the breaker shut: a listing still prefers it.
    let entries = client.list_dir("/share").await.unwrap();
    assert_eq!(entries[0].name, "from-backend");
}

#[tokio::test]
async fn a_backend_without_offset_writes_declines_to_open_one() {
    // The trait default is what every non-SMB backend gets: opening a file
    // for writing is refused outright, so a caller keeps buffering rather
    // than discovering the gap halfway through a file.
    use crate::transport::{OpenWriteTransport, WriteOpen};
    struct Bulk;
    impl OpenWriteTransport for Bulk {}

    // `Box<dyn WriteHandle>` has no Debug, so unwrap_err is out.
    match Bulk.open_write("/share/f.bin", WriteOpen::CreateNew).await {
        Err(SynoFsError::NotSupported) => {}
        Err(e) => panic!("expected a decline, got {e:?}"),
        Ok(_) => panic!("a backend with no offset writes must not hand one out"),
    }
}
