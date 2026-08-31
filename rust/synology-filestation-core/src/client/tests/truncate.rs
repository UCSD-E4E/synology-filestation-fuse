//! Truncate.

use super::*;

// ── truncate ─────────────────────────────────────────────────────────────
//
// A file's length is a number. On a protocol that can say so it is one
// round trip; over the FileStation API, which only knows "upload this whole
// file", it costs a read and a write of the contents. The fallback at least
// reads only the part it keeps.

#[tokio::test]
async fn truncate_prefers_the_metadata_backend() {
    let backend = FakeMeta::new(Behave::Ok(b""));
    // Offline: if the backend didn't take it, there is no HTTP to fall to.
    let client = offline_client().with_metadata_transport(backend.clone());
    client.truncate("/share/big.bin", 1024).await.unwrap();
    assert_eq!(backend.call_count(), 1);
}

#[tokio::test]
async fn truncating_to_zero_never_reads_the_file() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true, "data": {"blks": null}
        })))
        .mount(&server)
        .await;

    client_for(&server)
        .truncate("/share/f.bin", 0)
        .await
        .unwrap();

    let downloads = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.query().is_some_and(|q| q.contains("method=download")))
        .count();
    assert_eq!(downloads, 0, "nothing worth keeping, so nothing fetched");
}

#[tokio::test]
async fn shrinking_reads_only_the_bytes_it_keeps() {
    // The tail is about to be discarded. Fetching it would double a
    // transfer that is already the wrong shape for the job.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"files": [{
                "name": "f.bin", "path": "/share/f.bin", "isdir": false,
                "additional": {"size": 5000, "owner": null, "time": null, "perm": null}
            }]}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(vec![7u8; 100]),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true, "data": {"blks": null}
        })))
        .mount(&server)
        .await;

    client_for(&server)
        .truncate("/share/f.bin", 100)
        .await
        .unwrap();

    let ranges: Vec<_> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.query().is_some_and(|q| q.contains("method=download")))
        .map(|r| {
            r.headers
                .get("Range")
                .map(|v| v.to_str().unwrap().to_string())
        })
        .collect();
    assert_eq!(
        ranges,
        vec![Some("bytes=0-99".to_string())],
        "asked for the 100 bytes it keeps, not the 5000 that exist"
    );
}

#[tokio::test]
async fn growing_reads_the_whole_file_before_padding() {
    // Extending needs everything that is already there; the new tail is
    // zeroes the caller never sent.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"files": [{
                "name": "f.bin", "path": "/share/f.bin", "isdir": false,
                "additional": {"size": 4, "owner": null, "time": null, "perm": null}
            }]}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/octet-stream")
                .set_body_bytes(b"abcd".to_vec()),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true, "data": {"blks": null}
        })))
        .mount(&server)
        .await;

    client_for(&server)
        .truncate("/share/f.bin", 8)
        .await
        .unwrap();

    let reqs = server.received_requests().await.unwrap();
    let range = reqs
        .iter()
        .find(|r| r.url.query().is_some_and(|q| q.contains("method=download")))
        .and_then(|r| r.headers.get("Range").cloned());
    assert!(range.is_none(), "the whole file, so no range");

    let body = reqs
        .iter()
        .find(|r| r.method == wiremock::http::Method::POST)
        .map(|r| String::from_utf8_lossy(&r.body).to_string())
        .unwrap();
    assert!(
        body.contains("abcd\0\0\0\0"),
        "the old bytes, then zeroes to the new length"
    );
}

#[tokio::test]
async fn truncating_a_directory_path_refuses_instead_of_deleting_it() {
    // A trailing slash yields an empty filename, and an empty filename
    // rejoined to its parent IS the parent — so the overwrite path would
    // have cleared the directory before writing. The bug is worth a test
    // precisely because its symptom is a missing folder, not an error.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true, "data": {}
        })))
        .mount(&server)
        .await;

    let err = client_for(&server)
        .truncate("/share/dir/", 0)
        .await
        .unwrap_err();
    assert!(matches!(err, SynoFsError::InvalidArg), "got {err:?}");

    let touched_the_nas = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|r| r.url.query().is_some_and(|q| q.contains("method=delete")));
    assert!(
        !touched_the_nas,
        "nothing was deleted on the way to the error"
    );
}

/// A backend whose answer changes call by call.
struct ScriptedMeta {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl MetadataTransport for ScriptedMeta {
    async fn list_dir(&self, _folder: &str) -> Result<Vec<SynoFileInfo>, SynoFsError> {
        match self.calls.fetch_add(1, Ordering::SeqCst) {
            // Trip the breaker.
            0 => Err(SynoFsError::Io("link down".into())),
            // The half-open probe, which this backend simply cannot serve.
            1 => Err(SynoFsError::NotSupported),
            // If the breaker was left half-open, we never get asked again.
            _ => Ok(vec![]),
        }
    }
}

#[tokio::test]
async fn declining_a_half_open_probe_does_not_strand_the_backend() {
    // `allows` returns false in HalfOpen until a verdict is recorded, so a
    // decline that records nothing disables the backend for the life of
    // the process — over an operation it merely does not implement.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"files": [], "total": 0, "offset": 0}
        })))
        .mount(&server)
        .await;

    let backend = Arc::new(ScriptedMeta {
        calls: AtomicUsize::new(0),
    });
    let client = client_for(&server).with_metadata_transport_breaker(
        backend.clone(),
        BreakerConfig {
            failure_threshold: 1,
            cooldown: Duration::ZERO,
        },
    );

    client.list_dir("/share").await.unwrap(); // trips the breaker
    client.list_dir("/share").await.unwrap(); // half-open probe, declined
    client.list_dir("/share").await.unwrap(); // must reach the backend again

    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        3,
        "the backend was asked again after declining; a stranded breaker \
         would have stopped at 2"
    );
}

/// The same script as `ScriptedMeta`, for the other two decline sites:
/// trip the breaker, decline the half-open probe, then answer.
struct ScriptedWriter {
    calls: AtomicUsize,
}

impl ScriptedWriter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
        })
    }
    fn next(&self) -> Result<(), SynoFsError> {
        match self.calls.fetch_add(1, Ordering::SeqCst) {
            0 => Err(SynoFsError::Io("link down".into())),
            1 => Err(SynoFsError::NotSupported),
            _ => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl StreamWriteTransport for ScriptedWriter {
    async fn write_from_path(&self, _p: &str, _local: &Path) -> Result<(), SynoFsError> {
        self.next()
    }
    async fn write_new_from_path(&self, _p: &str, _local: &Path) -> Result<(), SynoFsError> {
        self.next()
    }
}

#[async_trait::async_trait]
impl OpenWriteTransport for ScriptedWriter {
    async fn open_write(
        &self,
        _path: &str,
        _mode: WriteOpen,
    ) -> Result<Box<dyn WriteHandle>, SynoFsError> {
        self.next()?;
        struct Nowhere;
        #[async_trait::async_trait]
        impl WriteHandle for Nowhere {
            async fn write_at(&mut self, _o: u64, _d: &[u8]) -> Result<(), SynoFsError> {
                Ok(())
            }
            async fn close(&mut self) -> Result<(), SynoFsError> {
                Ok(())
            }
        }
        Ok(Box::new(Nowhere))
    }
}

fn twitchy_breaker() -> BreakerConfig {
    BreakerConfig {
        failure_threshold: 1,
        cooldown: Duration::ZERO,
    }
}

#[tokio::test]
async fn a_declined_open_write_leaves_the_backend_askable() {
    let server = MockServer::start().await;
    let backend = ScriptedWriter::new();
    let client =
        client_for(&server).with_open_write_transport_breaker(backend.clone(), twitchy_breaker());

    // Trip, then a declined half-open probe, then it must be asked again.
    client
        .open_write("/share/f.bin", WriteOpen::Existing)
        .await
        .ok();
    client
        .open_write("/share/f.bin", WriteOpen::Existing)
        .await
        .ok();
    client
        .open_write("/share/f.bin", WriteOpen::Existing)
        .await
        .ok();

    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        3,
        "a stranded breaker would have stopped asking at 2"
    );
}

#[tokio::test]
async fn a_declined_create_new_leaves_the_backend_askable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true, "data": {"blks": null}
        })))
        .mount(&server)
        .await;

    let src = write_scratch_file(b"payload");
    let backend = ScriptedWriter::new();
    let client =
        client_for(&server).with_stream_write_transport_breaker(backend.clone(), twitchy_breaker());

    for _ in 0..3 {
        client
            .upload_from_path(&src, "/share", "f.bin", false)
            .await
            .unwrap();
    }

    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        3,
        "a stranded breaker would have stopped asking at 2"
    );
    std::fs::remove_file(&src).ok();
}
