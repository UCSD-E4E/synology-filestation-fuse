//! Retry behaviour, the concurrency cap, backoff, and error classification.

use super::*;

// ── retry behaviour ──────────────────────────────────────────────────────
//
// A VPN coming up mid-session silently kills existing TCP connections.
// reqwest's pool happily hands out the dead connection, the request fails,
// and without a retry the FUSE callback returns EIO to the user. The retry
// helper re-issues the request — pool_idle_timeout(4s) gets us a fresh
// connection, which routes correctly over the new VPN interface.
//
// wiremock can't simulate a connection-layer fault (it only models HTTP
// responses), so these tests stand up a tiny tokio TcpListener that closes
// the socket without responding to trigger a real reqwest::Error.

/// Spawn a TCP server that drops the first `failures` connections, then
/// answers the next one with `body` as a JSON HTTP/1.1 response.
async fn flaky_json_server(
    failures: usize,
    body: &'static str,
) -> (u16, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        for _ in 0..failures {
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream); // close immediately, no HTTP response
            }
        }
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    (port, handle)
}

#[tokio::test]
async fn list_dir_recovers_after_transient_connection_drops() {
    // Simulates the VPN-flap scenario: first 2 connections die, 3rd succeeds.
    let body = r#"{"success":true,"data":{"files":[{"name":"hi.txt","path":"/share/hi.txt","isdir":false,"additional":null}]}}"#;
    let (port, handle) = flaky_json_server(2, body).await;

    let client = SynologyClient::new("127.0.0.1", port, false);
    let files = client.list_dir("/share").await.unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "hi.txt");
    handle.await.ok();
}

#[tokio::test]
async fn list_dir_returns_io_error_when_all_retries_fail() {
    // 10 failures > 3 attempts — verifies the helper eventually gives up
    // with an Io error instead of hanging the FUSE callback forever.
    let (port, handle) = flaky_json_server(10, "").await;

    let client = SynologyClient::new("127.0.0.1", port, false);
    let err = client.list_dir("/share").await.unwrap_err();
    assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");
    handle.abort();
}

#[tokio::test]
async fn list_dir_does_not_retry_on_api_error() {
    // API-level failures (success: false) must NOT be retried — they're
    // deterministic, and retrying would multiply the user's wait on a real
    // permission denial or rate-limit.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 408}
        })))
        .expect(1) // verified when MockServer is dropped
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client.list_dir("/share").await.unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(408)));
}

// ── throttle: concurrency cap, backoff, error classification, retry bound ──
//
// The NAS incident: parallel FileStation Download calls saturated the shared
// synoscgi CGI backend, and an inner retry storm re-fetched the same files
// 200-250×. The throttle is the fix — a small global concurrency semaphore,
// a rate-limit belt, jittered exponential backoff on transient/degraded
// responses (HTTP 502/503/504, 407, DSM 402 busy), fail-fast on permanent
// errors (missing file / no permission), and a hard per-file attempt cap so
// the outer scheduler (e.g. Temporal) owns re-scheduling instead of an
// unbounded inner loop.

/// A throttle tuned for fast tests: tiny backoff so retry tests don't sleep
/// for real seconds.
fn fast_throttle(max_concurrency: usize, max_attempts: u32) -> ThrottleConfig {
    ThrottleConfig {
        max_concurrency,
        min_interval: Duration::from_millis(0),
        max_attempts,
        backoff_base: Duration::from_millis(1),
        backoff_max: Duration::from_millis(5),
    }
}

fn client_throttled_for(server: &MockServer, cfg: ThrottleConfig) -> SynologyClient {
    let uri = server.uri();
    let without_scheme = uri.trim_start_matches("http://");
    let (host, port_str) = without_scheme.rsplit_once(':').unwrap();
    let port: u16 = port_str.parse().unwrap();
    SynologyClient::new(host, port, false).with_throttle(cfg)
}

#[tokio::test]
async fn download_retries_http_502_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(ResponseTemplate::new(502))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"payload".to_vec()))
        .mount(&server)
        .await;

    let client = client_throttled_for(&server, fast_throttle(4, 5));
    let bytes = client.download("/share/f", 0, 0).await.unwrap();
    assert_eq!(bytes.as_ref(), b"payload");
}

#[tokio::test]
async fn download_retries_http_407_then_succeeds() {
    // 407 during the incident was the backend fail-closing — back off and
    // retry, don't hammer through it.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(ResponseTemplate::new(407))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ok".to_vec()))
        .mount(&server)
        .await;

    let client = client_throttled_for(&server, fast_throttle(4, 5));
    let bytes = client.download("/share/f", 0, 0).await.unwrap();
    assert_eq!(bytes.as_ref(), b"ok");
}

#[tokio::test]
async fn download_402_busy_backs_off_and_retries() {
    // DSM 402 (system busy) arrives as a 200-OK JSON envelope. It is
    // transient — back off (harder) and retry rather than fail fast.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"success":false,"error":{"code":402}}"#),
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
                .set_body_bytes(b"after-busy".to_vec()),
        )
        .mount(&server)
        .await;

    let client = client_throttled_for(&server, fast_throttle(4, 5));
    let bytes = client.download("/share/f", 0, 0).await.unwrap();
    assert_eq!(bytes.as_ref(), b"after-busy");
}

#[tokio::test]
async fn download_missing_file_fails_fast_without_retry() {
    // A permanent error (DSM 415, no such file/folder) must NOT be retried —
    // retrying wastes the backend's attention exactly like a 502 storm.
    // .expect(1) fails on MockServer drop if we attempt it more than once.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(r#"{"success":false,"error":{"code":415}}"#),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = client_throttled_for(&server, fast_throttle(4, 5));
    let err = client.download("/share/missing", 0, 0).await.unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(415)), "got {err:?}");
}

#[tokio::test]
async fn download_bounded_by_max_attempts() {
    // Persistent transient failure must give up after max_attempts — no
    // unbounded inner loop. .expect(3) pins the exact attempt count.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(ResponseTemplate::new(502))
        .expect(3)
        .mount(&server)
        .await;

    let client = client_throttled_for(&server, fast_throttle(4, 3));
    let err = client.download("/share/f", 0, 0).await.unwrap_err();
    assert!(matches!(err, SynoFsError::Io(_)), "got {err:?}");
}

#[tokio::test]
async fn download_concurrency_capped_by_semaphore() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Raw TCP server that records the peak number of simultaneously
    // in-flight requests. Each connection holds its slot for 50 ms so
    // parallel downloads overlap if the semaphore lets them.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cur = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let cur_s = cur.clone();
    let peak_s = peak.clone();
    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let cur = cur_s.clone();
            let peak = peak_s.clone();
            tokio::spawn(async move {
                let now = cur.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
                let body = b"OKOKOK";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
                cur.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });

    let client =
        Arc::new(SynologyClient::new("127.0.0.1", port, false).with_throttle(fast_throttle(2, 3)));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let c = client.clone();
        tasks.push(tokio::spawn(
            async move { c.download("/share/x", 0, 6).await },
        ));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    let observed = peak.load(Ordering::SeqCst);
    assert!(observed <= 2, "peak concurrency {observed} exceeded cap 2");
    assert!(observed >= 2, "expected the cap to actually be reached");
    handle.abort();
}

#[tokio::test]
async fn download_rate_gate_spaces_out_requests() {
    // Even with plenty of concurrency, the min-interval belt keeps the
    // request rate against synoscgi modest. 4 requests spaced 80 ms apart
    // means the batch cannot finish faster than ~3 intervals.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"z".to_vec()))
        .mount(&server)
        .await;

    let cfg = ThrottleConfig {
        max_concurrency: 8,
        min_interval: Duration::from_millis(80),
        max_attempts: 1,
        backoff_base: Duration::from_millis(1),
        backoff_max: Duration::from_millis(1),
    };
    let client = std::sync::Arc::new(client_throttled_for(&server, cfg));

    let start = std::time::Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let c = client.clone();
        tasks.push(tokio::spawn(
            async move { c.download("/share/x", 0, 0).await },
        ));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(150),
        "rate gate did not space requests: {elapsed:?}"
    );
}

#[tokio::test]
async fn unthrottled_client_download_unaffected() {
    // The FUSE/CLI path constructs the client without a throttle: behavior
    // is exactly as before (no cap, no added delay, plain success).
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"plain".to_vec()))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let bytes = client.download("/share/f", 0, 0).await.unwrap();
    assert_eq!(bytes.as_ref(), b"plain");
}
