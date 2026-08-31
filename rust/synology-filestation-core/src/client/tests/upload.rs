//! Uploads: whole-file, streaming selection, slice protocol, and deadlines.

use super::*;

// ── upload ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn upload_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"blks": null}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    client
        .upload("/share", "test.txt", b"content".to_vec(), false)
        .await
        .unwrap();
}

#[tokio::test]
async fn upload_returns_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 1805}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .upload("/share", "test.txt", b"data".to_vec(), false)
        .await
        .unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(1805)));
}

#[tokio::test]
async fn upload_with_overwrite_deletes_then_polls_then_uploads() {
    let server = MockServer::start().await;
    // DELETE call (GET method=delete)
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "delete"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true
        })))
        .mount(&server)
        .await;
    // Poll for file gone (GET method=getinfo) — return error so upload proceeds
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 414}
        })))
        .mount(&server)
        .await;
    // Actual upload (POST)
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"blks": null}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    client
        .upload("/share", "test.txt", b"new content".to_vec(), true)
        .await
        .unwrap();
}

/// Regression: `clear_for_overwrite` used to run *once*, before the retry
/// loop. An overwrite that had to be retried therefore re-POSTed with
/// `overwrite=false` onto ground that was no longer clear — if the first
/// attempt actually landed on the NAS before the response was lost, DSM
/// answered 418 and a write that had *succeeded* was reported as
/// AlreadyExists. Each attempt must start from cleared ground.
#[tokio::test]
async fn overwrite_upload_reclears_the_destination_before_each_retry() {
    let server = MockServer::start().await;

    // The delete must happen once per upload attempt, not once per call.
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "delete"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"success": true})),
        )
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"success": false, "error": {"code": 414}})),
        )
        .mount(&server)
        .await;

    // First attempt: the backend is degraded (the shape that leaves a write
    // possibly-applied but unacknowledged). Second attempt: fine.
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"success": true, "data": {"blks": null}})),
        )
        .with_priority(2)
        .mount(&server)
        .await;

    let client = client_for(&server);
    client
        .upload("/share", "test.txt", b"new content".to_vec(), true)
        .await
        .expect("a retried overwrite must succeed, not report AlreadyExists");
    // `expect(2)` on the delete mock is asserted when the server drops.
}

/// The retry above is only safe because each attempt re-clears; it must not
/// widen into retrying a *definitive* refusal. A 400 is the server telling
/// us the request itself is wrong — resending it cannot help.
#[tokio::test]
async fn upload_does_not_retry_a_permanent_http_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(400))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_for(&server);
    let err = client
        .upload("/share", "test.txt", b"data".to_vec(), false)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SynoFsError::Io(ref m) if m.contains("400")),
        "expected a permanent HTTP error, got {err:?}"
    );
}

// ── streaming upload (upload_from_path) selection ────────────────────────

#[tokio::test]
async fn upload_from_path_prefers_stream_backend_and_skips_http() {
    let src = write_scratch_file(b"streamed payload");
    let backend = FakeBackend::new(Behave::Ok(b""));
    let client = offline_client().with_stream_write_transport(backend.clone());
    client
        .upload_from_path(&src, "/share", "f.bin", true)
        .await
        .unwrap();
    assert_eq!(backend.call_count(), 1);
    std::fs::remove_file(&src).ok();
}

#[tokio::test]
async fn upload_from_path_falls_back_to_http_on_transient() {
    let src = write_scratch_file(b"streamed payload");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true, "data": {"blks": null}
        })))
        .mount(&server)
        .await;
    let backend = FakeBackend::new(Behave::Transient);
    let client = client_for(&server).with_stream_write_transport(backend.clone());
    client
        .upload_from_path(&src, "/share", "f.bin", true)
        .await
        .unwrap();
    assert_eq!(backend.call_count(), 1, "attempted before HTTP fallback");
    std::fs::remove_file(&src).ok();
}

#[tokio::test]
async fn a_new_file_is_streamed_through_the_backend() {
    // Creating a file is the case large copies are made of, so it must not
    // be the one case that skips the fast path. The backend is asked for
    // create-new semantics rather than the replacing write, so the "don't
    // clobber" contract survives the change of transport.
    let src = write_scratch_file(b"streamed payload");
    let server = MockServer::start().await;
    let backend = FakeBackend::new(Behave::Ok(b""));
    let client = client_for(&server).with_stream_write_transport(backend.clone());
    client
        .upload_from_path(&src, "/share", "f.bin", false)
        .await
        .unwrap();

    assert_eq!(
        backend.new_call_count(),
        1,
        "asked to create, not to replace"
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "the NAS's HTTP API is not touched when the backend took the write"
    );
    std::fs::remove_file(&src).ok();
}

#[tokio::test]
async fn a_new_file_whose_name_is_taken_is_refused_rather_than_retried() {
    // The name being taken is an answer, not a transport hiccup: HTTP would
    // only reach the same conclusion, and re-uploading to find out costs
    // the whole file.
    let src = write_scratch_file(b"streamed payload");
    let server = MockServer::start().await;
    let backend = FakeBackend::new(Behave::Exists);
    let client = client_for(&server).with_stream_write_transport(backend.clone());
    let err = client
        .upload_from_path(&src, "/share", "f.bin", false)
        .await
        .unwrap_err();

    assert!(matches!(err, SynoFsError::AlreadyExists), "got {err:?}");
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no second opinion over HTTP"
    );
    std::fs::remove_file(&src).ok();
}

#[tokio::test]
async fn a_backend_that_cannot_create_new_defers_to_http() {
    // Declining is not failing. A backend without create-new semantics
    // simply doesn't get the new-file case, and its breaker stays shut so
    // it still serves the writes it can.
    let src = write_scratch_file(b"streamed payload");
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true, "data": {"blks": null}
        })))
        .mount(&server)
        .await;
    let backend = FakeBackend::new(Behave::CannotCreateNew);
    let client = client_for(&server).with_stream_write_transport(backend.clone());
    client
        .upload_from_path(&src, "/share", "f.bin", false)
        .await
        .unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 1);

    // Same client, a replacing write: the breaker must not have been
    // tripped by the decline.
    client
        .upload_from_path(&src, "/share", "f.bin", true)
        .await
        .unwrap();
    assert_eq!(
        backend.call_count(),
        2,
        "the decline cost the backend nothing"
    );
    std::fs::remove_file(&src).ok();
}

// ── slice upload ─────────────────────────────────────────────────────────
//
// Mirrors what the DSM 7 File Station web UI does for large files (mined
// from a browser capture of a 4.9 GB upload): one POST per slice, with the
// chunking carried in request headers rather than the multipart body. Every
// slice repeats the same body fields; the server ties them together by tmpfile.
//
//   X-TYPE-NAME: SLICEUPLOAD
//   X-FILE-SIZE: <total bytes>
//   X-FILE-CHUNK-END: false   (true on the final slice)
//   X-TMP-FILE: <tmpfile>     (echoed from the previous response, slice 2+)
//
// Confirmed against DSM's own uploader (FileUploader_T9JY.js): the final
// data slice carries X-FILE-CHUNK-END: true and its response is the result --
// there is no separate finalize request. Slices are tied together by echoing
// the response's `tmpfile` back as X-TMP-FILE; a non-final response without
// one is fatal. DSM slices only above 4 GiB; we slice above one slice, because
// our motive is bounded memory rather than its POST limit.

#[tokio::test]
async fn slice_upload_splits_file_and_marks_final_slice() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"blSkip": false, "progress": 1, "tmpfile": "slice.1.0.9224"}
        })))
        .mount(&server)
        .await;

    let local = scratch_file("split.bin", 2500);
    let client = client_for(&server).with_slice_size(1024);
    client
        .upload_from_path(&local, "/share", "big.bin", false)
        .await
        .unwrap();

    // POSTs only: a completed sliced upload also GETs the file back to
    // check what landed.
    let reqs = slice_posts(&server).await;
    assert_eq!(reqs.len(), 3, "2500 bytes at 1024/slice is 3 slices");
    for r in &reqs {
        assert_eq!(header_of(r, "X-TYPE-NAME").as_deref(), Some("SLICEUPLOAD"));
        assert_eq!(header_of(r, "X-FILE-SIZE").as_deref(), Some("2500"));
    }
    let ends: Vec<_> = reqs
        .iter()
        .map(|r| header_of(r, "X-FILE-CHUNK-END").unwrap())
        .collect();
    assert_eq!(ends, vec!["false", "false", "true"]);

    // Slice 1 opens the upload; every later slice echoes the tmpfile the
    // server handed back, which is what ties them to one partial file.
    let tmps: Vec<_> = reqs.iter().map(|r| header_of(r, "X-TMP-FILE")).collect();
    assert_eq!(
        tmps,
        vec![
            None,
            Some("slice.1.0.9224".to_string()),
            Some("slice.1.0.9224".to_string())
        ]
    );
    std::fs::remove_file(&local).ok();
}

#[tokio::test]
async fn slice_upload_skipped_for_file_that_fits_one_slice() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true, "data": {"blks": null}
        })))
        .mount(&server)
        .await;

    let local = scratch_file("small.bin", 500);
    let client = client_for(&server).with_slice_size(1024);
    client
        .upload_from_path(&local, "/share", "small.bin", false)
        .await
        .unwrap();

    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "one-shot upload for a file under one slice");
    assert!(
        header_of(&reqs[0], "X-TYPE-NAME").is_none(),
        "no slice headers on the one-shot path"
    );
    std::fs::remove_file(&local).ok();
}

#[tokio::test]
async fn slice_upload_stops_at_the_failing_slice() {
    // A DSM error code is a verdict, not a blip: the slice is not resent,
    // and the remaining slices are not sent either. (Transport failures are
    // resent — see `slice_upload_resends_a_failed_slice_on_the_same_tmpfile`.)
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false, "error": {"code": 1805}
        })))
        .mount(&server)
        .await;

    let local = scratch_file("fail.bin", 2500);
    let client = client_for(&server).with_slice_size(1024);
    let err = client
        .upload_from_path(&local, "/share", "big.bin", false)
        .await
        .unwrap_err();

    assert!(matches!(err, SynoFsError::ApiError(1805)));
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "first slice fails, remaining slices are not sent"
    );
    std::fs::remove_file(&local).ok();
}

#[tokio::test]
async fn slice_upload_aborts_when_tmpfile_missing() {
    // DSM's own client treats a non-final response with no tmpfile as fatal:
    // without it the next slice has nothing to append to.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"blSkip": false, "progress": 1}
        })))
        .mount(&server)
        .await;

    let local = scratch_file("notmp.bin", 2500);
    let client = client_for(&server).with_slice_size(1024);
    let err = client
        .upload_from_path(&local, "/share", "big.bin", false)
        .await
        .unwrap_err();

    assert!(matches!(err, SynoFsError::Io(_)));
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "no tmpfile to continue with, so no second slice"
    );
    std::fs::remove_file(&local).ok();
}

#[tokio::test]
async fn upload_preserves_mtime_and_sends_size() {
    // Proven against the NAS in a browser capture: File Station sends the
    // local mtime in ms and the server stores it (the listing came back with
    // mtime = the value sent, crtime = upload time). Without it every
    // uploaded file is stamped with the upload time instead.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true, "data": {"blks": null}
        })))
        .mount(&server)
        .await;

    let local = scratch_file("mtime.bin", 300);
    let client = client_for(&server);
    client
        .upload_from_path(&local, "/share", "mtime.bin", false)
        .await
        .unwrap();

    let reqs = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&reqs[0].body).to_string();
    assert!(body.contains("name=\"size\""), "one-shot upload sends size");
    assert!(
        body.contains("name=\"mtime\""),
        "one-shot upload sends mtime"
    );
    let sent_ms: u128 = body
        .split("name=\"mtime\"")
        .nth(1)
        .unwrap()
        .trim_start_matches("\r\n\r\n")
        .lines()
        .next()
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let want_ms = std::fs::metadata(&local)
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    assert_eq!(
        sent_ms, want_ms,
        "mtime is the local file's, in milliseconds"
    );
    std::fs::remove_file(&local).ok();
}

#[tokio::test]
async fn slice_upload_reports_progress_per_slice() {
    // The FFI can't observe slice boundaries itself (they live inside the
    // core loop), so the GUI's upload bar depends on this callback.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"blSkip": false, "tmpfile": "slice.1.0.9224"}
        })))
        .mount(&server)
        .await;

    let local = scratch_file("progress.bin", 2500);
    let client = client_for(&server).with_slice_size(1024);
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = seen.clone();
    client
        .upload_from_path_with_progress(
            &local,
            "/share",
            "big.bin",
            false,
            Some(&move |done, total| sink.lock().unwrap().push((done, total))),
        )
        .await
        .unwrap();

    assert_eq!(
        *seen.lock().unwrap(),
        vec![(1024, 2500), (2048, 2500), (2500, 2500)],
        "cumulative bytes after each slice"
    );
    std::fs::remove_file(&local).ok();
}

#[tokio::test]
async fn slice_upload_sends_create_parents_like_the_one_shot_path() {
    // Both paths are reached through the same public API, so a large file
    // must not lose directory auto-creation that a small one gets.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"blSkip": false, "tmpfile": "slice.1.0.9224"}
        })))
        .mount(&server)
        .await;

    let local = scratch_file("parents.bin", 2500);
    let client = client_for(&server).with_slice_size(1024);
    client
        .upload_from_path(&local, "/share/new/dir", "big.bin", false)
        .await
        .unwrap();

    for req in slice_posts(&server).await {
        let body = String::from_utf8_lossy(&req.body).to_string();
        assert!(
            body.contains("name=\"create_parents\""),
            "every slice carries create_parents"
        );
        // Deliberately absent: DSM's own uploader sends `size` only on the
        // one-shot path and puts the total in X-FILE-SIZE when slicing.
        assert!(
            !body.contains("name=\"size\""),
            "the slice path uses the X-FILE-SIZE header, not a size field"
        );
    }
    std::fs::remove_file(&local).ok();
}

// ── upload deadlines ─────────────────────────────────────────────────────
//
// reqwest's `read_timeout` is not the idle timer its name suggests: it is
// armed when the request is created and polled alongside the pending
// request, so it caps the whole span from "request started" to "response
// headers arrived" — including writing the request body. A 30 s cap
// therefore aborts any upload whose body takes longer than 30 s to push,
// which on a slow link is every large file; the caller sees "operation
// timed out" (EIO on the FUSE mount) with nothing actually wrong. Uploads
// get their own client with no read timeout, bounded per request by a
// size-derived deadline instead.

#[tokio::test]
async fn one_shot_upload_outlives_the_metadata_read_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(400))
                .set_body_json(serde_json::json!({"success": true, "data": {}})),
        )
        .mount(&server)
        .await;

    let local = scratch_file("slow-oneshot.bin", 500);
    let client = client_for(&server)
        .with_slice_size(1024)
        .with_read_timeout_for_test(Duration::from_millis(100));
    client
        .upload_from_path(&local, "/share", "slow.bin", false)
        .await
        .expect("a slow upload is not a dead one");
    std::fs::remove_file(&local).ok();
}

#[tokio::test]
async fn slice_upload_outlives_the_metadata_read_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(400))
                .set_body_json(serde_json::json!({
                    "success": true,
                    "data": {"blSkip": false, "tmpfile": "slice.1.0.9224"}
                })),
        )
        .mount(&server)
        .await;

    let local = scratch_file("slow-slice.bin", 2500);
    let client = client_for(&server)
        .with_slice_size(1024)
        .with_read_timeout_for_test(Duration::from_millis(100));
    client
        .upload_from_path(&local, "/share", "big.bin", false)
        .await
        .expect("every slice gets the same reprieve");

    assert_eq!(slice_posts(&server).await.len(), 3);
    std::fs::remove_file(&local).ok();
}

#[tokio::test]
async fn upload_is_still_bounded_by_its_own_deadline() {
    // Dropping the read timeout must not mean "hang forever": a server that
    // takes the body and then goes silent still has to fail, or the FUSE
    // callback that called flush never returns.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/entry.cgi"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(30))
                .set_body_json(serde_json::json!({"success": true, "data": {}})),
        )
        .mount(&server)
        .await;

    let local = scratch_file("hung.bin", 500);
    let client = client_for(&server)
        .with_slice_size(1024)
        .with_upload_deadline_for_test(Duration::from_millis(150), u64::MAX);
    let started = std::time::Instant::now();
    let err = client
        .upload_from_path(&local, "/share", "hung.bin", false)
        .await
        .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the deadline fired, not the mock's own delay: {err}"
    );
    std::fs::remove_file(&local).ok();
}

#[test]
fn upload_deadline_scales_with_the_payload() {
    let policy = UploadDeadline::default();
    // A 10 MiB slice on a link crawling at the assumed floor still fits.
    let slice = policy.for_bytes(DEFAULT_SLICE_SIZE as u64);
    assert!(
        slice >= Duration::from_secs(5 * 60),
        "10 MiB at the floor rate needs minutes, got {slice:?}"
    );
    // A bigger payload gets proportionally longer, rather than one fixed cap
    // that is either too tight for slow links or useless on fast ones.
    assert!(policy.for_bytes(DEFAULT_SLICE_SIZE as u64 * 4) > slice);
    // An empty body still gets the grace period, never a zero deadline.
    assert_eq!(policy.for_bytes(0), policy.grace);
}
