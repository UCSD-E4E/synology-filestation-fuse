//! Logging in, how the session id travels, and recovering from SID expiry.

use super::*;

// ── secret leakage ───────────────────────────────────────────────────────

/// Regression: reqwest embeds the full request URL, query string included,
/// in the Display of a transport error. Every FileStation call carried the
/// session id as `_sid`, so one connection failure published a live bearer
/// token into the CLI's stderr, the GUI's log pane and the message of every
/// Python exception. Nothing leaving this client may carry it.
#[tokio::test]
async fn a_transport_error_never_carries_the_session_id() {
    // Port 1 has nothing listening, so the request fails at connect — the
    // path that bakes the request URL into the error message.
    let client = SynologyClient::new("127.0.0.1", 1, false);
    *client.sid.write().unwrap() = Some("SUPERSECRETSID".to_string());

    let err = client.list_dir("/share").await.unwrap_err();

    let message = err.to_string();
    assert!(
        message.contains("entry.cgi"),
        "precondition: the error should carry the URL, else this proves \
         nothing: {message}"
    );
    assert!(
        !message.contains("SUPERSECRETSID"),
        "session id leaked into a transport error: {message}"
    );
}

/// The stashed password must not be one stray `{:?}` away from a log line.
///
/// The literal is deliberately shaped like a placeholder rather than like a
/// password: a realistic-looking one here trips secret scanners on every
/// pull request, and a security check that cries wolf is one people learn
/// to click past.
#[test]
fn debug_formatting_stored_creds_hides_the_password() {
    let creds = StoredCreds {
        user: "alice".into(),
        password: "placeholder-not-a-real-password".into(),
    };
    let rendered = format!("{creds:?}");
    assert!(
        !rendered.contains("placeholder-not-a-real-password"),
        "{rendered}"
    );
    assert!(rendered.contains("alice"), "{rendered}");
}

// ── how the session id travels ───────────────────────────────────────────

/// Mount the share listing the post-login probe asks for.
async fn mount_probe_ok(server: &MockServer) {
    Mock::given(method("GET"))
        .and(query_param("method", "list_share"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"success": true, "data": {"total": 0, "shares": []}}),
        ))
        .mount(server)
        .await;
}

fn empty_list() -> ResponseTemplate {
    ResponseTemplate::new(200)
        .set_body_json(serde_json::json!({"success": true, "data": {"total": 0, "files": []}}))
}

/// Regression: the session id rode in the query string of every call, which
/// puts a live bearer token in the NAS's own access log, in any proxy's log
/// in between, and in the text of every transport error. It travels as a
/// cookie now, and no request URL may contain it.
#[tokio::test]
async fn the_session_id_never_appears_in_a_request_url() {
    let server = MockServer::start().await;
    mount_auth(
        &server,
        serde_json::json!({"success": true, "data": {"sid": "SUPERSECRETSID"}}),
    )
    .await;
    mount_probe_ok(&server).await;
    Mock::given(method("GET"))
        .and(query_param("method", "list"))
        .respond_with(empty_list())
        .mount(&server)
        .await;

    let client = client_for(&server);
    client.login("alice", "secret", None).await.unwrap();
    client.list_dir("/share").await.unwrap();
    client.logout().await.unwrap();

    let requests = server.received_requests().await.unwrap();
    assert!(requests.len() >= 4, "login + probe + list + logout");
    for req in &requests {
        assert!(
            !req.url.as_str().contains("SUPERSECRETSID"),
            "session id in a request URL: {}",
            req.url
        );
        assert!(
            !req.url.as_str().contains("_sid"),
            "_sid parameter still present: {}",
            req.url
        );
    }
}

/// ...and it does still reach the server, just in a header.
#[tokio::test]
async fn the_session_id_travels_as_a_cookie() {
    let server = MockServer::start().await;
    mount_auth(
        &server,
        serde_json::json!({"success": true, "data": {"sid": "SUPERSECRETSID"}}),
    )
    .await;
    mount_probe_ok(&server).await;

    let client = client_for(&server);
    client.login("alice", "secret", None).await.unwrap();
    assert!(client.session_in_cookie());

    let requests = server.received_requests().await.unwrap();
    let probe = requests
        .iter()
        .find(|r| r.url.query().is_some_and(|q| q.contains("list_share")))
        .expect("the probe request");
    assert_eq!(
        probe.headers.get("cookie").unwrap().to_str().unwrap(),
        "id=SUPERSECRETSID"
    );
}

/// The cookie is a claim about a server we cannot test against here, so it
/// is verified rather than assumed. A DSM that answers 119 to the probe
/// sends the client back to the query parameter — degraded, but working,
/// which is the right way round for an unverifiable assumption.
#[tokio::test]
async fn a_dsm_that_rejects_the_cookie_falls_back_to_the_query_parameter() {
    let server = MockServer::start().await;
    mount_auth(
        &server,
        serde_json::json!({"success": true, "data": {"sid": "SUPERSECRETSID"}}),
    )
    .await;
    Mock::given(method("GET"))
        .and(query_param("method", "list_share"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"success": false, "error": {"code": 119}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(query_param("method", "list"))
        .respond_with(empty_list())
        .mount(&server)
        .await;

    let client = client_for(&server);
    client.login("alice", "secret", None).await.unwrap();
    assert!(
        !client.session_in_cookie(),
        "a 119 to the probe must switch the client to query auth"
    );

    client.list_dir("/share").await.unwrap();
    let requests = server.received_requests().await.unwrap();
    let list = requests
        .iter()
        .rfind(|r| r.url.query().is_some_and(|q| q.contains("method=list&")))
        .expect("the list request");
    assert!(
        list.url.as_str().contains("_sid=SUPERSECRETSID"),
        "the fallback must still authenticate: {}",
        list.url
    );
}

/// A probe that cannot reach the NAS says nothing about whether the cookie
/// is accepted — the network is simply down. Downgrading on that would
/// permanently degrade a session over an unrelated blip.
#[tokio::test]
async fn a_probe_that_cannot_reach_the_nas_does_not_downgrade_the_session() {
    let server = MockServer::start().await;
    mount_auth(
        &server,
        serde_json::json!({"success": true, "data": {"sid": "s"}}),
    )
    .await;
    // No probe route: wiremock answers 404 with an empty body — a failure,
    // but not a 119.
    let client = client_for(&server);
    client.login("alice", "secret", None).await.unwrap();

    assert!(
        client.session_in_cookie(),
        "only a definitive 119 should downgrade the session"
    );
}

// ── login ────────────────────────────────────────────────────────────────

/// Mount an auth.cgi handler and return the login response body it serves.
async fn mount_auth(server: &MockServer, body: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/webapi/auth.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn login_stores_sid_on_success() {
    let server = MockServer::start().await;
    mount_auth(
        &server,
        serde_json::json!({"success": true, "data": {"sid": "abc123def"}}),
    )
    .await;

    let client = client_for(&server);
    client.login("alice", "secret", None).await.unwrap();
    assert_eq!(client.sid(), "abc123def");
}

#[tokio::test]
async fn login_returns_api_error_on_failure() {
    let server = MockServer::start().await;
    mount_auth(
        &server,
        serde_json::json!({"success": false, "error": {"code": 400}}),
    )
    .await;

    let client = client_for(&server);
    let err = client.login("alice", "wrong", None).await.unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(400)));
}

#[tokio::test]
async fn login_with_otp_sends_the_otp_code() {
    let server = MockServer::start().await;
    mount_auth(
        &server,
        serde_json::json!({"success": true, "data": {"sid": "otp_sid_xyz"}}),
    )
    .await;

    let client = client_for(&server);
    client
        .login("alice", "secret", Some("123456"))
        .await
        .unwrap();
    assert_eq!(client.sid(), "otp_sid_xyz");

    let reqs = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&reqs[0].body);
    assert!(
        body.contains("otp_code=123456"),
        "otp missing from body: {body}"
    );
}

/// Regression: login was a GET carrying `passwd=<plaintext>` in the query
/// string. Query strings are written to DSM's own nginx access log and to
/// any proxy in between, so every login left the account password sitting
/// in plaintext on disk in at least one place. Credentials belong in the
/// request body.
#[tokio::test]
async fn login_never_puts_credentials_in_the_url() {
    let server = MockServer::start().await;
    mount_auth(
        &server,
        serde_json::json!({"success": true, "data": {"sid": "s"}}),
    )
    .await;

    let client = client_for(&server);
    client
        .login("alice", "placeholder-not-a-real-password", Some("998877"))
        .await
        .unwrap();

    let reqs = server.received_requests().await.unwrap();
    let req = &reqs[0];
    let url = req.url.as_str();
    assert!(
        !url.contains("placeholder-not-a-real-password"),
        "password leaked into the URL: {url}"
    );
    assert!(!url.contains("passwd"), "passwd param in the URL: {url}");
    assert!(!url.contains("998877"), "otp leaked into the URL: {url}");
    assert!(!url.contains("alice"), "account leaked into the URL: {url}");

    // ...and it really did travel, just in the body.
    let body = String::from_utf8_lossy(&req.body);
    assert!(
        body.contains("placeholder-not-a-real-password"),
        "password missing from the body: {body}"
    );
}

// ── logout ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn logout_clears_sid() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/auth.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"sid": "session_abc"}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    client.login("alice", "secret", None).await.unwrap();
    assert_eq!(client.sid(), "session_abc");
    client.logout().await.unwrap();
    assert_eq!(client.sid(), "");
}

// ── auto-relogin & SID-expiry handling ───────────────────────────────────
//
// DSM expires session tokens after ~30 minutes of inactivity, returning
// ApiError(119) ("SID not found"). Long-running scripts should recover
// transparently. These tests pin down the contract:
//   - default client (no auto_relogin): 119 surfaces unchanged
//   - auto_relogin client: 119 triggers one re-login + one retry; if the
//     retry succeeds the caller never sees 119; if the retry or re-login
//     itself fails, the *latest* error is what surfaces

#[tokio::test]
async fn default_client_does_not_stash_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/auth.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"sid": "abc"}
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    client.login("alice", "secret", None).await.unwrap();
    assert!(!client.auto_relogin_enabled());
    // No stashed creds → relogin must refuse rather than silently no-op.
    let err = client.relogin().await.unwrap_err();
    assert!(matches!(err, SynoFsError::NotSupported));
}

#[tokio::test]
async fn auto_relogin_client_stashes_credentials_on_login() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/auth.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"sid": "first"}
        })))
        .mount(&server)
        .await;

    let client = client_auto_for(&server);
    assert!(client.auto_relogin_enabled());
    client.login("alice", "secret", None).await.unwrap();
    // relogin should succeed using stashed creds (server returns the same SID).
    client.relogin().await.unwrap();
}

#[tokio::test]
async fn api_119_surfaces_when_auto_relogin_off() {
    // Pre-bug-fix behavior: a default client should still see 119 directly.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/auth.cgi"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"sid": "s"}
        })))
        .mount(&server)
        .await;
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
    client.login("alice", "secret", None).await.unwrap();
    let err = client
        .with_relogin_retry(|| client.get_info("/share/x"))
        .await
        .unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(119)));
}

#[tokio::test]
async fn api_119_triggers_transparent_relogin_and_retry_succeeds() {
    // Sequence: client logs in → operation returns 119 (SID expired) →
    // client transparently re-logs-in → operation retried → caller sees Ok.
    let server = MockServer::start().await;

    // Both login calls return the same fixed sid; server doesn't care
    // about sid value, only that the call sequence is right.
    Mock::given(method("POST"))
        .and(path("/webapi/auth.cgi"))
        .and(body_string_contains("method=login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"sid": "fresh_sid"}
        })))
        .expect(2) // initial login + one re-login
        .mount(&server)
        .await;

    // First getinfo call: 119. Second call: success.
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 119}
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"files": [
                {"name": "x", "path": "/share/x", "isdir": false, "additional": null}
            ]}
        })))
        .mount(&server)
        .await;

    let client = client_auto_for(&server);
    client.login("alice", "secret", None).await.unwrap();
    let info = client
        .with_relogin_retry(|| client.get_info("/share/x"))
        .await
        .unwrap();
    assert_eq!(info.name, "x");
    // MockServer drop verifies the .expect(2) on the login mock — both
    // initial login and re-login were observed.
}

#[tokio::test]
async fn api_119_relogin_failure_surfaces_auth_error() {
    // Initial login OK; first op gets 119; re-login fails (e.g. password
    // changed server-side). Caller should see the re-login failure, NOT
    // the original 119, so they can act on the right cause.
    let server = MockServer::start().await;

    // First login: success. Second login (re-login): auth failure (400).
    Mock::given(method("POST"))
        .and(path("/webapi/auth.cgi"))
        .and(body_string_contains("method=login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"sid": "first"}
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/webapi/auth.cgi"))
        .and(body_string_contains("method=login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 400}
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 119}
        })))
        .mount(&server)
        .await;

    let client = client_auto_for(&server);
    client.login("alice", "secret", None).await.unwrap();
    let err = client
        .with_relogin_retry(|| client.get_info("/share/x"))
        .await
        .unwrap_err();
    // The re-login failure is wrapped so callers can distinguish "the
    // operation failed" from "we couldn't even re-authenticate."
    match err {
        SynoFsError::LoginFailed(inner) => assert!(
            matches!(*inner, SynoFsError::ApiError(400)),
            "expected wrapped ApiError(400), got {inner:?}"
        ),
        other => panic!("expected LoginFailed(ApiError(400)), got {other:?}"),
    }
}

#[tokio::test]
async fn api_119_only_retries_once() {
    // If both the initial call AND the retry return 119, give up — don't
    // loop forever. The second 119 is what the caller sees.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/auth.cgi"))
        .and(body_string_contains("method=login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"sid": "s"}
        })))
        .expect(2) // initial + 1 re-login, no more
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 119}
        })))
        .expect(2) // exactly 2 attempts, never 3
        .mount(&server)
        .await;

    let client = client_auto_for(&server);
    client.login("alice", "secret", None).await.unwrap();
    let err = client
        .with_relogin_retry(|| client.get_info("/share/x"))
        .await
        .unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(119)));
}

#[tokio::test]
async fn non_119_errors_do_not_trigger_relogin() {
    // 408 (no permission) is deterministic — re-logging-in won't fix it.
    // Verify we don't re-auth on non-119 errors. The login mock has
    // .expect(1) and the test will fail on drop if we re-login.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/webapi/auth.cgi"))
        .and(body_string_contains("method=login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "data": {"sid": "s"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/webapi/entry.cgi"))
        .and(query_param("method", "getinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": false,
            "error": {"code": 408}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client_auto_for(&server);
    client.login("alice", "secret", None).await.unwrap();
    let err = client
        .with_relogin_retry(|| client.get_info("/share/x"))
        .await
        .unwrap_err();
    assert!(matches!(err, SynoFsError::ApiError(408)));
}
