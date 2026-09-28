//! Tests for [`crate::session`] — the admin-key → cookie exchange.
//!
//! Driven through the real router, not the handlers directly, because
//! three of the properties under test are wiring properties: that the
//! exchange route is reachable, that the cookie the handler emits is one
//! a browser would actually store and replay, and that the resulting
//! cookie authenticates the *gate* on a route the SPA reads. A handler
//! unit test cannot see any of those.

use super::*;
use crate::state::AdminState;
use aisix_core::snapshot::SnapshotHandle;
use aisix_core::{AdminConfig, AisixSnapshot, TlsConfig};
use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode};
use axum::Router;
use std::sync::Arc;
use tower::ServiceExt;

const KEY: &str = "admin-secret";

fn admin_cfg(tls: bool) -> AdminConfig {
    AdminConfig {
        enabled: true,
        addr: "127.0.0.1:0".into(),
        admin_keys: vec![KEY.into()],
        tls: tls.then(|| TlsConfig {
            cert_file: "cert.pem".into(),
            key_file: "key.pem".into(),
        }),
    }
}

fn state(cfg: &AdminConfig) -> AdminState {
    AdminState::new(
        SnapshotHandle::new(AisixSnapshot::new()),
        crate::store::InMemoryStore::new() as Arc<dyn crate::store::ConfigStore>,
        cfg,
    )
}

/// The real router, so the CSRF layer and the real auth extractor are in
/// the path exactly as they are in the binary.
fn router(state: &AdminState) -> Router {
    crate::build_router(state.clone())
}

fn cookie_of(response: &Response) -> String {
    response
        .headers()
        .get(header::SET_COOKIE)
        .expect("the exchange must set a cookie")
        .to_str()
        .expect("cookie header must be text")
        .to_string()
}

/// The `name=value` pair a browser would send back.
fn cookie_pair(set_cookie: &str) -> String {
    set_cookie
        .split(';')
        .next()
        .expect("a cookie always has a name=value first")
        .trim()
        .to_string()
}

fn exchange_body(key: &str) -> String {
    serde_json::json!({ "admin_key": key }).to_string()
}

async fn send(router: Router, request: Request<Body>) -> (StatusCode, Response) {
    let response = router.oneshot(request).await.expect("router must answer");
    (response.status(), response)
}

async fn post_session(router: Router, key: &str) -> (StatusCode, Response) {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/admin/v1/auth/session")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::HOST, "admin.example.com")
        .body(Body::from(exchange_body(key)))
        .unwrap();
    send(router, request).await
}

// ---- the exchange --------------------------------------------------------

/// The whole point of the endpoint: a valid key buys a cookie, and that
/// cookie then opens a route the SPA reads which was 401 without it.
#[tokio::test]
async fn a_valid_key_buys_a_cookie_that_authenticates_a_protected_read() {
    let state = state(&admin_cfg(false));
    let router = router(&state);

    // Before: no credential at all.
    let (status, _) = send(
        router.clone(),
        Request::builder()
            .uri("/admin/v1/models")
            .header(header::HOST, "admin.example.com")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Exchange.
    let (status, response) = post_session(router.clone(), KEY).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let set_cookie = cookie_of(&response);

    // After: the cookie authenticates the read.
    let (status, _) = send(
        router.clone(),
        Request::builder()
            .uri("/admin/v1/models")
            .header(header::HOST, "admin.example.com")
            .header(header::COOKIE, cookie_pair(&set_cookie))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// The exact attributes the security contract is made of. Pinned
/// individually, because a single `contains("HttpOnly")` on the whole
/// string would still pass if `Secure` were dropped.
///
/// The expectations are **literals, not the constants they check** —
/// `Path=/admin/v1`, a 64-character token, the cookie name. An assertion
/// written as `Path={COOKIE_PATH}` would track the very constant it
/// exists to pin: change `COOKIE_PATH` to `/` and it still passes. Every
/// value here is a contract, not a restatement.
#[tokio::test]
async fn the_cookie_carries_the_documented_attributes() {
    let state = state(&admin_cfg(false));
    let (_, response) = post_session(router(&state), KEY).await;
    let set_cookie = cookie_of(&response);

    let mut parts: Vec<String> = set_cookie
        .split(';')
        .map(|p| p.trim().to_string())
        .collect();
    let value = parts.remove(0);
    assert!(
        value.starts_with("cavora_admin_session="),
        "cookie name: {value}"
    );
    // 32 random bytes, hex-encoded.
    let token = value.split_once('=').unwrap().1;
    assert_eq!(token.len(), 64, "token width: {token}");
    assert!(
        token
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "token must be lowercase hex: {token}"
    );

    assert!(
        parts.contains(&"Path=/admin/v1".to_string()),
        "the cookie must be scoped to the narrowest path that still covers the admin API: {set_cookie}"
    );
    assert!(parts.contains(&"HttpOnly".to_string()));
    assert!(parts.contains(&"SameSite=Strict".to_string()));
    // A plain-HTTP listener: no `Secure`, and no `Max-Age`/`Expires`, so
    // the browser drops the cookie when the browser session ends.
    assert!(!parts.iter().any(|p| p == "Secure"), "{set_cookie}");
    assert!(
        !parts.iter().any(|p| p.starts_with("Max-Age")),
        "{set_cookie}"
    );
    assert!(
        !parts.iter().any(|p| p.starts_with("Expires")),
        "{set_cookie}"
    );
    // Nothing rides along that was not asked for.
    assert_eq!(parts.len(), 3, "unexpected cookie attributes: {set_cookie}");
}

/// The `204` has no body at all, so the token cannot be echoed into one
/// and the SPA has nothing to mis-handle. A body is the one place a
/// second copy of a credential would naturally end up.
#[tokio::test]
async fn the_exchange_response_carries_no_body() {
    let state = state(&admin_cfg(false));
    let (status, response) = post_session(router(&state), KEY).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // A zero `Content-Length` is hyper's, not ours, and is what actually
    // comes back on the wire. RFC 7230 §3.3.2 says a server must not send
    // it on a 204, so this is arguably hyper being non-conformant — but it
    // is harmless (an empty body either way) and asserting its absence
    // would be asserting on the transport, not on this handler. The
    // property that matters is that the body is empty and the declared
    // length agrees.
    let declared_length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|v| v.as_bytes() == b"0");
    assert_ne!(
        declared_length,
        Some(false),
        "unexpected Content-Length on a 204: {:?}",
        response.headers().get(header::CONTENT_LENGTH)
    );
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    assert!(bytes.is_empty(), "204 must not carry a body: {bytes:?}");
}

/// A TLS admin listener marks the cookie `Secure`, so the token never
/// crosses a cleartext hop.
#[tokio::test]
async fn a_tls_listener_marks_the_cookie_secure() {
    let state = state(&admin_cfg(true));
    let (_, response) = post_session(router(&state), KEY).await;
    let set_cookie = cookie_of(&response);
    assert!(set_cookie.contains("; Secure"), "{set_cookie}");
    // And `Secure` does not displace the rest of the contract.
    assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
    assert!(set_cookie.contains("SameSite=Strict"), "{set_cookie}");
    assert!(
        set_cookie.contains(&format!("Path={COOKIE_PATH}")),
        "{set_cookie}"
    );
}

/// A bad key is 401, and the answer must not carry the key back in any
/// form — not the body, not a header. An echoed key is the one way a
/// "you got it wrong" response becomes a "here is the right one".
#[tokio::test]
async fn a_bad_key_is_401_and_the_body_never_echoes_it() {
    let state = state(&admin_cfg(false));
    let router = router(&state);
    let guessed = "super-secret-guess-that-must-not-echo";
    let (status, response) = post_session(router.clone(), guessed).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The secret is nowhere in the response: not the body, and not any
    // header. An echoed key is the one way a "you got it wrong" answer
    // becomes a "here is the right one".
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&body).to_string();
    assert!(!text.contains(guessed), "body echoed the key: {text}");
    for (name, value) in &headers {
        let rendered = format!("{}: {value:?}", name.as_str());
        assert!(
            !rendered.contains(guessed),
            "header echoed the key: {rendered}"
        );
    }
    assert!(
        !text.contains(KEY),
        "body leaked the configured key: {text}"
    );

    // And it issued no cookie.
    let (status, response) = send(
        router,
        Request::builder()
            .method(Method::POST)
            .uri("/admin/v1/auth/session")
            .header(header::HOST, "admin.example.com")
            .body(Body::from(exchange_body(guessed)))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        response.headers().get(header::SET_COOKIE).is_none(),
        "a refused exchange must not set a cookie"
    );
}

/// Two exchanges produce two different tokens, and revoking one does not
/// disturb the other. Without this, a collision would silently be one
/// shared session.
#[tokio::test]
async fn each_exchange_mints_a_distinct_session() {
    let state = state(&admin_cfg(false));
    let router = router(&state);
    let (_, first) = post_session(router.clone(), KEY).await;
    let (_, second) = post_session(router, KEY).await;
    let first = cookie_pair(&cookie_of(&first));
    let second = cookie_pair(&cookie_of(&second));
    assert_ne!(first, second, "two exchanges produced the same session");

    state.sessions.revoke(second.split_once('=').unwrap().1);
    assert!(state
        .sessions
        .is_live(first.split_once('=').unwrap().1, Utc::now()));
    assert!(!state
        .sessions
        .is_live(second.split_once('=').unwrap().1, Utc::now()));
}

// ---- strict body validation ---------------------------------------------

/// Every shape that is not exactly `{"admin_key": "<non-empty string>"}`
/// is refused, and none of the refusals is a `500`.
#[tokio::test]
async fn the_request_body_is_validated_strictly() {
    let state = state(&admin_cfg(false));
    let router = router(&state);
    for (label, body) in [
        ("not json", "nope"),
        ("json array", "[]"),
        ("json string", "\"admin-secret\""),
        ("json null", "null"),
        ("json number", "42"),
        ("empty body", ""),
        ("missing field", "{}"),
        ("null field", "{\"admin_key\":null}"),
        ("numeric field", "{\"admin_key\":7}"),
        ("object field", "{\"admin_key\":{\"a\":1}}"),
        ("empty key", "{\"admin_key\":\"\"}"),
        ("wrong field name", "{\"key\":\"admin-secret\"}"),
        (
            "unknown extra field",
            "{\"admin_key\":\"admin-secret\",\"x\":1}",
        ),
    ] {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/admin/v1/auth/session")
            .header(header::HOST, "admin.example.com")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, response) = send(router.clone(), request).await;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
            "{label}: expected a 4xx, got {status}"
        );
        // `unknown extra field` carries the REAL key. It must not be
        // accepted — a body shape the operator did not write is refused
        // rather than reaching the key check as a different string.
        if label == "unknown extra field" {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
            assert!(
                response.headers().get(header::SET_COOKIE).is_none(),
                "{label} must not authenticate"
            );
        }
    }
}

// ---- logout --------------------------------------------------------------

/// Logout clears the cookie in the browser AND revokes the session
/// server-side, so the captured token is dead even if something kept a
/// copy of it.
#[tokio::test]
async fn logout_clears_the_cookie_and_revokes_the_session() {
    let state = state(&admin_cfg(false));
    let router = router(&state);
    let (_, response) = post_session(router.clone(), KEY).await;
    let set_cookie = cookie_of(&response);
    let pair = cookie_pair(&set_cookie);

    let (status, response) = send(
        router.clone(),
        Request::builder()
            .method(Method::DELETE)
            .uri("/admin/v1/auth/session")
            .header(header::HOST, "admin.example.com")
            .header(header::COOKIE, &pair)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The clearing header must name the SAME cookie at the SAME path, or
    // the browser keeps the original and only looks like it worked.
    let cleared = cookie_of(&response);
    let cleared_pair = cookie_pair(&cleared);
    assert_eq!(
        cleared_pair.split_once('=').unwrap().0,
        pair.split_once('=').unwrap().0,
        "logout cleared a differently-named cookie: {cleared}"
    );
    assert!(
        cleared.contains(&format!("Path={COOKIE_PATH}")),
        "{cleared}"
    );
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert!(cleared.contains("HttpOnly"), "{cleared}");
    assert!(cleared.contains("SameSite=Strict"), "{cleared}");

    // The captured token is dead: replaying it is 401.
    let (status, _) = send(
        router,
        Request::builder()
            .uri("/admin/v1/models")
            .header(header::HOST, "admin.example.com")
            .header(header::COOKIE, &pair)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked session token must not authenticate"
    );
}

/// Logout is behind the admin gate like every other admin route, so the
/// unauthenticated gate is not weakened with a new public surface.
#[tokio::test]
async fn logout_requires_a_credential() {
    let state = state(&admin_cfg(false));
    let router = router(&state);
    let (status, _) = send(
        router,
        Request::builder()
            .method(Method::DELETE)
            .uri("/admin/v1/auth/session")
            .header(header::HOST, "admin.example.com")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A caller that authenticated with a header key has no session to
/// revoke, but the observable outcome — the cookie is gone — still
/// holds, so it is a `204`.
#[tokio::test]
async fn logout_with_a_header_key_still_clears_the_cookie() {
    let state = state(&admin_cfg(false));
    let router = router(&state);
    let (status, response) = send(
        router,
        Request::builder()
            .method(Method::DELETE)
            .uri("/admin/v1/auth/session")
            .header(header::HOST, "admin.example.com")
            .header(header::AUTHORIZATION, format!("Bearer {KEY}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(cookie_of(&response).contains("Max-Age=0"));
}

// ---- expiry --------------------------------------------------------------

/// The TTL is real: a session issued at the far end of its window is
/// already dead, and one issued just inside it is live. Both halves are
/// asserted, because a check that only ever sees `false` cannot tell a
/// TTL from a store that never issues anything.
#[tokio::test]
async fn a_session_expires_at_its_ttl() {
    let store = SessionStore::default();
    let now = Utc::now();

    let fresh = store.issue(now);
    assert!(store.is_live(&fresh, now));
    assert!(store.is_live(&fresh, now + Duration::seconds(SESSION_TTL_SECONDS - 1)));
    assert!(
        !store.is_live(&fresh, now + Duration::seconds(SESSION_TTL_SECONDS)),
        "the session outlived its TTL"
    );
    assert!(
        !store.is_live(&fresh, now + Duration::seconds(SESSION_TTL_SECONDS + 3600)),
        "an hour past its TTL the session is still live"
    );
}

/// An expired session read through the real middleware is 401, which is
/// the replay case: the operator's captured token, past its deadline.
#[tokio::test]
async fn an_expired_session_replays_as_401_through_the_gate() {
    let state = state(&admin_cfg(false));
    let router = router(&state);
    // Mint a token and age it out by hand — the only way to reach expiry
    // without sleeping eight hours.
    let token = state
        .sessions
        .issue(Utc::now() - Duration::seconds(SESSION_TTL_SECONDS + 1));
    let (status, _) = send(
        router,
        Request::builder()
            .uri("/admin/v1/models")
            .header(header::HOST, "admin.example.com")
            .header(header::COOKIE, format!("{COOKIE_NAME}={token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Reading an expired session removes it, so a process nobody logs out
/// of does not accumulate dead entries forever.
#[test]
fn reading_an_expired_session_prunes_it() {
    let store = SessionStore::default();
    let now = Utc::now();
    let token = store.issue(now);
    assert!(store.is_live(&token, now));
    let entries = || store.session_count();
    assert_eq!(entries(), 1);
    assert!(!store.is_live(&token, now + Duration::seconds(SESSION_TTL_SECONDS + 1)));
    assert_eq!(entries(), 0, "an expired session was left in the table");
}

// ---- what is (and is not) stored ----------------------------------------

/// The plaintext token is not retained anywhere: only its SHA-256 digest
/// is in the table, so a memory dump cannot hand out a usable session.
#[test]
fn only_the_digest_is_stored() {
    let store = SessionStore::default();
    let token = store.issue(Utc::now());
    let key = digest(&token);
    assert_eq!(key.len(), 64, "SHA-256 hex is 64 characters");
    assert!(store.contains_digest(&key));
    for entry in store.digest_keys() {
        assert_ne!(entry, token, "the plaintext token is in the store");
    }
}

/// And the digest is a real SHA-256 of the token — not an opaque
/// identifier that merely *looks* hashed, which would be a store that
/// still yields the token.
#[test]
fn the_digest_is_the_documented_sha256() {
    // Pinned against a value computed independently, so a change of hash
    // function is a test failure rather than a silent redefinition of
    // what is stored.
    assert_eq!(
        digest("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_ne!(digest("abc"), digest("abd"));
}

// ---- CSRF, through the real router ---------------------------------------

/// A browser holding a valid session cookie cannot be made to mutate
/// from another origin. This is the end-to-end statement of the whole
/// decision: cookie auth does not hand a cross-site page the admin API.
#[tokio::test]
async fn a_cross_origin_mutation_is_refused_with_a_valid_session_cookie() {
    let state = state(&admin_cfg(false));
    let router = router(&state);
    let (_, response) = post_session(router.clone(), KEY).await;
    let pair = cookie_pair(&cookie_of(&response));

    for (label, extra) in [
        ("cross origin", Some(("Origin", "https://evil.example.com"))),
        ("opaque origin", Some(("Origin", "null"))),
        (
            "cross referer",
            Some(("Referer", "https://evil.example.com/x")),
        ),
        (
            "sibling port",
            Some(("Origin", "https://admin.example.com:4001")),
        ),
    ] {
        let mut builder = Request::builder()
            .method(Method::DELETE)
            .uri("/admin/v1/combos/whatever")
            .header(header::HOST, "admin.example.com")
            .header(header::COOKIE, &pair);
        if let Some((name, value)) = extra {
            builder = builder.header(name, value);
        }
        let (status, _) = send(router.clone(), builder.body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{label}");
    }

    // The same request, same-origin, is allowed — so the refusals above
    // are the check and not a blanket ban on mutations.
    let (status, _) = send(
        router,
        Request::builder()
            .method(Method::DELETE)
            .uri("/admin/v1/combos/whatever")
            .header(header::HOST, "admin.example.com")
            .header(header::COOKIE, &pair)
            .header(header::ORIGIN, "https://admin.example.com")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    // 404, not 403: the id does not exist, which means the route was
    // reached.
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The exchange itself is a mutation, so it is behind the same guard —
/// otherwise the login form would be a cross-site write primitive.
#[tokio::test]
async fn the_exchange_route_is_itself_origin_checked() {
    let state = state(&admin_cfg(false));
    let (status, _) = post_session_with_origin(&state, KEY, "https://evil.example.com").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

async fn post_session_with_origin(
    state: &AdminState,
    key: &str,
    origin: &str,
) -> (StatusCode, Response) {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/admin/v1/auth/session")
        .header(header::HOST, "admin.example.com")
        .header(header::ORIGIN, origin)
        .body(Body::from(exchange_body(key)))
        .unwrap();
    send(router(state), request).await
}

// ---- the gate is not weakened -------------------------------------------

/// The plain unauthenticated case, for every protected route shape. The
/// exchange is new, and the way a new auth surface weakens an old one is
/// by quietly admitting requests the old one refused.
#[tokio::test]
async fn unauthenticated_admin_access_is_still_401() {
    let state = state(&admin_cfg(false));
    let router = router(&state);
    for (method, path) in [
        (Method::GET, "/admin/v1/models"),
        (Method::GET, "/admin/v1/provider_keys"),
        (Method::GET, "/admin/v1/preset_providers"),
        (Method::GET, "/admin/v1/combos"),
        (Method::GET, "/admin/v1/health"),
        (Method::POST, "/admin/v1/combos"),
        (Method::PATCH, "/admin/v1/combos/x"),
        (Method::DELETE, "/admin/v1/combos/x"),
        (Method::POST, "/admin/v1/resources"),
        (Method::DELETE, "/admin/v1/auth/session"),
    ] {
        let (status, _) = send(
            router.clone(),
            Request::builder()
                .method(method.clone())
                .uri(path)
                .header(header::HOST, "admin.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
    }
}

// ---- cookie reading ------------------------------------------------------

/// The reader matches the exact name and nothing influences the result.
#[test]
fn session_token_from_cookies_reads_only_our_cookie() {
    let mut headers = HeaderMap::new();
    assert!(session_token_from_cookies(&headers).is_none());

    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("_ga=GA1; cavora_admin_session=tok; theme=dark"),
    );
    assert_eq!(session_token_from_cookies(&headers).as_deref(), Some("tok"));

    // A prefix match is not a match.
    let mut prefixed = HeaderMap::new();
    prefixed.insert(
        header::COOKIE,
        HeaderValue::from_static("cavora_admin_session_x=nope"),
    );
    assert!(session_token_from_cookies(&prefixed).is_none());

    // A name with no value carries no session.
    let mut empty = HeaderMap::new();
    empty.insert(
        header::COOKIE,
        HeaderValue::from_static("cavora_admin_session="),
    );
    assert!(session_token_from_cookies(&empty).is_none());

    // Two Cookie headers: the ours is still found.
    let mut split = HeaderMap::new();
    split.append(header::COOKIE, HeaderValue::from_static("a=1"));
    split.append(
        header::COOKIE,
        HeaderValue::from_static("cavora_admin_session=second"),
    );
    assert_eq!(
        session_token_from_cookies(&split).as_deref(),
        Some("second")
    );
}
