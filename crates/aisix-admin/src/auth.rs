//! Admin authorization: which credential a request presents, and which
//! cross-origin requests may present one at all.
//!
//! Two concerns live here because they are one concern: a credential the
//! browser attaches **by itself** is ambient authority, and ambient
//! authority is what makes a request forgeable from another origin.
//!
//! ## Credentials
//!
//! Admin keys come from `config.admin.admin_keys` (static, bootstrap
//! config), not the `ApiKey` table in etcd, and are presented as
//! `Authorization: Bearer <key>` with an `x-api-key` fallback. A
//! [`crate::session`] cookie is an equally-valid alternative for a
//! browser client; see that module for why the key has to be exchanged
//! at all.
//!
//! ## Precedence: the first credential presented is the one that decides
//!
//! Resolution is ordered, and it **never falls through**:
//!
//! 1. `Authorization`, if present — valid key, authorized; anything else,
//!    `401`, *without consulting the cookie*.
//! 2. `x-api-key`, if present — same rule.
//! 3. The session cookie, if present — live session, authorized;
//!    expired, revoked, or unknown, `401`.
//! 4. Nothing — `401`.
//!
//! The no-fall-through part is the security-relevant half. If a *bad*
//! `Authorization` header could be rescued by a good cookie, then a
//! client holding a stale header reads `200` and never learns its header
//! is wrong; worse, the authority actually used is no longer the one the
//! request named, which is precisely the ambiguity an attacker wants
//! when they can influence headers. A presented credential is a
//! *declaration* of how the caller is authenticating, and the answer
//! must be about that declaration. `pinned_precedence_never_falls_through`
//! is the test that says so.
//!
//! `AdminAuth` short-circuits with an `AdminError::Unauthorized`
//! envelope before any handler runs.
//!
//! ## CSRF: the guard the cookie makes necessary
//!
//! Once a browser holds the session cookie, every mutating admin route
//! becomes reachable from any page the operator visits, and the header
//! path is no longer a defence — a cross-origin page cannot set
//! `Authorization` without a CORS preflight, but it does not need to when
//! the cookie rides along on its own.
//!
//! [`require_same_origin`] is the second layer, and it is deliberately
//! *not* a CSRF token. `SameSite=Strict` already prevents the browser from
//! attaching the cookie to a cross-site request at all, which is the
//! primary control; a double-submit token would add a second
//! JS-readable value, a second header, and a second failure mode to
//! defend a case `Strict` does not reach. What `Strict` alone does not
//! give is a check that runs **server-side and is therefore testable**,
//! and does not depend on browser-version cookie handling, and covers
//! the residual surfaces `Strict` leaves: a same-site cross-origin
//! context (a different port or a sibling subdomain of the same
//! registrable domain still sends a `Strict` cookie, because `Strict`
//! keys on *site*, not *origin*). `Origin`/`Referer` verification is
//! listed by OWASP as a defence to deploy alongside `SameSite` — see
//! <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>,
//! "Common approaches", which recommends using the two together.
//!
//! The check compares **host, not scheme**, for a reason worth stating:
//! scheme is not observable from an axum request here (TLS completes in
//! the gateway's own accept loop), and cookies ignore scheme and port
//! alike, so host is the boundary that both `SameSite` and the cookie's
//! own scoping actually use. Comparing the scheme would require trusting
//! a client-supplied forwarded header to say anything at all.

use axum::body::Body;
use axum::extract::{FromRef, FromRequestParts, Request};
use axum::http::header;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::error::AdminError;
use crate::session::{session_token_from_cookies, SessionStore};
use crate::state::AdminState;

/// Marker yielded by the extractor once an admin credential has been
/// verified. Handlers don't need the credential itself — just proof that
/// the caller supplied a valid one — so the type is empty by design.
/// (A handler that does need to act on a session reads the cookie itself;
/// see `delete_session`.)
#[derive(Debug, Clone, Copy)]
pub struct AdminAuth;

#[axum::async_trait]
impl<S> FromRequestParts<S> for AdminAuth
where
    S: Send + Sync,
    AdminState: FromRef<S>,
{
    type Rejection = AdminError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let admin_state = AdminState::from_ref(state);
        if !is_admin_authorized(
            &parts.headers,
            &admin_state.admin_keys,
            &admin_state.sessions,
        ) {
            return Err(AdminError::Unauthorized);
        }
        Ok(AdminAuth)
    }
}

/// Header-level admin check shared by the extractor above and by
/// router-layer middleware (which runs *before* per-handler extractors
/// and therefore cannot use `AdminAuth` directly). True iff the request
/// presents a valid admin credential under the precedence the module doc
/// states.
///
/// `sessions` is the only thing the cookie path needs; a caller that
/// cannot have sessions (no store) simply answers `false` for a cookie,
/// which is the same answer as an invalid one.
pub(crate) fn is_admin_authorized(
    headers: &HeaderMap,
    admin_keys: &[String],
    sessions: &SessionStore,
) -> bool {
    // A header that is *present* is a declaration, and it is answered on
    // its own. Note that a present-but-unusable header (wrong scheme,
    // empty, non-UTF-8) short-circuits to `false` rather than being
    // skipped: it was presented, so it is the credential being claimed.
    if let Some(raw) = headers.get(header::AUTHORIZATION) {
        return match raw.to_str().ok().and_then(strip_bearer) {
            Some(token) => admin_key_is_valid(token, admin_keys),
            None => false,
        };
    }
    if let Some(raw) = headers.get("x-api-key") {
        return match raw.to_str() {
            Ok(value) => admin_key_is_valid(value.trim(), admin_keys),
            Err(_) => false,
        };
    }
    match session_token_from_cookies(headers) {
        Some(token) => sessions.is_live(&token, chrono::Utc::now()),
        None => false,
    }
}

/// The `Bearer ` prefix, or `None` for any other scheme. An empty token
/// after the prefix is still a token, just never a valid one — which
/// `admin_key_is_valid` decides, so the emptiness check stays in the one
/// place that compares keys.
fn strip_bearer(value: &str) -> Option<&str> {
    value.strip_prefix("Bearer ").map(str::trim)
}

/// True iff `candidate` is one of `admin_keys`.
///
/// The comparison visits every key and every byte position of the longer of
/// the two, and decides only at the end, because this is the check an
/// exchange endpoint and a header both funnel through: a timing side channel
/// here would be a side channel on the admin key, and routing two paths
/// through one primitive means neither can quietly ship the weaker version.
///
/// The two properties that are easy to get wrong, and what they cost when
/// they are:
///
/// * **Length is compared exactly, not modulo a word.** The form this
///   replaced accumulated `(candidate.len() ^ key.len()) as u8`, which
///   truncates: a 32-byte key with a candidate of `key + "A" * 256` has
///   `32 ^ 288 == 256`, and `256u8 == 0` — so a 288-byte string beginning
///   with the whole admin key was ACCEPTED. That is not a no-credential
///   bypass (the key still has to be presented in full), but it makes this
///   function's own contract false and makes "the length is compared" a
///   claim about a truncated quantity. `diff` is a `usize` here, and the
///   lengths are folded into it before the byte loop rather than truncated
///   into it.
/// * **`zip` alone hides the tail.** `bytes.iter().zip(other.iter())` walks
///   `min(len)` pairs, so bytes past the shorter operand are never looked at
///   even in principle. The loop is over `max(len)` and reads the missing
///   side as a zero byte, which costs nothing to express and makes "every
///   position is compared" true rather than approximately true.
///
/// What is still NOT hidden is the lengths themselves: the loop runs
/// `max(len)` times, so an attacker learns how long the operator's key is.
/// That is the operator's own value in their own config, and hiding it would
/// need a fixed-width compare over a padded field — a different and larger
/// design — so it is stated here rather than implied away. What is hidden is
/// everything the attacker would actually brute-force: no position of the key
/// can be probed by timing.
///
/// A present-but-malformed `Authorization` never reaches here: a
/// non-`Bearer` scheme is rejected by the caller's [`strip_bearer`].
pub(crate) fn admin_key_is_valid(candidate: &str, admin_keys: &[String]) -> bool {
    if candidate.is_empty() {
        return false;
    }
    let bytes = candidate.as_bytes();
    let mut matched = false;
    // `|=` does not short-circuit, so every key is compared every time.
    for key in admin_keys {
        let other = key.as_bytes();
        // Full-width, and exact: see the doc above for what `as u8` cost.
        let mut diff = bytes.len() ^ other.len();
        for i in 0..bytes.len().max(other.len()) {
            // A position past the end of one side reads as zero. The lengths
            // are already folded into `diff`, so the zero itself decides
            // nothing — it only keeps the loop from skipping those positions.
            let a = bytes.get(i).copied().unwrap_or(0);
            let b = other.get(i).copied().unwrap_or(0);
            diff |= usize::from(a ^ b);
        }
        matched |= diff == 0;
    }
    matched
}

/// Router-layer CSRF guard, applied to the whole admin router in
/// `build_router`.
///
/// Enforcement is on **unsafe methods only** (`POST`, `PUT`, `PATCH`,
/// `DELETE`, … — anything that is not `GET`/`HEAD`/`OPTIONS`), so reads
/// are untouched and the rule cannot regress a dashboard read by being
/// stricter than it needs to be.
///
/// The rule, in full:
///
/// - no `Origin` and no `Referer` → allowed. This is the non-browser
///   case (`curl`, a server-side script, a CI job): those clients send
///   neither, and refusing them would break every scripted caller for no
///   security gain — a non-browser client is not a browser that can be
///   made to issue a cross-site request.
/// - `Origin` present → its `host[:port]` must equal the request's `Host`
///   header, or `403`.
/// - `Origin` absent, `Referer` present → same comparison on the
///   referer's `host[:port]`, or `403`.
///
/// Requiring the header to be *present* would be the stricter design and
/// is deliberately not used: `Origin` is not sent by non-browser clients
/// at all, so requiring it refuses them, and browsers always send `Origin`
/// on a cross-origin unsafe request (the Fetch spec sets it for every
/// non-`GET`/`HEAD` request, including a cross-site form `POST`), while it
/// cannot be suppressed by a page the way `Referer` can — `no-referrer`
/// drops `Referer` but not `Origin`. The comparison therefore closes the
/// browser case while leaving the scripted case intact, which is the same
/// split `SameSite` draws and for the same reason.
///
/// `Origin: null` (a sandboxed/opaque origin) does not match any host and
/// is refused, which is the intent.
pub(crate) async fn require_same_origin(
    request: Request<Body>,
    next: axum::middleware::Next,
) -> Result<Response, Response> {
    if is_safe(request.method()) {
        return Ok(next.run(request).await);
    }

    // RFC 3986: the host is case-insensitive, and a browser will not
    // normalize it for us. Lowercased so it compares equal to
    // `host_of_authority`, which lowercases the other side.
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase());

    // Which header, if any, declares an origin, and what host it names.
    // The outer `Option` is "a header was present at all" and the inner
    // one is "a host we could read out of it" — keeping them apart is
    // load-bearing, because a present-but-unreadable value must be
    // REFUSED, never treated as the absent case. Collapsing the two is
    // how `Origin: null` becomes a bypass.
    let declared: Option<Option<String>> = match request.headers().get(header::ORIGIN) {
        Some(origin) => Some(origin.to_str().ok().and_then(host_of_authority)),
        None => request
            .headers()
            .get(header::REFERER)
            .map(|referer| referer.to_str().ok().and_then(host_of_authority)),
    };
    match declared {
        // Neither header present: a `curl`, a server-side script, a CI
        // job, or an in-process `oneshot`. No browser produces this for an
        // unsafe request, so there is no cross-site request to refuse, and
        // requiring the header would break every scripted caller for
        // nothing.
        None => Ok(next.run(request).await),
        // A header WAS sent and names no host to compare against —
        // `Origin: null` from a sandboxed context, a relative referer, a
        // non-UTF-8 value. Refused.
        Some(None) => Err(csrf_rejection()),
        // A declaration exists, so it has to be vouched for. A missing
        // `Host` cannot vouch for it. (A browser always sends `Host` on
        // HTTP/1.1, so that combination is unreachable from the threat
        // model and costs no real caller.)
        Some(Some(declared)) => match host {
            Some(host) if host == declared => Ok(next.run(request).await),
            _ => Err(csrf_rejection()),
        },
    }
}

/// The `host[:port]` of an `Origin` (`https://h:p`) or a `Referer`
/// (`https://h:p/path`). `None` when the value is not an absolute URL we
/// can take an authority from — including `null`, and including a
/// relative referer, neither of which identifies a host.
///
/// Deliberately the *whole authority*, port included: a browser omits the
/// port on a default-port origin on both sides of the comparison
/// (`Host: example.com` over HTTPS, `Origin: https://example.com`), so
/// including it costs nothing and keeps `http://h:3001` and `http://h:4001`
/// — which DO share cookies, because cookies ignore port — from being
/// treated as the same origin.
fn host_of_authority(value: &str) -> Option<String> {
    let after_scheme = value.split_once("://")?.1;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    // Strip userinfo — it is not part of the host comparison.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        None
    } else {
        Some(authority.to_ascii_lowercase())
    }
}

fn is_safe(method: &Method) -> bool {
    method == Method::GET || method == Method::HEAD || method == Method::OPTIONS
}

/// The 403 body. It names the failing check and nothing else — no
/// `Origin`, no `Host`, no hint about whether a session exists. A CSRF
/// refusal is a statement about the request, not about the caller.
fn csrf_rejection() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error_msg": "cross-origin request refused: this admin route is same-origin only",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{SessionStore, COOKIE_NAME};
    use axum::http::HeaderValue;
    use axum::Router;
    use tower::ServiceExt;

    fn bearer(value: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_static(value));
        h
    }

    fn store_with_live_session() -> (SessionStore, String) {
        let store = SessionStore::default();
        let token = store.issue(chrono::Utc::now());
        (store, token)
    }

    fn cookie_header(name: &str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{name}={value}")).unwrap(),
        );
        h
    }

    // ---- credential extraction ------------------------------------------

    #[test]
    fn extract_bearer_reads_authorization_header() {
        let h = bearer("Bearer admin-secret");
        let keys = vec!["admin-secret".to_string()];
        assert!(is_admin_authorized(&h, &keys, &SessionStore::default()));
    }

    #[test]
    fn extract_bearer_accepts_x_api_key_fallback() {
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_static("admin-secret"));
        let keys = vec!["admin-secret".to_string()];
        assert!(is_admin_authorized(&h, &keys, &SessionStore::default()));
    }

    #[test]
    fn extract_bearer_rejects_missing_and_wrong_scheme() {
        let keys = vec!["admin-secret".to_string()];
        let empty = SessionStore::default();
        assert!(!is_admin_authorized(&HeaderMap::new(), &keys, &empty));

        let wrong_scheme = bearer("Basic Zm9v");
        assert!(!is_admin_authorized(&wrong_scheme, &keys, &empty));

        // Present but empty: presented, therefore answered, therefore 401.
        let empty_bearer = bearer("Bearer ");
        assert!(!is_admin_authorized(&empty_bearer, &keys, &empty));
    }

    #[test]
    fn is_admin_authorized_checks_key_membership() {
        let keys = vec!["admin-secret".to_string()];
        let empty = SessionStore::default();
        assert!(is_admin_authorized(
            &bearer("Bearer admin-secret"),
            &keys,
            &empty
        ));
        assert!(!is_admin_authorized(&bearer("Bearer nope"), &keys, &empty));
        assert!(!is_admin_authorized(&HeaderMap::new(), &keys, &empty));
    }

    /// The comparison is exact, on every axis, and not only in the way the
    /// obvious cases check.
    ///
    /// The case this exists for is the one a length-only check gets wrong in
    /// a way that is invisible until you compute it: the implementation this
    /// replaces accumulated `(candidate.len() ^ key.len()) as u8`, which
    /// truncates modulo 256, so for a 32-byte key a candidate of
    /// `key + "A" * 256` has `32 ^ 288 == 256` and `256u8 == 0` — the whole
    /// admin key followed by 256 bytes was ACCEPTED. Both halves are
    /// asserted directly, because a test that only checked "the exact key is
    /// accepted" would have stayed green through that bug.
    #[test]
    fn a_key_is_accepted_exactly_and_a_superstring_of_it_is_not() {
        let key = "0123456789abcdef0123456789abcdef"; // 32 bytes, as shipped
        let keys = vec![key.to_string()];
        assert_eq!(key.len(), 32, "the fixture must be the length it claims");
        assert!(admin_key_is_valid(key, &keys));

        // The truncation case, spelled out: 32 ^ 288 == 256, and 256 & 0xFF
        // == 0, so the old accumulator saw no difference at all.
        let padded = format!("{key}{}", "A".repeat(256));
        assert_eq!(padded.len(), 288);
        assert_eq!(32 ^ 288, 256, "the arithmetic this test pins");
        assert!(
            !admin_key_is_valid(&padded, &keys),
            "the admin key followed by 256 bytes authenticated as the admin key"
        );
        // A prefix, a suffix and a single flipped byte are all refused, and
        // the byte position does not matter — the old `zip` walked only
        // `min(len)`, so a difference past the shorter side was never in
        // range to be found.
        for candidate in [
            format!("{key}A"),
            format!("A{key}"),
            format!("{key} "),
            "0123456789abcdef0123456789abcdeZ".to_string(),
            "0123456789abcdef0123456789abcdeF".to_string(),
        ] {
            assert!(
                !admin_key_is_valid(&candidate, &keys),
                "a near miss authenticated: {candidate:?}"
            );
        }
        // An empty candidate is refused by the guard, not by the compare.
        assert!(!admin_key_is_valid("", &keys));
        // Membership, not equality with the first entry — and specifically a
        // match in the LAST position, which is what a short-circuit that
        // returned on the first key would get wrong. The key is deliberately
        // the final element, so an implementation that stops comparing after
        // the first non-match fails here.
        let many = vec!["other".to_string(), "third".to_string(), key.to_string()];
        assert!(admin_key_is_valid(key, &many));
        assert!(!admin_key_is_valid("nope", &many));
        // …and the first-position case is the same answer, so the result does
        // not depend on where in the list the match sits.
        let first = vec![key.to_string(), "other".to_string()];
        assert!(admin_key_is_valid(key, &first));
    }

    // ---- the cookie credential ------------------------------------------

    #[test]
    fn a_live_session_cookie_authorizes_on_its_own() {
        let (sessions, token) = store_with_live_session();
        let keys: Vec<String> = Vec::new();
        let h = cookie_header(COOKIE_NAME, &token);
        assert!(is_admin_authorized(&h, &keys, &sessions));
    }

    #[test]
    fn a_revoked_or_unknown_session_cookie_is_unauthorized() {
        let (sessions, token) = store_with_live_session();
        let keys: Vec<String> = Vec::new();
        sessions.revoke(&token);
        assert!(!is_admin_authorized(
            &cookie_header(COOKIE_NAME, &token),
            &keys,
            &sessions
        ));
        // A token this process never issued reads the same way.
        assert!(!is_admin_authorized(
            &cookie_header(COOKIE_NAME, &"0".repeat(64)),
            &keys,
            &sessions
        ));
    }

    #[test]
    fn an_expired_session_cookie_is_unauthorized() {
        let sessions = SessionStore::default();
        // Issued a full TTL ago, so it is already past its own deadline.
        let token = sessions.issue(chrono::Utc::now() - chrono::Duration::seconds(86_400));
        assert!(!sessions.is_live(&token, chrono::Utc::now()));
        assert!(!is_admin_authorized(
            &cookie_header(COOKIE_NAME, &token),
            &Vec::new(),
            &sessions
        ));
    }

    #[test]
    fn a_cookie_sitting_beside_others_is_found() {
        let (sessions, token) = store_with_live_session();
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("_ga=GA1.2.3; {COOKIE_NAME}={token}; theme=dark"))
                .unwrap(),
        );
        assert!(is_admin_authorized(&h, &Vec::new(), &sessions));
    }

    /// A cookie whose name merely *starts with* ours is a different
    /// cookie. Without the `=` check, `aisix_admin_session_x` would
    /// match the `aisix_admin_session` prefix and be read as a token.
    ///
    /// Asserted on the READER, not on `is_admin_authorized`: an unknown
    /// token is unauthenticated either way, so a gate-level assertion
    /// cannot tell "not recognised as our cookie" from "recognised, but
    /// no such session" — and would stay green if the prefix check were
    /// removed entirely.
    #[test]
    fn a_longer_cookie_name_is_not_our_cookie() {
        let (sessions, _token) = store_with_live_session();
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{COOKIE_NAME}_backup=whatever")).unwrap(),
        );
        assert_eq!(session_token_from_cookies(&h), None);
        assert!(!is_admin_authorized(&h, &Vec::new(), &sessions));
    }

    // ---- precedence ------------------------------------------------------

    /// The precedence rule, pinned: a bad `Authorization` header is
    /// answered `401` even when a *valid* session cookie rides along, and
    /// the same in reverse for a bad `x-api-key`. Neither credential
    /// rescues the other.
    #[test]
    fn pinned_precedence_never_falls_through() {
        let (sessions, token) = store_with_live_session();
        let valid_cookie = cookie_header(COOKIE_NAME, &token);

        // Valid header, valid cookie -> authorized either way.
        let keys = vec!["admin-secret".to_string()];
        let both_valid = {
            let mut h = bearer("Bearer admin-secret");
            h.insert(header::COOKIE, valid_cookie[header::COOKIE].clone());
            h
        };
        assert!(is_admin_authorized(&both_valid, &keys, &sessions));

        // BAD header, valid cookie -> refused. The header was presented,
        // so the header decides.
        let bad_header = {
            let mut h = bearer("Bearer wrong-key");
            h.insert(header::COOKIE, valid_cookie[header::COOKIE].clone());
            h
        };
        assert!(
            !is_admin_authorized(&bad_header, &keys, &sessions),
            "an invalid Authorization header must not fall through to a valid cookie"
        );

        // BAD x-api-key, valid cookie -> refused, same rule.
        let bad_fallback = {
            let mut h = HeaderMap::new();
            h.insert("x-api-key", HeaderValue::from_static("wrong-key"));
            h.insert(header::COOKIE, valid_cookie[header::COOKIE].clone());
            h
        };
        assert!(!is_admin_authorized(&bad_fallback, &keys, &sessions));

        // Authorization wins over x-api-key: a bad Authorization with a
        // GOOD x-api-key is still refused, because Authorization is first.
        let bad_auth_good_fallback = {
            let mut h = bearer("Bearer wrong-key");
            h.insert("x-api-key", HeaderValue::from_static("admin-secret"));
            h
        };
        assert!(!is_admin_authorized(
            &bad_auth_good_fallback,
            &keys,
            &sessions
        ));
    }

    /// A good `x-api-key` with no `Authorization` header is authorized —
    /// the fallback still works, and the cookie is not needed.
    #[test]
    fn x_api_key_fallback_is_reached_only_when_authorization_is_absent() {
        let keys = vec!["admin-secret".to_string()];
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_static("admin-secret"));
        assert!(is_admin_authorized(&h, &keys, &SessionStore::default()));
    }

    // ---- key membership --------------------------------------------------

    #[test]
    fn admin_key_is_valid_rejects_wrong_length_and_wrong_bytes() {
        let keys = vec!["admin-secret".to_string()];
        assert!(admin_key_is_valid("admin-secret", &keys));
        assert!(!admin_key_is_valid("admin-secre", &keys));
        assert!(!admin_key_is_valid("admin-secrets", &keys));
        assert!(!admin_key_is_valid("admin-secreT", &keys));
        assert!(!admin_key_is_valid("", &keys));
        assert!(!admin_key_is_valid("x", &keys));
    }

    /// A key at ANY position in the list counts, and a near-miss at any
    /// position does not. This pins the membership decision over the
    /// whole list, which is what a refactor to "check the first key, then
    /// the rest" would break.
    ///
    /// It does **not** pin the constant-time property, and nothing in a
    /// unit test can: there is no assertion that fails when a `return`
    /// goes back inside the loop. The timing argument is a property of
    /// the source (no early return, `|=` rather than `||`) and is
    /// reviewed, not measured. Stated here so this test is not read as
    /// evidence for something it cannot show.
    #[test]
    fn every_key_in_the_list_is_compared() {
        let keys = vec![
            "first".to_string(),
            "second".to_string(),
            "third".to_string(),
        ];
        assert!(admin_key_is_valid("third", &keys));
        assert!(admin_key_is_valid("first", &keys));
        assert!(!admin_key_is_valid("thirt", &keys));
        assert!(!admin_key_is_valid("thirD", &keys));
        // An empty list has nothing to match.
        assert!(!admin_key_is_valid("third", &[]));
    }

    // ---- CSRF guard ------------------------------------------------------

    /// A router carrying the guard and a route that would happily answer
    /// anything. `Next` has no public constructor in axum, so driving the
    /// guard means driving it through the real middleware stack — which
    /// is the better test anyway: it is the wiring the binary uses.
    fn guarded() -> Router {
        Router::new()
            .route(
                "/admin/v1/combos/:id",
                axum::routing::any(|| async { StatusCode::NO_CONTENT }),
            )
            .layer(axum::middleware::from_fn(require_same_origin))
    }

    /// The status the guard produces: `200`-ish when the request reached
    /// the handler, `403` when the guard refused it.
    async fn verdict(method: Method, headers: &[(&str, &str)]) -> StatusCode {
        let mut builder = Request::builder()
            .method(method)
            .uri("/admin/v1/combos/whatever");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        guarded()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .expect("router must answer")
            .status()
    }

    async fn verdict_body(headers: &[(&str, &str)]) -> (StatusCode, String) {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/admin/v1/combos/whatever");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = guarded()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .expect("router must answer");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    /// The base case the refusals below are measured against: same-origin
    /// reaches the handler. Without it, a blanket 403 would pass
    /// everything.
    async fn same_origin_baseline() {
        assert_eq!(
            verdict(
                Method::POST,
                &[
                    ("Host", "admin.example.com"),
                    ("Origin", "https://admin.example.com")
                ]
            )
            .await,
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn cross_origin_mutation_is_refused() {
        same_origin_baseline().await;
        assert_eq!(
            verdict(
                Method::POST,
                &[
                    ("Host", "admin.example.com"),
                    ("Origin", "https://evil.example.com")
                ]
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn a_different_port_on_the_same_host_is_refused() {
        // Cookies ignore the port, so a sibling-port page still gets the
        // `Strict` cookie — exactly the residual surface `Strict` leaves,
        // and the reason the second layer exists.
        same_origin_baseline().await;
        assert_eq!(
            verdict(
                Method::POST,
                &[
                    ("Host", "admin.example.com:3001"),
                    ("Origin", "https://admin.example.com:4001"),
                ]
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn an_opaque_null_origin_is_refused() {
        same_origin_baseline().await;
        assert_eq!(
            verdict(
                Method::POST,
                &[("Host", "admin.example.com"), ("Origin", "null")]
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn a_cross_origin_referer_is_refused_when_origin_is_absent() {
        same_origin_baseline().await;
        assert_eq!(
            verdict(
                Method::POST,
                &[
                    ("Host", "admin.example.com"),
                    ("Referer", "https://evil.example.com/page"),
                ]
            )
            .await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn same_origin_mutation_is_allowed_with_and_without_default_ports() {
        for (host, origin) in [
            ("admin.example.com", "https://admin.example.com"),
            ("localhost:3001", "http://localhost:3001"),
            // A non-default port present on BOTH sides matches.
            ("admin.example.com:8443", "https://admin.example.com:8443"),
        ] {
            assert_eq!(
                verdict(Method::POST, &[("Host", host), ("Origin", origin)]).await,
                StatusCode::NO_CONTENT,
                "host={host} origin={origin}"
            );
        }
    }

    #[tokio::test]
    async fn same_origin_referer_is_allowed_when_origin_is_absent() {
        assert_eq!(
            verdict(
                Method::POST,
                &[
                    ("Host", "admin.example.com"),
                    ("Referer", "https://admin.example.com/dashboard/"),
                ]
            )
            .await,
            StatusCode::NO_CONTENT
        );
    }

    /// A scheme difference is deliberately NOT a failure: the gateway
    /// cannot observe the request's scheme, and cookies ignore it.
    #[tokio::test]
    async fn scheme_mismatch_alone_does_not_refuse() {
        assert_eq!(
            verdict(
                Method::POST,
                &[
                    ("Host", "admin.example.com"),
                    ("Origin", "http://admin.example.com"),
                ]
            )
            .await,
            StatusCode::NO_CONTENT
        );
    }

    /// A non-browser client sends neither header. Refusing it would break
    /// every scripted caller and buy nothing.
    #[tokio::test]
    async fn a_request_with_neither_origin_nor_referer_is_allowed() {
        assert_eq!(
            verdict(Method::POST, &[("Host", "admin.example.com")]).await,
            StatusCode::NO_CONTENT
        );
    }

    /// A declaration that cannot be vouched for is refused. With a
    /// `Host` and no `Origin` there is nothing claimed to check, so the
    /// non-browser case applies; with an `Origin` and no `Host` the
    /// claim cannot be confirmed, and that is a refusal.
    #[tokio::test]
    async fn a_mutation_without_a_host_header_is_refused_when_it_claims_an_origin() {
        assert_eq!(
            verdict(Method::POST, &[("Origin", "https://admin.example.com")]).await,
            StatusCode::FORBIDDEN
        );
        // Nothing claimed, nothing to check: allowed, which is what keeps
        // in-process and scripted callers working.
        assert_eq!(verdict(Method::POST, &[]).await, StatusCode::NO_CONTENT);
    }

    /// The `Some(None)` branch on its own. A present-but-unreadable
    /// `Origin` must not be mistaken for an absent one — that is the
    /// bypass, and it is why the two `Option`s are kept apart.
    #[tokio::test]
    async fn a_present_but_unreadable_origin_is_refused_not_treated_as_absent() {
        for value in ["null", "/relative", "://", "https://"] {
            assert_eq!(
                verdict(
                    Method::POST,
                    &[("Host", "admin.example.com"), ("Origin", value)]
                )
                .await,
                StatusCode::FORBIDDEN,
                "Origin: {value}"
            );
        }
    }

    /// Reads are not gated at all — including a read that carries a
    /// cross-origin `Origin`, which a browser produces for a `no-cors`
    /// fetch. Gating reads is what would break a dashboard page; the
    /// cookie is ambient for reads too, but a read leaks nothing to the
    /// attacker's script (it is not readable cross-origin without CORS,
    /// and CORS is deliberately absent).
    #[tokio::test]
    async fn safe_methods_are_never_gated() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert_eq!(
                verdict(
                    method.clone(),
                    &[
                        ("Origin", "https://evil.example.com"),
                        ("Host", "admin.example.com")
                    ]
                )
                .await,
                StatusCode::NO_CONTENT,
                "{method}"
            );
        }
    }

    /// Every unsafe method is gated, not just `POST` — a guard that only
    /// covered `POST` would leave `DELETE` cross-origin-reachable.
    #[tokio::test]
    async fn every_unsafe_method_is_gated() {
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert_eq!(
                verdict(
                    method.clone(),
                    &[
                        ("Host", "admin.example.com"),
                        ("Origin", "https://evil.example.com")
                    ]
                )
                .await,
                StatusCode::FORBIDDEN,
                "{method}"
            );
        }
    }

    /// The rejection body must not leak the request's own headers back to
    /// whoever sent them.
    #[tokio::test]
    async fn the_refusal_body_carries_no_request_detail() {
        let (status, body) = verdict_body(&[
            ("Host", "admin.example.com"),
            ("Origin", "https://evil.example.com"),
        ])
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            body.contains("error_msg"),
            "admin error envelope shape: {body}"
        );
        assert!(
            !body.contains("evil.example.com"),
            "echoed the origin: {body}"
        );
        assert!(
            !body.contains("admin.example.com"),
            "echoed the host: {body}"
        );
    }

    // ---- authority parsing ----------------------------------------------

    #[test]
    fn host_of_authority_takes_the_host_and_port_only() {
        assert_eq!(
            host_of_authority("https://admin.example.com"),
            Some("admin.example.com".to_string())
        );
        assert_eq!(
            host_of_authority("http://localhost:3001/dashboard/"),
            Some("localhost:3001".to_string())
        );
        assert_eq!(
            host_of_authority("https://user:pw@admin.example.com/x?y#z"),
            Some("admin.example.com".to_string())
        );
        // Case is normalized so `Host` and `Origin` compare equal.
        assert_eq!(
            host_of_authority("https://Admin.Example.COM"),
            Some("admin.example.com".to_string())
        );
        // Not an absolute URL, or no authority at all.
        assert_eq!(host_of_authority("null"), None);
        assert_eq!(host_of_authority("/relative/path"), None);
        assert_eq!(host_of_authority("https://"), None);
    }

    /// Both sides of the comparison are lowercased or not at all, and a
    /// `Host` that is not lowercase must still match an `Origin` that is.
    /// (A real `Host` is case-insensitive per RFC 3986.)
    #[tokio::test]
    async fn host_comparison_is_case_insensitive() {
        assert_eq!(
            verdict(
                Method::POST,
                &[
                    ("Host", "Admin.Example.com"),
                    ("Origin", "https://admin.example.com"),
                ]
            )
            .await,
            StatusCode::NO_CONTENT
        );
    }
}
