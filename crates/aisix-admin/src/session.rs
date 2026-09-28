//! Admin-key → HttpOnly session-cookie exchange.
//!
//! ## Why this exists
//!
//! The dashboard SPA is a static export the binary itself serves on the
//! admin listener, so the SPA and the Admin API now share an origin. That
//! makes cookie auth possible, and cookie auth is the only way the UI can
//! work: every admin read in the SPA is unauthenticated unless *something*
//! presents a credential, and the only credential an operator has is the
//! admin key — which is a header value, not something a browser will
//! attach to a `fetch` the SPA's own code makes. A `localStorage` copy
//! would be readable by any script on the origin, which is the exact
//! thing the admin key is not meant to be. So the key is exchanged once
//! for a session the SPA never has to see:
//!
//! - `POST   /admin/v1/auth/session` — body carries the admin key, the
//!   response carries a `Set-Cookie` the SPA does not need to read.
//! - `DELETE /admin/v1/auth/session` — revokes the server-side session
//!   and clears the cookie.
//!
//! The key travels in the **request body**, never a query string: a key
//! in a URL lands in access logs, `Referer` headers, and browser history.
//!
//! ## What is stored, and what is deliberately not
//!
//! A session is 32 bytes from the OS CSPRNG, hex-encoded, and the server
//! stores only `SHA-256(token)` — the same construction
//! `ApiKey::hash_bearer` already uses for caller API keys. The plaintext
//! token exists only in the `Set-Cookie` header, in the caller's browser,
//! and in the local variable that builds it. It is never stored, never
//! logged, and never compared: lookup is a map index on the hash, so the
//! stored digest is not a password that can be brute-forced or
//! second-preimage-guessed — it is the index of a 256-bit random value.
//!
//! That is also why there is **no pepper**. A pepper protects a
//! low-entropy secret whose hash can be enumerated; a 256-bit random
//! token cannot be enumerated at all, so a pepper would add a second
//! operator-managed secret (and a new way to lose access to the admin
//! surface) to defend against an attack that SHA-256 does not have.
//!
//! ## Lifetime
//!
//! The `Set-Cookie` carries **no `Max-Age` and no `Expires`**: the cookie
//! is a session cookie, so the browser discards it when the browser
//! session ends, which is the property the exchange is for. Server-side
//! authority is separate and absolute — see [`SESSION_TTL_SECONDS`].
//!
//! **In-memory storage, and what that costs.** Sessions live in this
//! process only. They do not survive a restart, and if the admin surface
//! is ever scaled past one replica, a session issued by replica A is not
//! a session replica B knows about: without sticky routing, every request
//! would land on a process that has never heard of the token. That is
//! safe (it fails closed — 401, re-exchange) but it is not usable, so a
//! multi-replica deployment needs shared session storage or a shared
//! store before cookie auth works there. In-memory is the right shape for
//! today's single-process admin listener and is called out here rather
//! than left to be discovered.

use axum::extract::State;
use axum::http::header;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde_json::Value;

use crate::auth::AdminAuth;
use crate::error::AdminError;
use crate::state::AdminState;

/// Cookie name. Namespaced so it cannot collide with anything the
/// dashboard bundle or an ingress sets on the same origin.
pub(crate) const COOKIE_NAME: &str = "cavora_admin_session";

/// Cookie `Path`, the narrowest scope that still authenticates the whole
/// admin API: the browser must present the cookie to `GET
/// /admin/v1/models` and to every other `/admin/v1/*` route, so
/// `/admin/v1/auth` would not do, and `/admin/v1/auth/session` would only
/// authenticate itself. It deliberately does **not** cover `/dashboard`,
/// `/_next/*`, `/livez`, `/readyz`, or `/admin/openapi.json` — none of
/// which read it, so none of which should receive it.
const COOKIE_PATH: &str = "/admin/v1";

/// Server-side session lifetime: eight hours, absolute (never extended by
/// use). Chosen to cover a working day so a dashboard left open over
/// lunch is not logged out mid-session, while still bounding how long a
/// captured cookie is worth to anyone. The browser-side lifetime is
/// shorter and separate: the cookie is a session cookie (see the module
/// doc), so closing the browser ends it regardless of this value.
pub(crate) const SESSION_TTL_SECONDS: i64 = 8 * 60 * 60;

/// Token entropy in bytes. 32 bytes = 256 bits, hex-encoded to a
/// 64-character cookie value.
const TOKEN_BYTES: usize = 32;

/// A live session: the moment it stops being honoured. Nothing else is
/// kept — no key material, no client identity, no issued-at bookkeeping,
/// because none of it is read and all of it would be something to leak.
#[derive(Debug, Clone, Copy)]
struct Session {
    expires_at: DateTime<Utc>,
}

/// The admin surface's session table, keyed by `SHA-256(token)` hex.
///
/// DashMap because the read path is per-request on the hot admin surface
/// and the table is small; it gives the same `Sync` shape `AdminState`
/// needs without a lock around the whole router state.
#[derive(Debug, Default)]
pub struct SessionStore {
    sessions: DashMap<String, Session>,
}

impl SessionStore {
    /// Mint a session, returning the plaintext token exactly once — to
    /// the caller that puts it in a `Set-Cookie`. Only the digest is
    /// retained.
    pub fn issue(&self, now: DateTime<Utc>) -> String {
        let token = generate_token();
        let ttl = Duration::seconds(SESSION_TTL_SECONDS);
        self.sessions.insert(
            digest(&token),
            Session {
                expires_at: now + ttl,
            },
        );
        token
    }

    /// True iff `token` names a session that exists and has not expired.
    /// An expired entry is removed on the way out, so the table cannot
    /// grow without bound on a process nothing ever logs out of.
    pub fn is_live(&self, token: &str, now: DateTime<Utc>) -> bool {
        let key = digest(token);
        // The verdict is read out under the guard and the guard is
        // DROPPED before `remove`: `DashMap::remove` takes a write lock
        // on the shard, so calling it while a read guard on that same
        // shard is alive self-deadlocks. Holding the guard across the
        // removal looks like the tidier code and hangs on the first
        // expired token the process ever sees.
        let expired = match self.sessions.get(&key) {
            Some(session) => session.expires_at <= now,
            // A token that was never issued, or was revoked by logout, is
            // simply absent — same answer as an expired one, and the
            // caller cannot tell them apart.
            None => return false,
        };
        if expired {
            self.sessions.remove(&key);
        }
        !expired
    }

    /// Revoke the session named by `token`, if any. Idempotent: logging
    /// out twice, or logging out a session that already expired, is a
    /// success.
    pub fn revoke(&self, token: &str) {
        self.sessions.remove(&digest(token));
    }

    /// Every key currently in the table. Test-only, and deliberately
    /// named for what it proves: the *keys* are what an operator would
    /// find in a memory dump, so that is what a test inspects.
    #[cfg(test)]
    pub(crate) fn digest_keys(&self) -> Vec<String> {
        self.sessions.iter().map(|e| e.key().clone()).collect()
    }

    #[cfg(test)]
    pub(crate) fn contains_digest(&self, key: &str) -> bool {
        self.sessions.contains_key(key)
    }

    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

/// 32 bytes from the OS CSPRNG, hex-encoded. `OsRng` rather than
/// `thread_rng` because the token is a bearer credential whose only
/// defence is that it cannot be guessed, and because the choice should be
/// legible at the call site.
fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The one and only way a token becomes a map key. Same construction as
/// `ApiKey::hash_bearer` (SHA-256, lowercase hex) so there is a single
/// shape of "secret that has been reduced to something storable" in this
/// codebase.
fn digest(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Build the `Set-Cookie` value for a fresh session.
///
/// `secure` is the whole TLS story in one flag, and it is derived rather
/// than configured — the `Secure`-on-TLS rule is resolved once, in
/// `AdminState`, from `admin.tls`. The rule is "mark the cookie `Secure`
/// exactly when the admin listener terminates TLS", which is the only
/// signal available: TLS is completed in the gateway's own accept loop,
/// so an axum request carries no indication of the scheme it arrived on,
/// and inferring it from a `Forwarded`/`X-Forwarded-Proto` header would
/// be reading a value the client can choose.
///
/// That rule errs in the safe direction for the two deployments that
/// exist: a TLS admin listener (`admin.tls` set) always marks the cookie
/// `Secure`, so the token never crosses a cleartext hop; and the
/// shipped plaintext listener (`admin.tls` absent, the
/// `config.example.yaml` default) omits it, so a cookie auth still works
/// over `http://127.0.0.1:3001` for local development and end-to-end
/// tests. An operator who terminates TLS in front of the gateway instead
/// of on it must configure `admin.tls`; that is stated in
/// `config.example.yaml` next to the `tls:` block rather than being a
/// footgun discovered at runtime.
///
/// No `Max-Age` and no `Expires`: a session cookie, discarded by the
/// browser when the browser session ends.
fn set_cookie_value(token: &str, secure: bool) -> String {
    let mut value = format!("{COOKIE_NAME}={token}; Path={COOKIE_PATH}; HttpOnly; SameSite=Strict");
    if secure {
        value.push_str("; Secure");
    }
    value
}

/// The clearing `Set-Cookie` for logout. It repeats every attribute of
/// the cookie it clears, because a browser only replaces a cookie when
/// `Path` and `Domain` match — a clearing header with a different
/// `Path` would leave the original in place while looking like it worked.
/// `Max-Age=0` is the deletion; `SameSite`/`HttpOnly` are repeated so the
/// replaced cookie cannot be anything other than a dead one.
fn clear_cookie_value(secure: bool) -> String {
    let mut value =
        format!("{COOKIE_NAME}=; Path={COOKIE_PATH}; HttpOnly; SameSite=Strict; Max-Age=0");
    if secure {
        value.push_str("; Secure");
    }
    value
}

/// `POST /admin/v1/auth/session` — exchange the admin key for a session.
///
/// The key is read from the request body, and only its membership in
/// `config.admin.admin_keys` is decided here — through the same
/// credential-membership check the header path uses, so the two can
/// never disagree about what a valid key is.
///
/// A bad key answers `401` with the standard admin error envelope. The
/// body never contains the key: the envelope is a fixed string, and the
/// request body is not echoed, reflected, or logged.
///
/// Success is `204 No Content` — the only thing the caller needs is the
/// `Set-Cookie`, and returning a body would only give the SPA something
/// to get wrong.
pub async fn create_session(
    State(state): State<AdminState>,
    body: String,
) -> Result<Response, AdminError> {
    let key = admin_key_from_body(&body)?;
    if !crate::auth::admin_key_is_valid(&key, &state.admin_keys) {
        return Err(AdminError::Unauthorized);
    }
    let token = state.sessions.issue(Utc::now());
    Ok((
        StatusCode::NO_CONTENT,
        [(
            header::SET_COOKIE,
            set_cookie_value(&token, state.session_cookie_secure),
        )],
    )
        .into_response())
}

/// `DELETE /admin/v1/auth/session` — revoke this session and clear the
/// cookie.
///
/// Behind the normal admin gate like every other admin route, so it is
/// `401` without a credential. The credential may be a session cookie or
/// a header key; either way the *session* is what gets revoked, and a
/// caller that authenticated with a header key simply has no session to
/// revoke — the answer is still `204`, because the observable outcome the
/// caller asked for (the cookie is gone) is achieved unconditionally.
///
/// A `401` here is a real and expected answer: it means the presented
/// session was already expired or revoked, so there was nothing to
/// revoke. A client should read `401` on logout as "already signed out"
/// and drop the cookie, because a cookie whose session has expired grants
/// nothing.
pub async fn delete_session(
    _auth: AdminAuth,
    State(state): State<AdminState>,
    headers: HeaderMap,
) -> Response {
    if let Some(token) = session_token_from_cookies(&headers) {
        state.sessions.revoke(&token);
    }
    (
        StatusCode::NO_CONTENT,
        [(
            header::SET_COOKIE,
            clear_cookie_value(state.session_cookie_secure),
        )],
    )
        .into_response()
}

/// Read `admin_key` out of the request body.
///
/// Strict on purpose, in both directions:
///
/// - An unparseable body, a non-object body, a missing field, or a
///   non-string field are all a refusal rather than a default. A
///   permissive read would let a shape the operator did not write reach
///   the key check as something other than the one string it compares.
/// - An **unknown field** is a refusal too. Silently dropping one is the
///   dangerous direction here: a client that sends a field this endpoint
///   does not implement gets a `204` and a session cookie, and concludes
///   its request was honoured — so a future `{"admin_key": "...",
///   "remember": true}` would hand back a *session* cookie while the
///   caller believes it asked for a persistent one. A `400` that names
///   the unexpected field makes that outcome impossible, which is the
///   same reason `keys_handler` pins the PATCHable field set with a
///   schema rather than a hand-maintained list.
fn admin_key_from_body(body: &str) -> Result<String, AdminError> {
    let parsed: Value = serde_json::from_str(body)
        .map_err(|_| AdminError::BadRequest("the request body is not a JSON object".into()))?;
    let object = parsed
        .as_object()
        .ok_or_else(|| AdminError::BadRequest("the request body is not a JSON object".into()))?;
    for name in object.keys() {
        if name != "admin_key" {
            return Err(AdminError::BadRequest(format!(
                "`{name}` is not a field of this request body; the only field is `admin_key`"
            )));
        }
    }
    match object.get("admin_key") {
        Some(Value::String(key)) if !key.is_empty() => Ok(key.clone()),
        Some(_) => Err(AdminError::BadRequest(
            "`admin_key` must be a non-empty string".into(),
        )),
        None => Err(AdminError::BadRequest(
            "the request body must carry `admin_key`".into(),
        )),
    }
}

/// The session token from the request's `Cookie` headers, if any.
///
/// Written by hand rather than pulled from a cookie-parsing dependency
/// because `aisix-admin` has none, and because the parsing rule that
/// matters here is narrow: match on the exact `name=` and nothing else
/// may influence the result. The value is hex, so it has no `;`, space,
/// or quote to unescape — a token containing any of those is not a token
/// this module issued and will simply fail the hash lookup.
pub(crate) fn session_token_from_cookies(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all(header::COOKIE) {
        let Ok(raw) = value.to_str() else { continue };
        for pair in raw.split(';') {
            let pair = pair.trim();
            let Some(token) = pair.strip_prefix(COOKIE_NAME) else {
                continue;
            };
            // `cavora_admin_session` must not match `cavora_admin_session_x`.
            let Some(token) = token.strip_prefix('=') else {
                continue;
            };
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
