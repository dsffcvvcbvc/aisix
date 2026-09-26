//! Cline (`cline`) / ClinePass (`clinepass`) bridges.
//!
//! Byte-parity sources in `open-sse` (read-only reference):
//! - `config/providers/registry/cline/index.ts` and
//!   `config/providers/registry/clinepass/index.ts`: shared host
//!   `POST https://api.cline.bot/api/v1/chat/completions`, OpenAI
//!   format, `forceStream: true` (a non-streaming request returns
//!   "generateText is not implemented", so the bridge always streams
//!   upstream and accumulates for `stream: false` callers).
//! - `src/shared/utils/clineAuth.ts`: the `workos:` bearer shape and
//!   the `HTTP-Referer / X-Title / User-Agent: Cline/<ver> /
//!   X-CLIENT-TYPE / X-CLIENT-VERSION / X-PLATFORM…` identity set, plus
//!   the dual-auth rule (`buildClinepassHeaders`: an OAuth connection
//!   sends `Bearer workos:<token>`, a BYOK `sk_…` key sends a plain
//!   `Bearer <key>`).
//! - `services/tokenRefresh/providers/cline.ts`: refresh posts JSON
//!   `{refreshToken, grantType: "refresh_token", clientType:
//!   "extension"}` and answers `{data: {accessToken, refreshToken,
//!   expiresAt}}` (flat `{accessToken, …}` tolerated).
//!
//! Credential routing inside `ProviderKey.api_key` (one secret, three
//! shapes — mirrors `AntigravityTokenMint::get_token`):
//! - `sk_…` / `sk-…` → BYOK key, sent verbatim (ClinePass only; the
//!   `cline` vendor rejects it upstream, exactly as the TS executor
//!   would after sending `workos:sk_…` — here it fails loudly instead).
//! - `workos:…` → OAuth access token, sent verbatim.
//! - anything else → OAuth refresh token, exchanged via the mint below
//!   (cached in-process with a 300s expiry margin). Operators holding
//!   a raw access token store it `workos:`-prefixed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aisix_gateway::url_cache::cached_endpoint_url;
use aisix_gateway::{
    apply_request_headers, Bridge, BridgeContext, BridgeError, ChatChunkStream, ChatFormat,
    ChatResponse, SseDecoder, SseEvent, UpstreamHeaderContext,
};
use async_trait::async_trait;
use futures::StreamExt;
use http::{
    header::{HeaderName, HeaderValue},
    HeaderMap,
};
use reqwest::{header, Client, StatusCode};
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::bridge::{map_http_error, parse_stream_chunk, prepare_outbound_body, with_deadline};
use crate::reasoning::{is_reasoning_model, ReasoningFamily};
use crate::wire::{build_request, messages_from, DeveloperRoleMode};

/// Cline client identity version sent as `User-Agent: Cline/<ver>`,
/// `X-CLIENT-VERSION` and `X-CORE-VERSION` (the TS side sends the app
/// version; here the bridge crate's own version plays that role).
const CLINE_CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Canonical Cline chat-completions base. An explicit
/// `ProviderKey.api_base` still wins (corporate proxy convention).
pub const CLINE_DEFAULT_BASE: &str = "https://api.cline.bot/api/v1";

/// Refresh endpoint from the `clinepass`/`cline` registry entries.
const CLINE_REFRESH_URL: &str = "https://api.cline.bot/api/v1/auth/refresh";

fn strip_chat_suffix(base: &str) -> &str {
    let trimmed = base.trim().trim_end_matches('/');
    trimmed
        .strip_suffix("/chat/completions")
        .map(|s| s.trim_end_matches('/'))
        .unwrap_or(trimmed)
}

fn resolve_base(ctx: &BridgeContext) -> String {
    match ctx.provider_key.api_base.as_deref() {
        Some(b) if !b.trim().is_empty() => strip_chat_suffix(b).to_string(),
        _ => CLINE_DEFAULT_BASE.to_string(),
    }
}

/// Idempotent `workos:` prefixing (`getClineAccessToken`).
fn cline_access_token(token: &str) -> String {
    let trimmed = token.trim();
    if trimmed.starts_with("workos:") {
        trimmed.to_string()
    } else {
        format!("workos:{trimmed}")
    }
}

fn is_byok_key(credential: &str) -> bool {
    credential.starts_with("sk_") || credential.starts_with("sk-")
}

// ─── Token mint ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ClineRefreshData {
    #[serde(rename = "accessToken")]
    access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<String>,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    #[serde(rename = "expiresIn")]
    expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct ClineRefreshPayload {
    data: Option<ClineRefreshData>,
    #[serde(rename = "accessToken")]
    access_token: Option<String>,
    #[serde(rename = "refreshToken")]
    refresh_token: Option<String>,
    #[serde(rename = "expiresIn")]
    expires_in: Option<i64>,
}

/// Exchange one refresh token for an access token, byte-faithful to
/// `refreshClineToken`: JSON `{refreshToken, grantType, clientType}`,
/// `invalid_grant` / `invalid_request` surfaces as
/// `InvalidUpstreamCredentials` (re-auth, do not retry).
async fn exchange_refresh_token(
    client: &Client,
    token_url: &str,
    refresh_token: &str,
) -> Result<(String, String, Duration), BridgeError> {
    let body = serde_json::json!({
        "refreshToken": refresh_token,
        "grantType": "refresh_token",
        "clientType": "extension",
    });
    let resp = client
        .post(token_url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| BridgeError::Transport(format!("cline token refresh request failed: {e}")))?;
    let status = resp.status();
    let raw = resp.bytes().await.unwrap_or_default();
    if status != StatusCode::OK {
        let text = String::from_utf8_lossy(&raw);
        let code = extract_oauth_error_code(&text);
        if code.as_deref() == Some("invalid_grant") || code.as_deref() == Some("invalid_request") {
            return Err(BridgeError::InvalidUpstreamCredentials(format!(
                "cline refresh token rejected ({code:?}); re-authentication required"
            )));
        }
        return Err(BridgeError::upstream_status(
            status.as_u16(),
            format!("cline token refresh rejected ({status}): {text}"),
        ));
    }
    let payload: ClineRefreshPayload = serde_json::from_slice(&raw).map_err(|e| {
        BridgeError::UpstreamDecode(format!("failed to parse cline token response: {e}"))
    })?;
    let (data_access, data_refresh, data_expires_at, data_expires_in) = match payload.data {
        Some(d) => (d.access_token, d.refresh_token, d.expires_at, d.expires_in),
        None => (None, None, None, None),
    };
    let access_token = data_access.or(payload.access_token).ok_or_else(|| {
        BridgeError::UpstreamDecode("cline token response carried no accessToken".into())
    })?;
    let refresh_token = data_refresh.or(payload.refresh_token).unwrap_or_else(|| refresh_token.to_string());
    let ttl = match data_expires_in.or(payload.expires_in) {
        Some(secs) if secs > 0 => Duration::from_secs(secs as u64),
        _ => match data_expires_at.as_deref() {
            Some(iso) => expires_in_from_iso(iso),
            None => Duration::from_secs(3600),
        },
    };
    Ok((access_token, refresh_token, ttl))
}

fn extract_oauth_error_code(text: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(code) = value
            .get("error")
            .and_then(|e| e.get("code").or_else(|| e.get("error")))
            .and_then(|c| c.as_str())
        {
            return Some(code.to_string());
        }
    }
    for code in ["invalid_grant", "invalid_request"] {
        if text.contains(code) {
            return Some(code.to_string());
        }
    }
    None
}

fn expires_in_from_iso(iso: &str) -> Duration {
    let secs = chrono::DateTime::parse_from_rfc3339(iso)
        .ok()
        .map(|dt| dt.timestamp() - chrono::Utc::now().timestamp())
        .unwrap_or(3600)
        .max(1);
    Duration::from_secs(secs as u64)
}

pub struct ClinepassTokenMint {
    client: Client,
    cached: RwLock<Option<(String, String, Instant)>>,
}

impl Default for ClinepassTokenMint {
    fn default() -> Self {
        Self::new()
    }
}

impl ClinepassTokenMint {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            cached: RwLock::new(None),
        }
    }

    /// Resolve `credential` to `(authorization_value, was_byok)`.
    pub async fn get_authorization(&self, credential: &str) -> Result<(String, bool), BridgeError> {
        let credential = credential.trim();
        if credential.is_empty() {
            return Err(BridgeError::InvalidUpstreamCredentials(
                "cline provider_key.api_key is empty".into(),
            ));
        }
        if is_byok_key(credential) {
            return Ok((format!("Bearer {credential}"), true));
        }
        if credential.starts_with("workos:") {
            return Ok((format!("Bearer {credential}"), false));
        }
        {
            let guard = self.cached.read().await;
            if let Some((token, _, expiry)) = guard.as_ref() {
                if Instant::now() + Duration::from_secs(300) < *expiry {
                    return Ok((format!("Bearer {}", cline_access_token(token)), false));
                }
            }
        }
        let mut guard = self.cached.write().await;
        if let Some((token, _, expiry)) = guard.as_ref() {
            if Instant::now() + Duration::from_secs(300) < *expiry {
                return Ok((format!("Bearer {}", cline_access_token(token)), false));
            }
        }
        let (access_token, refresh_token, ttl) =
            exchange_refresh_token(&self.client, CLINE_REFRESH_URL, credential).await?;
        *guard = Some((
            access_token.clone(),
            refresh_token,
            Instant::now() + ttl,
        ));
        Ok((format!("Bearer {}", cline_access_token(&access_token)), false))
    }
}

// ─── Shared bridge core ─────────────────────────────────────────────────

fn developer_role_mode(ctx: &BridgeContext) -> DeveloperRoleMode {
    if ctx.provider_key.provider.trim().eq_ignore_ascii_case("openai") {
        DeveloperRoleMode::Preserve
    } else {
        DeveloperRoleMode::MapToSystem
    }
}

/// The `applyClineProtocolHeaders` identity set (`clineAuth.ts:72-98`).
fn cline_protocol_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    let set = |headers: &mut HeaderMap, name: &'static str, value: String| {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            headers.insert(n, v);
        }
    };
    set(&mut headers, "http-referer", "https://cline.bot".to_string());
    set(&mut headers, "x-title", "Cline".to_string());
    set(&mut headers, "user-agent", format!("Cline/{CLINE_CLIENT_VERSION}"));
    set(&mut headers, "x-is-multiroot", "false".to_string());
    set(&mut headers, "x-client-type", "omniroute".to_string());
    set(&mut headers, "x-client-version", CLINE_CLIENT_VERSION.to_string());
    set(&mut headers, "x-platform", std::env::consts::OS.to_string());
    set(&mut headers, "x-platform-version", "unknown".to_string());
    set(&mut headers, "x-core-version", CLINE_CLIENT_VERSION.to_string());
    headers
}

fn build_request_headers(
    authorization: &str,
    request_id: &str,
    hdr: &UpstreamHeaderContext<'_>,
) -> Result<HeaderMap, BridgeError> {
    let mut headers = cline_protocol_headers();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(authorization).map_err(|_| {
            BridgeError::InvalidUpstreamCredentials("cline credential is not a valid header value".into())
        })?,
    );
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(header::ACCEPT, HeaderValue::from_static("text/event-stream"));
    headers.insert(
        HeaderName::from_static("x-aisix-request-id"),
        HeaderValue::from_str(request_id)
            .map_err(|e| BridgeError::Config(format!("request_id contains invalid header chars: {e}")))?,
    );
    // Operator `default_headers` + forwarded client headers merge last
    // (skip-if-present: the Cline identity set above always wins).
    apply_request_headers(&mut headers, hdr);
    Ok(headers)
}

struct ClinepassCore {
    client: Client,
    mint: Arc<ClinepassTokenMint>,
}

impl ClinepassCore {
    fn new() -> Self {
        Self {
            client: aisix_gateway::client_builder()
                .build()
                .unwrap_or_else(|_| Client::new()),
            mint: Arc::new(ClinepassTokenMint::new()),
        }
    }

    fn client_for(&self, ctx: &BridgeContext) -> Client {
        aisix_gateway::upstream_tls::client_for_provider_key(
            &self.client,
            ctx.provider_key.upstream_connection().as_ref(),
        )
    }

    async fn chat_accumulate(
        &self,
        req: &ChatFormat,
        ctx: &BridgeContext,
    ) -> Result<ChatResponse, BridgeError> {
        let mut stream = self.chat_stream_inner(req, ctx).await?;
        let mut full_content = String::new();
        let mut full_reasoning = String::new();
        let mut final_usage = None;
        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res?;
            if let Some(content) = chunk.delta.content {
                full_content.push_str(&content);
            }
            if let Some(reasoning) = chunk.delta.reasoning_content {
                full_reasoning.push_str(&reasoning);
            }
            if chunk.usage.is_some() {
                final_usage = chunk.usage;
            }
        }
        let model = ctx
            .model
            .model_name
            .as_deref()
            .unwrap_or(&ctx.model.display_name)
            .to_string();
        let mut message = aisix_gateway::ChatMessage::assistant(full_content);
        if !full_reasoning.is_empty() {
            message.extra.insert(
                "reasoning_content".to_string(),
                serde_json::Value::String(full_reasoning),
            );
        }
        Ok(ChatResponse {
            id: ctx.request_id.clone(),
            model,
            message,
            finish_reason: aisix_gateway::FinishReason::Stop,
            usage: final_usage.unwrap_or_default(),
        })
    }

    async fn chat_stream_inner(
        &self,
        req: &ChatFormat,
        ctx: &BridgeContext,
    ) -> Result<ChatChunkStream, BridgeError> {
        // `forceStream: true` — the upstream only implements streaming,
        // so even a `stream: false` client request goes out streaming
        // and `chat()` accumulates the SSE back into JSON.
        let (authorization, _) = self.mint.get_authorization(&ctx.provider_key.api_key).await?;
        let upstream = ctx
            .model
            .model_name
            .as_deref()
            .ok_or_else(|| BridgeError::InvalidUpstreamConfig("model.model_name missing".into()))?;
        let messages = messages_from(req, developer_role_mode(ctx));
        let typed = build_request(req, upstream, &messages, true);
        let body = prepare_outbound_body(
            &typed,
            is_reasoning_model(ReasoningFamily::Openai, upstream),
            ctx.provider_key.request.as_ref(),
            ctx.provider_key.response.as_ref(),
        )?;
        let headers = build_request_headers(&authorization, &ctx.request_id, &ctx.header_ctx())?;
        let url = cached_endpoint_url(
            &ctx.provider_key_id,
            "clinepass/chat",
            &[
                ctx.provider_key.api_base.as_deref().unwrap_or(""),
                &ctx.provider_key.provider,
            ],
            || Ok(format!("{}/chat/completions", resolve_base(ctx))),
        )?;
        let client = self.client_for(ctx);
        let started = Instant::now();
        let resp = with_deadline(ctx.deadline, started, async move {
            url.post_on(&client)
                .headers(headers)
                .json(&body)
                .send()
                .await
                .map_err(aisix_gateway::send_error)
        })
        .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_http_error(status, resp).await);
        }
        let byte_stream = resp.bytes_stream();
        let stream = async_stream::try_stream! {
            let mut decoder = SseDecoder::new();
            let mut stream = Box::pin(byte_stream);
            while let Some(next) = stream.next().await {
                let chunk = next.map_err(|e| BridgeError::Transport(aisix_gateway::transport_error_message(&e)))?;
                for event in decoder.feed(chunk.as_ref()).map_err(|e| BridgeError::UpstreamDecode(e.to_string()))? {
                    match event {
                        SseEvent::Done => break,
                        SseEvent::Data(payload) => {
                            // Tolerate the legacy `{success, data}` JSON
                            // envelope: unwrap `data` and parse it as the
                            // OpenAI chunk.
                            let payload = unwrap_legacy_envelope(&payload);
                            let parsed = parse_stream_chunk(&payload, None)?;
                            yield crate::wire::stream_chunk_into_chat_chunk(parsed);
                        }
                    }
                }
            }
            if let Some(SseEvent::Data(payload)) = decoder.finish().map_err(|e| BridgeError::UpstreamDecode(e.to_string()))? {
                let payload = unwrap_legacy_envelope(&payload);
                let parsed = parse_stream_chunk(&payload, None)?;
                yield crate::wire::stream_chunk_into_chat_chunk(parsed);
            }
        };
        Ok(Box::pin(stream))
    }
}

/// Unwrap the legacy `{success, data}` JSON envelope the Cline API used
/// to wrap SSE frames in; passes ordinary OpenAI chunks through
/// untouched.
fn unwrap_legacy_envelope(payload: &str) -> String {
    if !payload.contains("\"data\"") {
        return payload.to_string();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
        return payload.to_string();
    };
    match value.get("data") {
        Some(inner) if inner.is_object() => inner.to_string(),
        _ => payload.to_string(),
    }
}

// ─── Public bridges ─────────────────────────────────────────────────────

/// `clinepass` — dual-auth (`Bearer workos:` OAuth or plain BYOK key).
pub struct ClinepassBridge {
    core: ClinepassCore,
}

/// `cline` — OAuth sibling on the same host (same chat URL, same
/// identity headers, same mint; registers under its own vendor key so
/// `provider: "cline"` model rows resolve here instead of the family
/// bridge).
pub struct ClineBridge {
    core: ClinepassCore,
}

impl ClinepassBridge {
    pub fn new() -> Self {
        Self {
            core: ClinepassCore::new(),
        }
    }
}

impl Default for ClinepassBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl ClineBridge {
    pub fn new() -> Self {
        Self {
            core: ClinepassCore::new(),
        }
    }
}

impl Default for ClineBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Bridge for ClinepassBridge {
    fn name(&self) -> &'static str {
        "clinepass"
    }

    fn wire_protocol(&self) -> &'static str {
        aisix_core::Adapter::Openai.wire_protocol()
    }

    async fn chat(&self, req: &ChatFormat, ctx: &BridgeContext) -> Result<ChatResponse, BridgeError> {
        self.core.chat_accumulate(req, ctx).await
    }

    async fn chat_stream(
        &self,
        req: &ChatFormat,
        ctx: &BridgeContext,
    ) -> Result<ChatChunkStream, BridgeError> {
        self.core.chat_stream_inner(req, ctx).await
    }
}

#[async_trait]
impl Bridge for ClineBridge {
    fn name(&self) -> &'static str {
        "cline"
    }

    fn wire_protocol(&self) -> &'static str {
        aisix_core::Adapter::Openai.wire_protocol()
    }

    async fn chat(&self, req: &ChatFormat, ctx: &BridgeContext) -> Result<ChatResponse, BridgeError> {
        self.core.chat_accumulate(req, ctx).await
    }

    async fn chat_stream(
        &self,
        req: &ChatFormat,
        ctx: &BridgeContext,
    ) -> Result<ChatChunkStream, BridgeError> {
        self.core.chat_stream_inner(req, ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_token_prefixing_is_idempotent() {
        assert_eq!(cline_access_token("abc"), "workos:abc");
        assert_eq!(cline_access_token("workos:abc"), "workos:abc");
        assert_eq!(cline_access_token("  workos:abc  "), "workos:abc");
    }

    #[test]
    fn byok_detection_matches_both_prefixes() {
        assert!(is_byok_key("sk_test123"));
        assert!(is_byok_key("sk-test123"));
        assert!(!is_byok_key("workos:abc"));
        assert!(!is_byok_key("refresh-token-value"));
    }

    #[test]
    fn legacy_envelope_unwraps_data_object() {
        let inner = r#"{"id":"c","choices":[]}"#;
        let wrapped = format!(r#"{{"success":true,"data":{inner}}}"#);
        let unwrapped: serde_json::Value =
            serde_json::from_str(&unwrap_legacy_envelope(&wrapped)).unwrap();
        let expected: serde_json::Value = serde_json::from_str(inner).unwrap();
        assert_eq!(unwrapped, expected);
        assert_eq!(unwrap_legacy_envelope(inner), inner);
    }

    #[test]
    fn oauth_error_code_extraction() {
        assert_eq!(
            extract_oauth_error_code(r#"{"error":{"code":"invalid_grant"}}"#).as_deref(),
            Some("invalid_grant")
        );
        assert_eq!(
            extract_oauth_error_code("plain invalid_request text").as_deref(),
            Some("invalid_request")
        );
        assert!(extract_oauth_error_code("nothing here").is_none());
    }

    /// Refresh posts the JSON `{refreshToken, grantType, clientType}`
    /// shape and reads the camelCase `{data: {accessToken,
    /// refreshToken, expiresAt}}` envelope.
    #[tokio::test]
    async fn refresh_posts_json_envelope_and_reads_data() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/refresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "accessToken": "a-new",
                    "refreshToken": "r-new",
                    "expiresAt": "2099-01-01T00:00:00.000Z",
                }
            })))
            .mount(&server)
            .await;
        let (access, refresh, ttl) = exchange_refresh_token(
            &Client::new(),
            &format!("{}/api/v1/auth/refresh", server.uri()),
            "rt-old",
        )
        .await
        .unwrap();
        assert_eq!(access, "a-new");
        assert_eq!(refresh, "r-new");
        assert!(ttl > Duration::from_secs(60), "ttl={ttl:?}");
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let body: serde_json::Value =
            serde_json::from_slice(&reqs[0].body).expect("refresh body is JSON");
        assert_eq!(body["refreshToken"], serde_json::json!("rt-old"));
        assert_eq!(body["grantType"], serde_json::json!("refresh_token"));
        assert_eq!(body["clientType"], serde_json::json!("extension"));
    }

    #[tokio::test]
    async fn refresh_invalid_grant_needs_reauth() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/refresh"))
            .respond_with(ResponseTemplate::new(400).set_body_string(r#"{"error":{"code":"invalid_grant"}}"#))
            .mount(&server)
            .await;
        let err = exchange_refresh_token(
            &Client::new(),
            &format!("{}/api/v1/auth/refresh", server.uri()),
            "rt-dead",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, BridgeError::InvalidUpstreamCredentials(_)),
            "unexpected: {err:?}"
        );
    }
}
