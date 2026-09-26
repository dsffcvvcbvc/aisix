//! Qoder (`qoder`) bridge — DashScope OpenAI-compatible endpoint.
//!
//! Byte-parity sources in `open-sse` (read-only reference):
//! - `config/providerHeaderProfiles.ts:212-223`
//!   (`getQoderDashscopeCompatHeaders`): `x-dashscope-authtype:
//!   qwen-oauth`, `x-dashscope-cachecontrol: enable`, `user-agent` +
//!   `x-dashscope-useragent: QwenCode/<ver> (<platform>; <arch>)`,
//!   `x-stainless-arch/lang/os`.
//! - `executors/qoder.ts:66-167` (`unwrapQoderEnvelope`): Qoder wraps
//!   upstream errors inside an HTTP 200 SSE envelope
//!   (`{statusCodeValue, body}`); the first event is peeked and a
//!   non-200 status becomes a proper HTTP error so fallback logic can
//!   trigger.
//! - `executors/qoder.ts:231-249`: `qwen3.5-plus` / `qwen3.6-plus` map
//!   to `coder-model`, `vision-model` maps to `qwen3-vl-plus`, empty
//!   model defaults to `qwen3.8-max-preview`.
//! - `services/tokenRefresh/providers/qoder.ts:11-37`: Basic refresh —
//!   `POST` form `{grant_type, refresh_token, client_id, client_secret}`
//!   with `Authorization: Basic base64(id:secret)`; client id/secret
//!   come from `QODER_OAUTH_CLIENT_ID` / `QODER_OAUTH_CLIENT_SECRET`
//!   (mirrored here as process env vars; when unset the bridge reports
//!   "browser OAuth is not configured", exactly like the TS warn).
//!
//! Deliberate divergences:
//! - `pt-…` PAT credentials drive the local `qodercli` binary in TS
//!   (WASM-signed Cosy auth, no HTTP equivalent). The gateway has no
//!   sidecar binary, so PATs fail loudly with `InvalidUpstreamConfig`
//!   instead of silently misrouting.

use std::time::{Duration, Instant};

use aisix_gateway::url_cache::cached_endpoint_url;
use aisix_gateway::{
    apply_request_headers, scrub_upstream_headers, Bridge, BridgeContext, BridgeError,
    ChatChunkStream, ChatFormat, ChatResponse, SseDecoder, SseEvent, UpstreamHeaderContext,
};
use async_trait::async_trait;
use base64::Engine as _;
use futures::StreamExt;
use http::{
    header::{HeaderName, HeaderValue},
    HeaderMap,
};
use reqwest::{header, Client};
use tokio::sync::RwLock;

use crate::bridge::{map_http_error, parse_stream_chunk, prepare_outbound_body, with_deadline};
use crate::reasoning::{is_reasoning_model, ReasoningFamily};
use crate::wire::{
    build_request, messages_from, response_into_chat_response, stream_chunk_into_chat_chunk,
    DeveloperRoleMode,
};

/// Qwen Code CLI version pinned in `providerHeaderProfiles.ts`.
const QWEN_CLI_VERSION: &str = "0.19.3";

/// DashScope OpenAI-compatible chat endpoint (`executors/qoder.ts`).
pub const QODER_DEFAULT_BASE: &str = "https://dashscope.aliyuncs.com/compatible-mode/v1";

fn qwen_user_agent() -> String {
    format!(
        "QwenCode/{QWEN_CLI_VERSION} ({}; {})",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

fn stainless_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "MacOS",
        "windows" => "Windows",
        "linux" => "Linux",
        "android" => "Android",
        _ => "Linux",
    }
}

fn stainless_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "x32",
        "arm" => "arm",
        _ => "x64",
    }
}

/// `getQoderDashscopeCompatHeaders` + `Authorization: Bearer`.
fn dashscope_headers(token: &str) -> Result<HeaderMap, BridgeError> {
    let mut headers = HeaderMap::new();
    let ua = qwen_user_agent();
    let pairs: Vec<(&str, String)> = vec![
        ("authorization", format!("Bearer {token}")),
        ("content-type", "application/json".to_string()),
        ("x-dashscope-authtype", "qwen-oauth".to_string()),
        ("x-dashscope-cachecontrol", "enable".to_string()),
        ("x-dashscope-useragent", ua.clone()),
        ("x-stainless-arch", stainless_arch().to_string()),
        ("x-stainless-lang", "js".to_string()),
        ("x-stainless-os", stainless_os().to_string()),
    ];
    for (name, value) in &pairs {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| BridgeError::Config(format!("bad qoder header name: {name}")))?,
            HeaderValue::from_str(&value).map_err(|_| {
                BridgeError::InvalidUpstreamCredentials(
                    "qoder credential is not a valid header value".into(),
                )
            })?,
        );
    }
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_str(&ua)
            .map_err(|e| BridgeError::Config(format!("qoder UA invalid: {e}")))?,
    );
    Ok(headers)
}

/// Model mapping from `QoderExecutor::execute` (`qoder.ts:242-247`).
fn map_model(model: &str) -> &str {
    match model {
        "qwen3.5-plus" | "qwen3.6-plus" => "coder-model",
        "vision-model" => "qwen3-vl-plus",
        "" => "qwen3.8-max-preview",
        other => other,
    }
}

fn resolve_base(ctx: &BridgeContext) -> String {
    match ctx.provider_key.api_base.as_deref() {
        Some(b) if !b.trim().is_empty() => {
            let trimmed = b.trim().trim_end_matches('/');
            trimmed
                .strip_suffix("/chat/completions")
                .map(|s| s.trim_end_matches('/').to_string())
                .unwrap_or_else(|| trimmed.to_string())
        }
        _ => QODER_DEFAULT_BASE.to_string(),
    }
}

fn api_key(ctx: &BridgeContext) -> Result<String, BridgeError> {
    let k = ctx.provider_key.api_key.trim().to_string();
    if k.is_empty() {
        return Err(BridgeError::InvalidUpstreamCredentials(
            "qoder provider_key.api_key is empty".into(),
        ));
    }
    if k.starts_with("pt-") {
        return Err(BridgeError::InvalidUpstreamConfig(
            "qoder PAT (pt-…) credentials require the local qodercli binary, which the gateway does not ship; use an OAuth or DashScope key instead".into(),
        ));
    }
    if HeaderValue::from_str(&k).is_err() {
        return Err(BridgeError::InvalidUpstreamCredentials(
            "qoder provider_key.api_key contains invalid header characters".into(),
        ));
    }
    Ok(k)
}

// ─── Basic refresh (`tokenRefresh/providers/qoder.ts`) ──────────────────

/// Pure refresh call so tests can drive it against a mock server.
async fn exchange_refresh_token(
    client: &Client,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<(String, String, Option<u64>), BridgeError> {
    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{client_secret}"));
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];
    let resp = client
        .post(token_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .header(header::AUTHORIZATION, format!("Basic {basic}"))
        .form(&params)
        .send()
        .await
        .map_err(|e| BridgeError::Transport(format!("qoder token refresh request failed: {e}")))?;
    let status = resp.status();
    let raw = resp.bytes().await.unwrap_or_default();
    if !status.is_success() {
        let text = String::from_utf8_lossy(&raw);
        let code = extract_qoder_error_code(&text);
        if matches!(code.as_deref(), Some("invalid_grant" | "invalid_client"))
            || status == reqwest::StatusCode::UNAUTHORIZED
        {
            return Err(BridgeError::InvalidUpstreamCredentials(format!(
                "qoder refresh token rejected ({}); re-authentication required",
                code.as_deref().unwrap_or("unauthorized")
            )));
        }
        return Err(BridgeError::upstream_status(
            status.as_u16(),
            format!("qoder token refresh rejected ({status}): {text}"),
        ));
    }
    let tokens: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| {
        BridgeError::UpstreamDecode(format!("failed to parse qoder token response: {e}"))
    })?;
    let access = tokens
        .get("access_token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if access.is_empty() {
        return Err(BridgeError::UpstreamDecode(
            "qoder token response carried no access_token".into(),
        ));
    }
    let refresh = tokens
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .unwrap_or(refresh_token)
        .to_string();
    let expires_in = tokens.get("expires_in").and_then(|v| v.as_u64());
    Ok((access, refresh, expires_in))
}

struct QoderTokenMint {
    client: Client,
    cached: RwLock<Option<(String, String, Instant)>>,
}

fn extract_qoder_error_code(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let error = value.get("error")?;
    if let Some(code) = error.get("code").and_then(|c| c.as_str()) {
        return Some(code.to_string());
    }
    if let Some(code) = error.get("error").and_then(|c| c.as_str()) {
        return Some(code.to_string());
    }
    if let Some(s) = error.as_str() {
        return Some(s.to_string());
    }
    None
}

impl QoderTokenMint {
    fn oauth_env() -> Option<(String, String, String)> {
        let id = std::env::var("QODER_OAUTH_CLIENT_ID")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let secret = std::env::var("QODER_OAUTH_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        let url = std::env::var("QODER_OAUTH_TOKEN_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())?;
        Some((id, secret, url))
    }

    /// Reactive refresh on a 401: exchanges `refresh_token` (the stored
    /// credential) via Basic auth. Returns `Ok(None)` when browser OAuth is
    /// not configured in this environment (TS returns null there);
    /// terminal upstream rejections surface as
    /// `InvalidUpstreamCredentials` instead of being swallowed.
    async fn refresh_on_401(
        &self,
        refresh_token: &str,
    ) -> Result<Option<(String, String)>, BridgeError> {
        {
            let guard = self.cached.read().await;
            if let Some((token, _, expiry)) = guard.as_ref() {
                if Instant::now() + Duration::from_secs(300) < *expiry {
                    return Ok(Some((token.clone(), refresh_token.to_string())));
                }
            }
        }
        let Some((id, secret, url)) = Self::oauth_env() else {
            return Ok(None);
        };
        // No guard held across the network round-trip; re-acquire +
        // re-check before inserting.
        let (access, refresh, expires_in) =
            exchange_refresh_token(&self.client, &url, &id, &secret, refresh_token).await?;
        let ttl = Duration::from_secs(expires_in.unwrap_or(3600).max(1));
        let mut guard = self.cached.write().await;
        if let Some((token, _, expiry)) = guard.as_ref() {
            if Instant::now() + Duration::from_secs(300) < *expiry {
                return Ok(Some((token.clone(), refresh_token.to_string())));
            }
        }
        *guard = Some((access.clone(), refresh.clone(), Instant::now() + ttl));
        Ok(Some((access, refresh)))
    }
}

// ─── Bridge ─────────────────────────────────────────────────────────────

pub struct QoderBridge {
    client: Client,
    mint: QoderTokenMint,
}

impl QoderBridge {
    pub fn new() -> Self {
        Self {
            client: aisix_gateway::client_builder()
                .build()
                .unwrap_or_else(|_| Client::new()),
            mint: QoderTokenMint {
                client: Client::builder()
                    .timeout(Duration::from_secs(30))
                    .build()
                    .unwrap_or_else(|_| Client::new()),
                cached: RwLock::new(None),
            },
        }
    }

    fn client_for(&self, ctx: &BridgeContext) -> Client {
        aisix_gateway::upstream_tls::client_for_provider_key(
            &self.client,
            ctx.provider_key.upstream_connection().as_ref(),
        )
    }

    fn build_headers(
        &self,
        token: &str,
        request_id: &str,
        sse: bool,
        hdr: &UpstreamHeaderContext<'_>,
    ) -> Result<HeaderMap, BridgeError> {
        let mut headers = dashscope_headers(token)?;
        let rid = HeaderValue::from_str(request_id).map_err(|e| {
            BridgeError::Config(format!("request_id contains invalid header chars: {e}"))
        })?;
        headers.insert(HeaderName::from_static("x-aisix-request-id"), rid);
        if sse {
            headers.insert(
                header::ACCEPT,
                HeaderValue::from_static("text/event-stream"),
            );
        }
        apply_request_headers(&mut headers, hdr);
        scrub_upstream_headers(&mut headers);
        Ok(headers)
    }

    async fn post_chat(
        &self,
        url: &aisix_gateway::url_cache::EndpointUrl,
        headers: HeaderMap,
        body: &serde_json::Value,
        client: &Client,
        credential: &str,
    ) -> Result<reqwest::Response, BridgeError> {
        let mut headers = headers;
        for refreshed in [false, true] {
            let resp = url
                .clone()
                .post_on(client)
                .headers(headers.clone())
                .json(body)
                .send()
                .await
                .map_err(aisix_gateway::send_error)?;
            // Reactive Basic refresh on 401 (single retry).
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed {
                match self.mint.refresh_on_401(credential).await {
                    Ok(Some((access, _))) => {
                        let auth =
                            HeaderValue::from_str(&format!("Bearer {access}")).map_err(|_| {
                                BridgeError::InvalidUpstreamCredentials(
                                    "refreshed qoder token is not a valid header value".into(),
                                )
                            })?;
                        headers.insert(header::AUTHORIZATION, auth);
                        continue;
                    }
                    // Terminal credential failure: surface re-auth
                    // instead of replaying the stale 401 body.
                    Err(e @ BridgeError::InvalidUpstreamCredentials(_)) => return Err(e),
                    Ok(None) | Err(_) => {}
                }
            }
            return Ok(resp);
        }
        Err(BridgeError::Transport("qoder retry loop exhausted".into()))
    }
}

impl Default for QoderBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect the `{statusCodeValue, body}` error envelope
/// (`unwrapQoderEnvelope`, `qoder.ts:111-138`). Returns the upstream
/// status + message when the frame is an error envelope, `None` for
/// ordinary OpenAI chunks.
fn qoder_envelope_error(payload: &str) -> Option<BridgeError> {
    let envelope: serde_json::Value =
        serde_json::from_str(payload.trim_start_matches("data:").trim()).ok()?;
    let status_val = envelope.get("statusCodeValue").and_then(|v| v.as_u64())? as u16;
    if status_val == 200 {
        return None;
    }
    let status = if status_val >= 400 { status_val } else { 502 };
    let msg = match envelope.get("body") {
        Some(serde_json::Value::String(s)) => {
            let mut short = s.chars().take(200).collect::<String>();
            if s.chars().count() > 200 {
                short.push('…');
            }
            short
        }
        _ => format!("upstream status {status_val}"),
    };
    Some(BridgeError::upstream_status(
        status,
        format!("[qoder error {status}: {msg}]"),
    ))
}

#[async_trait]
impl Bridge for QoderBridge {
    fn name(&self) -> &'static str {
        "qoder"
    }

    fn wire_protocol(&self) -> &'static str {
        aisix_core::Adapter::Openai.wire_protocol()
    }

    async fn chat(
        &self,
        req: &ChatFormat,
        ctx: &BridgeContext,
    ) -> Result<ChatResponse, BridgeError> {
        let credential = api_key(ctx)?;
        let model_name =
            ctx.model.model_name.as_deref().ok_or_else(|| {
                BridgeError::InvalidUpstreamConfig("model.model_name missing".into())
            })?;
        let upstream = map_model(model_name).to_string();
        let messages = messages_from(req, DeveloperRoleMode::MapToSystem);
        let typed = build_request(req, &upstream, &messages, false);
        let body = prepare_outbound_body(
            &typed,
            is_reasoning_model(ReasoningFamily::Openai, &upstream),
            ctx.provider_key.request.as_ref(),
            ctx.provider_key.response.as_ref(),
        )?;
        let headers = self.build_headers(&credential, &ctx.request_id, false, &ctx.header_ctx())?;
        let url = cached_endpoint_url(
            &ctx.provider_key_id,
            "qoder/chat",
            &[
                ctx.provider_key.api_base.as_deref().unwrap_or(""),
                &ctx.provider_key.provider,
            ],
            || Ok(format!("{}/chat/completions", resolve_base(ctx))),
        )?;
        let client = self.client_for(ctx);
        let started = Instant::now();
        let credential_for_retry = credential.clone();
        let this = &self;
        let resp = with_deadline(ctx.deadline, started, async move {
            this.post_chat(&url, headers, &body, &client, &credential_for_retry)
                .await
        })
        .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_http_error(status, resp).await);
        }
        let parsed: crate::wire::OpenAiResponse = resp
            .json()
            .await
            .map_err(|e| BridgeError::UpstreamDecode(e.to_string()))?;
        Ok(response_into_chat_response(parsed))
    }

    async fn chat_stream(
        &self,
        req: &ChatFormat,
        ctx: &BridgeContext,
    ) -> Result<ChatChunkStream, BridgeError> {
        let credential = api_key(ctx)?;
        let model_name =
            ctx.model.model_name.as_deref().ok_or_else(|| {
                BridgeError::InvalidUpstreamConfig("model.model_name missing".into())
            })?;
        let upstream = map_model(model_name).to_string();
        let messages = messages_from(req, DeveloperRoleMode::MapToSystem);
        let typed = build_request(req, &upstream, &messages, true);
        let body = prepare_outbound_body(
            &typed,
            is_reasoning_model(ReasoningFamily::Openai, &upstream),
            ctx.provider_key.request.as_ref(),
            ctx.provider_key.response.as_ref(),
        )?;
        let headers = self.build_headers(&credential, &ctx.request_id, true, &ctx.header_ctx())?;
        let url = cached_endpoint_url(
            &ctx.provider_key_id,
            "qoder/chat",
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
                            if let Some(err) = qoder_envelope_error(&payload) {
                                Err(err)?;
                            }
                            let parsed = parse_stream_chunk(&payload, None)?;
                            yield stream_chunk_into_chat_chunk(parsed);
                        }
                    }
                }
            }
            if let Some(SseEvent::Data(payload)) = decoder.finish().map_err(|e| BridgeError::UpstreamDecode(e.to_string()))? {
                if let Some(err) = qoder_envelope_error(&payload) {
                    Err(err)?;
                }
                let parsed = parse_stream_chunk(&payload, None)?;
                yield stream_chunk_into_chat_chunk(parsed);
            }
        };
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_mapping_matches_executor() {
        assert_eq!(map_model("qwen3.5-plus"), "coder-model");
        assert_eq!(map_model("qwen3.6-plus"), "coder-model");
        assert_eq!(map_model("vision-model"), "qwen3-vl-plus");
        assert_eq!(map_model(""), "qwen3.8-max-preview");
        assert_eq!(map_model("qwen3.8-max-preview"), "qwen3.8-max-preview");
    }

    #[test]
    fn envelope_error_detects_non_200_status() {
        let err = qoder_envelope_error(r#"{"statusCodeValue":401,"body":"bad key"}"#)
            .expect("must detect");
        match err {
            BridgeError::UpstreamStatus {
                status, message, ..
            } => {
                assert_eq!(status, 401);
                assert!(message.contains("bad key"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(qoder_envelope_error(r#"{"statusCodeValue":200,"body":"x"}"#).is_none());
        assert!(qoder_envelope_error(r#"{"id":"chatcmpl-1","choices":[]}"#).is_none());
    }

    #[test]
    fn dashscope_headers_carry_qwen_oauth_identity() {
        let headers = dashscope_headers("tok").unwrap();
        assert_eq!(headers["x-dashscope-authtype"], "qwen-oauth");
        assert_eq!(headers["x-dashscope-cachecontrol"], "enable");
        let ua = headers[header::USER_AGENT].to_str().unwrap().to_string();
        assert!(ua.starts_with("QwenCode/0.19.3 ("), "ua={ua}");
        assert_eq!(headers["x-dashscope-useragent"], ua.as_str());
        assert_eq!(headers["x-stainless-lang"], "js");
    }

    /// Basic refresh sends the `Basic base64(id:secret)` credential and
    /// the `{grant_type, refresh_token, client_id, client_secret}` form.
    #[tokio::test]
    async fn basic_refresh_sends_basic_auth_and_form() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(header("authorization", "Basic aWQ6c2VjcmV0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "a-new",
                "expires_in": 7200,
            })))
            .mount(&server)
            .await;
        let (access, refresh, expires) = exchange_refresh_token(
            &Client::new(),
            &format!("{}/oauth/token", server.uri()),
            "id",
            "secret",
            "rt-old",
        )
        .await
        .unwrap();
        assert_eq!(access, "a-new");
        // No rotated refresh token in the response → keep the old one.
        assert_eq!(refresh, "rt-old");
        assert_eq!(expires, Some(7200));
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1, "Basic auth mismatch — request did not match");
        let body = String::from_utf8_lossy(&reqs[0].body).into_owned();
        assert!(body.contains("grant_type=refresh_token"), "body={body}");
        assert!(body.contains("refresh_token=rt-old"), "body={body}");
    }
}
