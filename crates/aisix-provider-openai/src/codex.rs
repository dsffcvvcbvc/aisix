//! Codex (`codex`) bridge — ChatGPT backend Codex Responses API.
//!
//! Byte-parity sources in `open-sse` (read-only reference):
//! - `config/providers/registry/codex/index.ts`: `POST
//!   https://chatgpt.com/backend-api/codex/responses`, format
//!   `openai-responses`, `forceStream: true` (upstream streams even
//!   when the client asked `stream: false`; the bridge always streams
//!   upstream and accumulates for non-streaming callers).
//! - `config/codexClient.ts:99-105` (`getCodexDefaultHeaders`):
//!   `Version: <ver>`, `Openai-Beta: responses_websockets=2026-02-06`,
//!   `User-Agent: codex-cli/<ver> (Windows 10.0.26200; x64)`.
//! - `services/tokenRefresh/providers/codex.ts:23-35`: refresh posts
//!   form `{grant_type, refresh_token, client_id}` to
//!   `https://auth.openai.com/oauth/token` and INTENTIONALLY omits
//!   `scope` (RFC 6749 §6 — including it re-scopes on Auth0 and can
//!   invalidate sibling refresh-token families). Rotating one-time
//!   refresh tokens: `refresh_token_reused` / `invalid_grant` /
//!   `token_expired` / `invalid_token` (plus any 401) are
//!   unrecoverable → re-authenticate.
//!
//! Deliberate divergences:
//! - The TS executor layers Codex instructions, verbosity, thinking
//!   budgets, tool schemas and app-server transports. Here the
//!   Responses body is the chat projection (shared with Grok-CLI) plus
//!   whatever the client/operator passes via `extra`; no default
//!   instructions are injected.
//! - Refresh is reactive (on 401, single retry) rather than
//!   expiry-proactive with account-store persistence — the gateway is
//!   stateless. `CODEX_OAUTH_CLIENT_ID` env carries the public client
//!   id (same env name the TS registry reads).

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
use reqwest::{header, Client};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::bridge::{map_http_error, with_deadline};
use crate::responses_wire::{build_responses_body, stream_event_into_chat_chunk};

/// `DEFAULT_CODEX_CLIENT_VERSION` (`src/shared/constants/codexClient`).
pub const CODEX_CLIENT_VERSION: &str = "0.156.1";
/// Beta gate from `getCodexDefaultHeaders` (`codexClient.ts:102`).
const CODEX_OPENAI_BETA: &str = "responses_websockets=2026-02-06";

/// Canonical Codex responses URL (registry `baseUrl`). An explicit
/// `ProviderKey.api_base` still wins (corporate proxy convention).
pub const CODEX_DEFAULT_BASE: &str = "https://chatgpt.com/backend-api/codex";

/// OAuth token endpoint (registry `oauth.tokenUrl`).
const CODEX_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";

fn codex_user_agent() -> String {
    format!("codex-cli/{CODEX_CLIENT_VERSION} (Windows 10.0.26200; x64)")
}

/// `getCodexDefaultHeaders` (`codexClient.ts:99-105`) + Bearer auth.
fn codex_headers(token: &str, sse: bool) -> Result<HeaderMap, BridgeError> {
    let mut headers = HeaderMap::new();
    let pairs: &[(&str, String)] = &[
        ("version", CODEX_CLIENT_VERSION.to_string()),
        ("openai-beta", CODEX_OPENAI_BETA.to_string()),
        ("user-agent", codex_user_agent()),
        (
            "accept",
            (if sse { "text/event-stream" } else { "application/json" }).to_string(),
        ),
        ("content-type", "application/json".to_string()),
        ("authorization", format!("Bearer {token}")),
    ];
    for (name, value) in pairs {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| BridgeError::Config(format!("bad codex header name: {name}")))?,
            HeaderValue::from_str(value).map_err(|_| {
                BridgeError::InvalidUpstreamCredentials(
                    "codex credential is not a valid header value".into(),
                )
            })?,
        );
    }
    Ok(headers)
}

// ─── Refresh (`tokenRefresh/providers/codex.ts`) ────────────────────────

/// Pure refresh call so tests can drive it against a mock server. The
/// body intentionally omits `scope` (see module docs).
async fn exchange_refresh_token(
    client: &Client,
    token_url: &str,
    refresh_token: &str,
    client_id: &str,
) -> Result<(String, String, Option<u64>), BridgeError> {
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    let resp = client
        .post(token_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .form(&params)
        .send()
        .await
        .map_err(|e| BridgeError::Transport(format!("codex token refresh request failed: {e}")))?;
    let status = resp.status();
    let raw = resp.bytes().await.unwrap_or_default();
    if !status.is_success() {
        let text = String::from_utf8_lossy(&raw);
        let code = extract_codex_error_code(&text);
        if matches!(
            code.as_deref(),
            Some("refresh_token_reused" | "invalid_grant" | "token_expired" | "invalid_token")
        ) || status == reqwest::StatusCode::UNAUTHORIZED
        {
            return Err(BridgeError::InvalidUpstreamCredentials(format!(
                "codex refresh token unusable ({}); re-authentication required",
                code.as_deref().unwrap_or("unauthorized")
            )));
        }
        return Err(BridgeError::upstream_status(
            status.as_u16(),
            format!("codex token refresh rejected ({status}): {text}"),
        ));
    }
    let tokens: Value = serde_json::from_slice(&raw).map_err(|e| {
        BridgeError::UpstreamDecode(format!("failed to parse codex token response: {e}"))
    })?;
    let access = tokens.get("access_token").and_then(Value::as_str).unwrap_or("");
    if access.is_empty() {
        return Err(BridgeError::UpstreamDecode(
            "codex token response carried no access_token".into(),
        ));
    }
    Ok((
        access.to_string(),
        tokens
            .get("refresh_token")
            .and_then(Value::as_str)
            .unwrap_or(refresh_token)
            .to_string(),
        tokens.get("expires_in").and_then(Value::as_u64),
    ))
}

fn extract_codex_error_code(text: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let error = value.get("error")?;
    if let Some(code) = error.get("code").and_then(Value::as_str) {
        return Some(code.to_string());
    }
    if let Some(s) = error.as_str() {
        return Some(s.to_string());
    }
    None
}

struct CodexTokenMint {
    client: Client,
    cached: RwLock<Option<(String, String, Instant)>>,
}

impl CodexTokenMint {
    async fn refresh(&self, refresh_token: &str) -> Result<(String, String), BridgeError> {
        {
            let guard = self.cached.read().await;
            if let Some((token, _, expiry)) = guard.as_ref() {
                if Instant::now() + Duration::from_secs(300) < *expiry {
                    return Ok((token.clone(), refresh_token.to_string()));
                }
            }
        }
        let client_id = std::env::var("CODEX_OAUTH_CLIENT_ID")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                BridgeError::InvalidUpstreamCredentials(
                    "codex OAuth client id is not configured (CODEX_OAUTH_CLIENT_ID); re-authenticate the account".into(),
                )
            })?;
        let mut guard = self.cached.write().await;
        if let Some((token, _, expiry)) = guard.as_ref() {
            if Instant::now() + Duration::from_secs(300) < *expiry {
                return Ok((token.clone(), refresh_token.to_string()));
            }
        }
        let (access, refresh, expires_in) =
            exchange_refresh_token(&self.client, CODEX_TOKEN_URL, refresh_token, client_id.trim()).await?;
        let ttl = Duration::from_secs(expires_in.unwrap_or(3600).max(1));
        *guard = Some((access.clone(), refresh.clone(), Instant::now() + ttl));
        Ok((access, refresh))
    }
}

// ─── Bridge ─────────────────────────────────────────────────────────────

pub struct CodexBridge {
    client: Client,
    mint: CodexTokenMint,
}

impl CodexBridge {
    pub fn new() -> Self {
        Self {
            client: aisix_gateway::client_builder()
                .build()
                .unwrap_or_else(|_| Client::new()),
            mint: CodexTokenMint {
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

    fn resolve_base(ctx: &BridgeContext) -> String {
        match ctx.provider_key.api_base.as_deref() {
            Some(b) if !b.trim().is_empty() => b.trim().trim_end_matches('/').to_string(),
            _ => CODEX_DEFAULT_BASE.to_string(),
        }
    }

    fn credential(ctx: &BridgeContext) -> Result<String, BridgeError> {
        let k = ctx.provider_key.api_key.trim().to_string();
        if k.is_empty() {
            return Err(BridgeError::InvalidUpstreamCredentials(
                "codex provider_key.api_key is empty".into(),
            ));
        }
        if HeaderValue::from_str(&k).is_err() {
            return Err(BridgeError::InvalidUpstreamCredentials(
                "codex provider_key.api_key contains invalid header characters".into(),
            ));
        }
        Ok(k)
    }

    fn build_headers(
        token: &str,
        request_id: &str,
        sse: bool,
        hdr: &UpstreamHeaderContext<'_>,
    ) -> Result<HeaderMap, BridgeError> {
        let mut headers = codex_headers(token, sse)?;
        headers.insert(
            HeaderName::from_static("x-aisix-request-id"),
            HeaderValue::from_str(request_id)
                .map_err(|e| BridgeError::Config(format!("request_id contains invalid header chars: {e}")))?,
        );
        apply_request_headers(&mut headers, hdr);
        Ok(headers)
    }

    async fn post_responses(
        &self,
        url: &aisix_gateway::url_cache::EndpointUrl,
        headers: HeaderMap,
        body: &Value,
        client: &Client,
        credential: &str,
    ) -> Result<reqwest::Response, BridgeError> {
        let mut headers = headers;
        for refreshed in [false, true] {
            let resp = url
                .clone()
                .post_on(client)
                .json(body)
                .send()
                .await
                .map_err(aisix_gateway::send_error)?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed {
                if let Ok((access, _)) = self.mint.refresh(credential).await {
                    let auth = HeaderValue::from_str(&format!("Bearer {access}")).map_err(|_| {
                        BridgeError::InvalidUpstreamCredentials(
                            "refreshed codex token is not a valid header value".into(),
                        )
                    })?;
                    headers.insert(header::AUTHORIZATION, auth);
                    continue;
                }
            }
            return Ok(resp);
        }
        unreachable!("the loop above always returns on its first two iterations");
    }
}

impl Default for CodexBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Bridge for CodexBridge {
    fn name(&self) -> &'static str {
        "codex"
    }

    fn wire_protocol(&self) -> &'static str {
        // Same Responses-is-OpenAI-family reasoning as Grok-CLI: the
        // closed `Adapter` enum has no responses variant.
        aisix_core::Adapter::Openai.wire_protocol()
    }

    async fn chat(&self, req: &ChatFormat, ctx: &BridgeContext) -> Result<ChatResponse, BridgeError> {
        // `forceStream: true` — upstream streams even for `stream:
        // false` clients; accumulate the SSE back into JSON.
        let mut stream = self.chat_stream(req, ctx).await?;
        let mut full_content = String::new();
        let mut full_reasoning = String::new();
        let mut tool_calls: Vec<Value> = Vec::new();
        let mut final_usage = None;
        while let Some(chunk_res) = stream.next().await {
            let chunk = chunk_res?;
            if let Some(content) = chunk.delta.content {
                full_content.push_str(&content);
            }
            if let Some(reasoning) = chunk.delta.reasoning_content {
                full_reasoning.push_str(&reasoning);
            }
            if let Some(calls) = chunk.delta.tool_calls {
                tool_calls.extend(calls);
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
        if !tool_calls.is_empty() {
            message.extra.insert("tool_calls".to_string(), Value::Array(tool_calls));
        }
        if !full_reasoning.is_empty() {
            message.extra.insert("reasoning_content".to_string(), Value::String(full_reasoning));
        }
        Ok(ChatResponse {
            id: ctx.request_id.clone(),
            model,
            message,
            finish_reason: aisix_gateway::FinishReason::Stop,
            usage: final_usage.unwrap_or_default(),
        })
    }

    async fn chat_stream(
        &self,
        req: &ChatFormat,
        ctx: &BridgeContext,
    ) -> Result<ChatChunkStream, BridgeError> {
        let credential = Self::credential(ctx)?;
        let upstream_model = ctx
            .model
            .model_name
            .as_deref()
            .unwrap_or(&ctx.model.display_name);
        // No default effort: the TS side derives it from the model
        // alias suffix, which the gateway does not model — the caller
        // (or operator `extra`) decides.
        let body = build_responses_body(req, upstream_model, true, None);
        let headers = Self::build_headers(&credential, &ctx.request_id, true, &ctx.header_ctx())?;
        let url = cached_endpoint_url(
            &ctx.provider_key_id,
            "codex/responses",
            &[
                ctx.provider_key.api_base.as_deref().unwrap_or(""),
                &ctx.provider_key.provider,
            ],
            || Ok(format!("{}/responses", Self::resolve_base(ctx))),
        )?;
        let client = self.client_for(ctx);
        let started = Instant::now();
        let credential_for_retry = credential.clone();
        let this = &self;
        let resp = with_deadline(ctx.deadline, started, async move {
            this.post_responses(&url, headers, &body, &client, &credential_for_retry).await
        })
        .await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(map_http_error(status, resp).await);
        }
        let model_owned = upstream_model.to_string();
        let request_id = ctx.request_id.clone();
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
                            if let Some(chunk) = stream_event_into_chat_chunk(&payload, &model_owned, &request_id) {
                                yield chunk;
                            }
                        }
                    }
                }
            }
            if let Some(SseEvent::Data(payload)) = decoder.finish().map_err(|e| BridgeError::UpstreamDecode(e.to_string()))? {
                if let Some(chunk) = stream_event_into_chat_chunk(&payload, &model_owned, &request_id) {
                    yield chunk;
                }
            }
        };
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_headers_match_codex_client() {
        let headers = codex_headers("tok", true).unwrap();
        assert_eq!(headers["version"], CODEX_CLIENT_VERSION);
        assert_eq!(headers["openai-beta"], CODEX_OPENAI_BETA);
        assert_eq!(
            headers["user-agent"],
            format!("codex-cli/{CODEX_CLIENT_VERSION} (Windows 10.0.26200; x64)").as_str()
        );
        assert_eq!(headers["authorization"], "Bearer tok");
    }

    #[test]
    fn codex_error_code_extraction() {
        assert_eq!(
            extract_codex_error_code(r#"{"error":{"code":"refresh_token_reused"}}"#).as_deref(),
            Some("refresh_token_reused")
        );
        assert_eq!(
            extract_codex_error_code(r#"{"error":"invalid_grant"}"#).as_deref(),
            Some("invalid_grant")
        );
        assert!(extract_codex_error_code("not json").is_none());
    }

    /// The refresh POST must carry exactly
    /// `{grant_type, refresh_token, client_id}` — a `scope` member
    /// would re-scope on Auth0 and invalidate sibling families.
    #[tokio::test]
    async fn refresh_form_omits_scope() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "a-new",
                "refresh_token": "r-new",
                "expires_in": 3600,
            })))
            .mount(&server)
            .await;
        let (access, refresh, _) = exchange_refresh_token(
            &Client::new(),
            &format!("{}/oauth/token", server.uri()),
            "rt-old",
            "cid",
        )
        .await
        .unwrap();
        assert_eq!(access, "a-new");
        assert_eq!(refresh, "r-new");
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let body = String::from_utf8_lossy(&reqs[0].body).into_owned();
        assert!(body.contains("grant_type=refresh_token"), "body={body}");
        assert!(body.contains("refresh_token=rt-old"), "body={body}");
        assert!(body.contains("client_id=cid"), "body={body}");
        assert!(!body.contains("scope"), "scope must be omitted: {body}");
    }

    #[tokio::test]
    async fn refresh_reused_token_is_unrecoverable() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {"code": "refresh_token_reused"},
            })))
            .mount(&server)
            .await;
        let err = exchange_refresh_token(
            &Client::new(),
            &format!("{}/oauth/token", server.uri()),
            "rt-used",
            "cid",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, BridgeError::InvalidUpstreamCredentials(_)),
            "unexpected: {err:?}"
        );
    }
}
