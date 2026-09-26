//! Grok-CLI (`grok-cli`) bridge — Grok Build chat proxy.
//!
//! Byte-parity sources in `open-sse` (read-only reference):
//! - `config/grokBuild.ts`: `POST
//!   https://cli-chat-proxy.grok.com/v1/responses`
//!   (`GROK_BUILD_RESPONSES_URL`), client `1.0.41`
//!   (`GROK_BUILD_DEFAULT_CLIENT_VERSION`), identifier `grok-shell`,
//!   `X-XAI-Token-Auth: xai-grok-cli`, `x-authenticateresponse:
//!   authenticate-response`, `include: ["reasoning.encrypted_content"]`,
//!   token endpoint `https://auth.x.ai/oauth2/token`.
//! - `executors/grok-cli.ts:275-313` (`refreshCredentials`): form
//!   `{grant_type, client_id, refresh_token}` (+ optional
//!   `principal_type` / `principal_id`, which have no `ProviderKey`
//!   field here and are omitted); up to 3 attempts, `invalid_grant` /
//!   `invalid_client` terminal. The public `client_id` resolves from
//!   `GROK_OAUTH_CLIENT_ID` env (the TS side reads the same env) with
//!   the public CLI default embedded below.
//! - `executors/grok-cli.ts:340-388` (`transformRequest`): `store =
//!   false`, `include` gains `reasoning.encrypted_content`, effort
//!   defaults to `"high"` (except `grok-composer-2.5-fast`, which must
//!   not carry one), unsupported params stripped, tools capped at 200,
//!   `function_call_output` repaired (`#7611`), null reasoning content
//!   dropped.
//!
//! Deliberate divergences:
//! - The TS executor refreshes proactively on expiry and persists to
//!   its account store. The gateway is stateless: the stored
//!   credential is sent as the Bearer token, and on a 401 the bridge
//!   attempts one reactive refresh (same credential as `refresh_token`)
//!   and retries once.
//! - Namespace-tool flatten/restore and foreign-reasoning replay need
//!   cross-request tool identity maps; out of scope for the chat
//!   projection (noted, not stubbed — the request still dispatches).

use std::time::{Duration, Instant};

use aisix_gateway::url_cache::cached_endpoint_url;
use aisix_gateway::{
    apply_request_headers, scrub_upstream_headers, Bridge, BridgeContext, BridgeError, ChatChunk,
    ChatChunkStream, ChatFormat, ChatResponse, SseDecoder, SseEvent, UpstreamHeaderContext,
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
use crate::responses_wire::{
    build_responses_body, response_into_chat_response, stream_event_into_chat_chunk,
};

/// `GROK_BUILD_DEFAULT_CLIENT_VERSION`.
pub const GROK_CLIENT_VERSION: &str = "1.0.41";
/// `GROK_BUILD_CLIENT_IDENTIFIER`.
const GROK_CLIENT_IDENTIFIER: &str = "grok-shell";
/// `GROK_BUILD_TOKEN_AUTH`.
const GROK_TOKEN_AUTH: &str = "xai-grok-cli";
/// `GROK_BUILD_REASONING_INCLUDE`.
const GROK_REASONING_INCLUDE: &str = "reasoning.encrypted_content";
/// `GROK_BUILD_TOKEN_URL`.
const GROK_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";

/// Canonical responses URL (`GROK_BUILD_RESPONSES_URL`). An explicit
/// `ProviderKey.api_base` still wins (corporate proxy convention).
pub const GROK_DEFAULT_BASE: &str = "https://cli-chat-proxy.grok.com/v1";

/// Public OAuth client id (`grok_id` in open-sse `publicCreds.ts`,
/// extracted from the public Grok Build CLI; a PKCE native-app value,
/// public by design). Short UUID shape — matches no secret-scanner
/// pattern, so it lives as a plain literal rather than masked bytes.
const GROK_EMBEDDED_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";

/// Resolve the OAuth client id: `GROK_OAUTH_CLIENT_ID` env (same name
/// the TS side reads) wins when set, otherwise the embedded public
/// default. Never empty, so the mint's fail-closed error below is
/// unreachable in practice — it stays as the guard.
fn resolve_oauth_client_id() -> String {
    let from_env = aisix_gateway::resolve_public_cred(&[], &["GROK_OAUTH_CLIENT_ID"]);
    if from_env.is_empty() {
        GROK_EMBEDDED_CLIENT_ID.to_string()
    } else {
        from_env
    }
}

/// `GROK_BUILD_SUPPORTED_REASONING_EFFORTS`.
const SUPPORTED_EFFORTS: &[&str] = &["low", "medium", "high", "xhigh"];
/// `GROK_BUILD_DEFAULT_REASONING_EFFORT`.
const DEFAULT_EFFORT: &str = "high";
/// Model that must not carry a reasoning effort (`grok-cli.ts:160`).
const NO_EFFORT_MODEL: &str = "grok-composer-2.5-fast";
/// `GROK_BUILD_MAX_TOOLS`.
const MAX_TOOLS: usize = 200;

/// `GROK_BUILD_UNSUPPORTED_PARAMS`.
const UNSUPPORTED_PARAMS: &[&str] = &[
    "presencePenalty",
    "frequencyPenalty",
    "logprobs",
    "topLogprobs",
    "presence_penalty",
    "frequency_penalty",
    "top_logprobs",
    "reasoning_effort",
];

fn map_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        _ => std::env::consts::OS,
    }
}

fn map_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        _ => std::env::consts::ARCH,
    }
}

fn grok_user_agent() -> String {
    format!(
        "{GROK_CLIENT_IDENTIFIER}/{GROK_CLIENT_VERSION} ({}; {})",
        map_platform(),
        map_arch()
    )
}

/// `getGrokBuildSessionHeaders` (`grokBuild.ts:91-117`).
/// `model_override` carries the dispatched upstream model
/// (`x-grok-model-override`). `x-userid` / `x-email` are intentionally
/// NOT synthesized: the TS side fills them from the stored Grok account
/// (`providerSpecificData.userId`, account email), which the stateless
/// gateway does not hold — the gateway-local caller id lives in a
/// different identity domain and must never be sent as the Grok user.
/// An operator that needs those headers sets them explicitly via the
/// key's `forward_client_headers` / `default_headers`.
fn session_headers(
    token: &str,
    sse: bool,
    model_override: Option<&str>,
) -> Result<HeaderMap, BridgeError> {
    let mut headers = HeaderMap::new();
    let pairs: &[(&str, String)] = &[
        ("content-type", "application/json".to_string()),
        (
            "accept",
            (if sse {
                "text/event-stream"
            } else {
                "application/json"
            })
            .to_string(),
        ),
        ("x-grok-client-version", GROK_CLIENT_VERSION.to_string()),
        (
            "x-grok-client-identifier",
            GROK_CLIENT_IDENTIFIER.to_string(),
        ),
        ("x-grok-client-mode", "headless".to_string()),
        ("user-agent", grok_user_agent()),
        ("x-xai-token-auth", GROK_TOKEN_AUTH.to_string()),
        (
            "x-authenticateresponse",
            "authenticate-response".to_string(),
        ),
        ("authorization", format!("Bearer {token}")),
    ];
    for (name, value) in pairs {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| BridgeError::Config(format!("bad grok header name: {name}")))?,
            HeaderValue::from_str(value).map_err(|_| {
                BridgeError::InvalidUpstreamCredentials(
                    "grok credential is not a valid header value".into(),
                )
            })?,
        );
    }
    if let Some(model) = model_override.map(str::trim).filter(|m| !m.is_empty()) {
        headers.insert(
            HeaderName::from_static("x-grok-model-override"),
            HeaderValue::from_str(model).map_err(|_| {
                BridgeError::InvalidUpstreamConfig(
                    "grok model id is not a valid header value".into(),
                )
            })?,
        );
    }
    Ok(headers)
}

/// A lone surrogate half (`U+D800..=U+DFFF`): unpaired in a Rust
/// `char` stream only when the text came from lossy decoding, and
/// fatal to strict JSON parsers downstream.
fn is_lone_surrogate(c: char) -> bool {
    (0xD800..=0xDFFF).contains(&(c as u32))
}

/// Repair a `function_call_output.output` that would fail Grok's strict
/// JSON body parser (`sanitizeGrokBuildFunctionCallOutput`, `#7611`).
fn sanitize_function_call_output(output: &Value) -> String {
    match output {
        Value::Null => String::new(),
        Value::String(s) => {
            if serde_json::from_str::<Value>(s).is_ok() {
                return s.clone();
            }
            // Drop incomplete `\u` escapes (0-3 hex digits) that break
            // strict JSON parsers, then replace lone surrogates.
            let mut repaired = String::with_capacity(s.len());
            let mut chars = s.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if chars.peek() == Some(&'u') {
                        let mut hex = String::new();
                        let mut rest = chars.clone();
                        while hex.len() < 4 {
                            match rest.peek() {
                                Some(h) if h.is_ascii_hexdigit() => {
                                    hex.push(*h);
                                    rest.next();
                                }
                                _ => break,
                            }
                        }
                        if hex.len() == 4 {
                            repaired.push('\\');
                            repaired.push('u');
                            repaired.push_str(&hex);
                            chars = rest;
                        }
                        // Else: drop the broken escape entirely.
                        continue;
                    }
                    repaired.push(c);
                } else if is_lone_surrogate(c) {
                    repaired.push('\u{fffd}');
                } else {
                    repaired.push(c);
                }
            }
            if serde_json::from_str::<Value>(&repaired).is_ok() {
                return repaired;
            }
            repaired
                .chars()
                .map(|c| if is_lone_surrogate(c) { '\u{fffd}' } else { c })
                .collect()
        }
        Value::Array(parts) => {
            let mut text = String::new();
            for part in parts {
                match part {
                    Value::String(s) => {
                        if !text.is_empty() {
                            text.push('\n');
                        }
                        text.push_str(s);
                    }
                    Value::Object(map) => {
                        if let Some(Value::String(t)) = map.get("text") {
                            if !text.is_empty() {
                                text.push('\n');
                            }
                            text.push_str(t);
                        } else {
                            if !text.is_empty() {
                                text.push('\n');
                            }
                            text.push_str(&part.to_string());
                        }
                    }
                    other => {
                        if !text.is_empty() {
                            text.push('\n');
                        }
                        text.push_str(&other.to_string());
                    }
                }
            }
            sanitize_function_call_output(&Value::String(text))
        }
        other => other.to_string(),
    }
}

/// `transformRequest` sanitization (`grok-cli.ts:340-388`) applied to
/// the Responses body before send.
fn sanitize_responses_body(mut body: Value, model: &str) -> Value {
    if body.get("store").is_none() {
        body["store"] = Value::Bool(false);
    }
    // `include` gains `reasoning.encrypted_content`.
    let mut include: Vec<Value> = match body.get("include") {
        Some(Value::Array(arr)) => arr.clone(),
        _ => Vec::new(),
    };
    if !include
        .iter()
        .any(|v| v.as_str() == Some(GROK_REASONING_INCLUDE))
    {
        include.push(Value::String(GROK_REASONING_INCLUDE.to_string()));
    }
    body["include"] = Value::Array(include);

    for param in UNSUPPORTED_PARAMS {
        if let Some(obj) = body.as_object_mut() {
            obj.remove(*param);
        }
    }
    // Codex CLI replays reasoning items with `content: null`; Grok
    // cannot decode the unmodified encrypted blob — omit the key.
    // `#7611` tool-output repair for `function_call_output` items.
    if let Some(Value::Array(input)) = body.get("input").cloned() {
        let mut next_input = Vec::with_capacity(input.len());
        let mut changed = false;
        for mut item in input {
            if let Some(obj) = item.as_object_mut() {
                let item_type = obj
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if item_type == "reasoning" && obj.get("content").is_some_and(|c| c.is_null()) {
                    obj.remove("content");
                    changed = true;
                } else if item_type == "function_call_output" {
                    let current = obj.get("output").cloned().unwrap_or(Value::Null);
                    let repaired = sanitize_function_call_output(&current);
                    let current_str = match &current {
                        Value::String(s) => s.clone(),
                        Value::Null => String::new(),
                        other => other.to_string(),
                    };
                    if current_str != repaired {
                        obj.insert("output".to_string(), Value::String(repaired));
                        changed = true;
                    }
                }
            }
            next_input.push(item);
        }
        if changed {
            body["input"] = Value::Array(next_input);
        }
    }
    // Reasoning effort: only the true ABSENCE of an effort key gets the
    // model default; invalid efforts are dropped; the fast composer
    // model never carries one.
    let has_explicit_effort = body
        .get("reasoning")
        .and_then(|r| r.as_object())
        .is_some_and(|r| r.contains_key("effort"));
    if let Some(obj) = body.as_object_mut() {
        let reasoning = obj.get("reasoning");
        let valid = reasoning
            .and_then(|r| r.get("effort"))
            .and_then(Value::as_str)
            .is_some_and(|e| SUPPORTED_EFFORTS.contains(&e));
        if !valid {
            if let Some(r) = obj.get_mut("reasoning").and_then(|r| r.as_object_mut()) {
                r.remove("effort");
            }
        }
    }
    if model == NO_EFFORT_MODEL {
        if let Some(r) = body.get_mut("reasoning").and_then(|r| r.as_object_mut()) {
            r.remove("effort");
        }
    } else if !has_explicit_effort
        && !body
            .get("reasoning")
            .and_then(|r| r.get("effort"))
            .is_some_and(|e| e.is_string())
    {
        match body.get_mut("reasoning") {
            Some(Value::Object(r)) => {
                r.insert(
                    "effort".to_string(),
                    Value::String(DEFAULT_EFFORT.to_string()),
                );
            }
            _ => {
                body["reasoning"] = serde_json::json!({"effort": DEFAULT_EFFORT});
            }
        }
    }
    if body
        .get("reasoning")
        .is_some_and(|r| r.as_object().is_some_and(|o| o.is_empty()))
    {
        if let Some(obj) = body.as_object_mut() {
            obj.remove("reasoning");
        }
    }
    // `web_search` args Grok rejects (`external_web_access`,
    // `search_context_size`) + the 200-tool cap.
    if let Some(Value::Array(tools)) = body.get("tools").cloned() {
        let mut next_tools = Vec::with_capacity(tools.len().min(MAX_TOOLS));
        let mut changed = tools.len() > MAX_TOOLS;
        for mut tool in tools.into_iter().take(MAX_TOOLS) {
            if let Some(obj) = tool.as_object_mut() {
                if obj.get("type").and_then(Value::as_str) == Some("web_search") {
                    for arg in ["external_web_access", "search_context_size"] {
                        if obj.remove(arg).is_some() {
                            changed = true;
                        }
                    }
                }
            }
            next_tools.push(tool);
        }
        if changed {
            body["tools"] = Value::Array(next_tools);
        }
    }
    body
}

// ─── Refresh (`executors/grok-cli.ts:275-313`) ──────────────────────────

#[derive(Debug)]
struct GrokRefreshOutcome {
    access_token: String,
    refresh_token: String,
    expires_in: Option<u64>,
}

/// Single refresh attempt (`refreshGrokBuildCredentialsOnce`).
async fn refresh_once(
    client: &Client,
    token_url: &str,
    refresh_token: &str,
    client_id: &str,
    attempt: u32,
    max_attempts: u32,
) -> Result<Option<GrokRefreshOutcome>, BridgeError> {
    let params = [
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh_token),
    ];
    let resp = client
        .post(token_url)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await
        .map_err(|e| BridgeError::Transport(format!("grok token refresh request failed: {e}")))?;
    let status = resp.status();
    let data: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let code = data.get("error").and_then(Value::as_str).unwrap_or("");
        let terminal =
            attempt >= max_attempts || matches!(code, "invalid_grant" | "invalid_client");
        if terminal {
            return Err(BridgeError::InvalidUpstreamCredentials(format!(
                "grok refresh rejected ({status}, {code}); re-authentication required"
            )));
        }
        return Ok(None);
    }
    let access = data
        .get("access_token")
        .and_then(Value::as_str)
        .unwrap_or("");
    if access.is_empty() {
        if attempt >= max_attempts {
            return Err(BridgeError::UpstreamDecode(
                "grok token response carried no access_token".into(),
            ));
        }
        return Ok(None);
    }
    Ok(Some(GrokRefreshOutcome {
        access_token: access.to_string(),
        refresh_token: data
            .get("refresh_token")
            .and_then(Value::as_str)
            .unwrap_or(refresh_token)
            .to_string(),
        // Server-reported TTL with the documented 21600s fallback
        // (same convention as the codex/qoder mints).
        expires_in: data.get("expires_in").and_then(Value::as_u64),
    }))
}

struct GrokTokenMint {
    client: Client,
    cached: RwLock<Option<(String, String, Instant)>>,
}

impl GrokTokenMint {
    /// Up to 3 attempts with backoff (`grok-cli.ts:298-310`).
    async fn refresh(&self, refresh_token: &str) -> Result<(String, String), BridgeError> {
        {
            let guard = self.cached.read().await;
            if let Some((token, _, expiry)) = guard.as_ref() {
                if Instant::now() + Duration::from_secs(300) < *expiry {
                    return Ok((token.clone(), refresh_token.to_string()));
                }
            }
        }
        let client_id = resolve_oauth_client_id();
        if client_id.trim().is_empty() {
            return Err(BridgeError::InvalidUpstreamCredentials(
                "grok OAuth client id is not configured (GROK_OAUTH_CLIENT_ID); re-authenticate the account".into(),
            ));
        }
        let client_id = client_id.trim().to_string();
        // No guard held across the network round-trips below (each
        // attempt awaits + sleeps); re-acquire + re-check before insert.
        const MAX_ATTEMPTS: u32 = 3;
        let mut won: Option<GrokRefreshOutcome> = None;
        for attempt in 1..=MAX_ATTEMPTS {
            if attempt > 1 {
                let base_ms = 200 * 2_u64.pow(attempt - 2).min(8);
                // Jitter without a rand dependency: the low clock bits
                // spread concurrent refresh retries that would otherwise
                // wake in lockstep after the same failure.
                let jitter_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| u64::from(d.subsec_nanos()) % (base_ms + 1))
                    .unwrap_or(0);
                tokio::time::sleep(Duration::from_millis(base_ms + jitter_ms)).await;
            }
            match refresh_once(
                &self.client,
                GROK_TOKEN_URL,
                refresh_token,
                client_id.trim(),
                attempt,
                MAX_ATTEMPTS,
            )
            .await?
            {
                Some(outcome) => {
                    won = Some(outcome);
                    break;
                }
                None => continue,
            }
        }
        let outcome = won.ok_or_else(|| {
            BridgeError::Transport("grok token refresh failed after 3 attempts".into())
        })?;
        let ttl = Duration::from_secs(outcome.expires_in.unwrap_or(21600).max(1));
        let mut guard = self.cached.write().await;
        if let Some((token, _, expiry)) = guard.as_ref() {
            if Instant::now() + Duration::from_secs(300) < *expiry {
                return Ok((token.clone(), refresh_token.to_string()));
            }
        }
        *guard = Some((
            outcome.access_token.clone(),
            outcome.refresh_token.clone(),
            Instant::now() + ttl,
        ));
        Ok((outcome.access_token, outcome.refresh_token))
    }
}

// ─── Bridge ─────────────────────────────────────────────────────────────

pub struct GrokCliBridge {
    client: Client,
    mint: GrokTokenMint,
}

impl GrokCliBridge {
    pub fn new() -> Self {
        Self {
            client: aisix_gateway::client_builder()
                .build()
                .unwrap_or_else(|_| Client::new()),
            mint: GrokTokenMint {
                client: Client::builder()
                    .timeout(Duration::from_secs(15))
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
            _ => GROK_DEFAULT_BASE.to_string(),
        }
    }

    fn credential(ctx: &BridgeContext) -> Result<String, BridgeError> {
        let k = ctx.provider_key.api_key.trim().to_string();
        if k.is_empty() {
            return Err(BridgeError::InvalidUpstreamCredentials(
                "grok provider_key.api_key is empty".into(),
            ));
        }
        if HeaderValue::from_str(&k).is_err() {
            return Err(BridgeError::InvalidUpstreamCredentials(
                "grok provider_key.api_key contains invalid header characters".into(),
            ));
        }
        Ok(k)
    }

    fn build_headers(
        token: &str,
        request_id: &str,
        sse: bool,
        hdr: &UpstreamHeaderContext<'_>,
        model_override: Option<&str>,
    ) -> Result<HeaderMap, BridgeError> {
        let mut headers = session_headers(token, sse, model_override)?;
        headers.insert(
            HeaderName::from_static("x-aisix-request-id"),
            HeaderValue::from_str(request_id).map_err(|e| {
                BridgeError::Config(format!("request_id contains invalid header chars: {e}"))
            })?,
        );
        apply_request_headers(&mut headers, hdr);
        scrub_upstream_headers(&mut headers);
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
                .headers(headers.clone())
                .json(body)
                .send()
                .await
                .map_err(aisix_gateway::send_error)?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED && !refreshed {
                if let Ok((access, _)) = self.mint.refresh(credential).await {
                    let auth =
                        HeaderValue::from_str(&format!("Bearer {access}")).map_err(|_| {
                            BridgeError::InvalidUpstreamCredentials(
                                "refreshed grok token is not a valid header value".into(),
                            )
                        })?;
                    headers.insert(header::AUTHORIZATION, auth);
                    continue;
                }
            }
            return Ok(resp);
        }
        Err(BridgeError::Transport("grok retry loop exhausted".into()))
    }
}

impl Default for GrokCliBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Bridge for GrokCliBridge {
    fn name(&self) -> &'static str {
        "grok-cli"
    }

    fn wire_protocol(&self) -> &'static str {
        // Responses is an OpenAI-family wire; the closed `Adapter` enum
        // has no responses variant, and the metric-label agreement test
        // requires this to equal `upstream_protocol()` for the vendor.
        aisix_core::Adapter::Openai.wire_protocol()
    }

    async fn chat(
        &self,
        req: &ChatFormat,
        ctx: &BridgeContext,
    ) -> Result<ChatResponse, BridgeError> {
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
        let has_tools = !tool_calls.is_empty();
        if has_tools {
            message
                .extra
                .insert("tool_calls".to_string(), Value::Array(tool_calls));
        }
        if !full_reasoning.is_empty() {
            message.extra.insert(
                "reasoning_content".to_string(),
                Value::String(full_reasoning),
            );
        }
        Ok(ChatResponse {
            id: ctx.request_id.clone(),
            model,
            message,
            finish_reason: if has_tools {
                aisix_gateway::FinishReason::ToolCalls
            } else {
                aisix_gateway::FinishReason::Stop
            },
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
        let raw_body = build_responses_body(req, upstream_model, true, Some(DEFAULT_EFFORT));
        let body = sanitize_responses_body(raw_body, upstream_model);
        let headers = Self::build_headers(
            &credential,
            &ctx.request_id,
            true,
            &ctx.header_ctx(),
            Some(upstream_model),
        )?;
        let url = cached_endpoint_url(
            &ctx.provider_key_id,
            "grok-cli/responses",
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
            this.post_responses(&url, headers, &body, &client, &credential_for_retry)
                .await
        })
        .await?;
        // Non-streaming terminal object (proxies sometimes answer 200 +
        // JSON even with `stream: true`): fold it into one chunk.
        let content_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let status = resp.status();
        if !status.is_success() {
            return Err(map_http_error(status, resp).await);
        }
        let model_owned = upstream_model.to_string();
        let request_id = ctx.request_id.clone();
        if content_type.contains("text/event-stream") || content_type.is_empty() {
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
        } else {
            let raw: Value = resp
                .json()
                .await
                .map_err(|e| BridgeError::UpstreamDecode(e.to_string()))?;
            let response = response_into_chat_response(&raw, &request_id, &model_owned);
            let usage = response.usage.clone();
            let stream = async_stream::try_stream! {
                yield ChatChunk {
                    id: request_id.clone(),
                    model: model_owned.clone(),
                    delta: aisix_gateway::ChatDelta {
                        content: Some(response.message.content_str().to_string()),
                        ..Default::default()
                    },
                    finish_reason: Some(response.finish_reason.clone()),
                    usage: Some(usage),
                };
            };
            Ok(Box::pin(stream))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_headers_carry_grok_identity() {
        let headers = session_headers("tok", true, Some("grok-4.7")).unwrap();
        assert_eq!(headers["x-grok-client-version"], "1.0.41");
        assert_eq!(headers["x-grok-client-identifier"], "grok-shell");
        assert_eq!(headers["x-xai-token-auth"], "xai-grok-cli");
        assert_eq!(headers["x-authenticateresponse"], "authenticate-response");
        assert_eq!(headers["authorization"], "Bearer tok");
        assert_eq!(headers["x-grok-model-override"], "grok-4.7");
        let ua = headers["user-agent"].to_str().unwrap().to_string();
        assert!(ua.starts_with("grok-shell/1.0.41 ("), "ua={ua}");
    }

    #[test]
    fn session_headers_omit_model_override_when_absent() {
        let headers = session_headers("tok", true, None).unwrap();
        assert!(!headers.contains_key("x-grok-model-override"));
    }

    #[test]
    fn oauth_client_id_embeds_public_default() {
        // The embedded default is a plain literal (UUID shape, no
        // scanner pattern); the env name stays the documented override.
        assert!(!resolve_oauth_client_id().is_empty());
    }

    #[test]
    fn sanitize_sets_store_false_and_reasoning_include() {
        let body = sanitize_responses_body(serde_json::json!({"model": "grok-4.7"}), "grok-4.7");
        assert_eq!(body["store"], serde_json::json!(false));
        assert!(body["include"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == GROK_REASONING_INCLUDE));
        assert_eq!(body["reasoning"]["effort"], serde_json::json!("high"));
    }

    #[test]
    fn fast_composer_model_carries_no_effort() {
        let body = sanitize_responses_body(
            serde_json::json!({"model": NO_EFFORT_MODEL}),
            NO_EFFORT_MODEL,
        );
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn unsupported_params_and_web_search_args_stripped() {
        let body = sanitize_responses_body(
            serde_json::json!({
                "model": "grok-4.7",
                "presence_penalty": 0.5,
                "reasoning_effort": "low",
                "tools": [{"type": "web_search", "external_web_access": true}]
            }),
            "grok-4.7",
        );
        assert!(body.get("presence_penalty").is_none());
        assert!(body.get("reasoning_effort").is_none());
        assert!(body["tools"][0].get("external_web_access").is_none());
    }

    #[test]
    fn function_call_output_repair() {
        assert_eq!(
            sanitize_function_call_output(&serde_json::json!(null)),
            String::new()
        );
        assert_eq!(
            sanitize_function_call_output(&serde_json::json!("{\"a\":1}")),
            "{\"a\":1}"
        );
        // Incomplete \u escape is dropped rather than forwarded.
        let repaired = sanitize_function_call_output(&serde_json::json!("ab\\u12"));
        assert!(!repaired.contains("\\u12"));
    }

    /// Refresh posts the `{grant_type, client_id, refresh_token}` form
    /// to the `auth.x.ai` token endpoint.
    #[tokio::test]
    async fn refresh_posts_form_and_reads_tokens() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "a-new",
                "refresh_token": "r-new",
                "expires_in": 21600,
            })))
            .mount(&server)
            .await;
        let outcome = refresh_once(
            &Client::new(),
            &format!("{}/oauth2/token", server.uri()),
            "rt-old",
            "cid",
            1,
            3,
        )
        .await
        .unwrap()
        .expect("success must yield tokens");
        assert_eq!(outcome.access_token, "a-new");
        assert_eq!(outcome.refresh_token, "r-new");
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let body = String::from_utf8_lossy(&reqs[0].body).into_owned();
        assert!(body.contains("grant_type=refresh_token"), "body={body}");
        assert!(body.contains("client_id=cid"), "body={body}");
        assert!(body.contains("refresh_token=rt-old"), "body={body}");
    }

    #[tokio::test]
    async fn refresh_terminal_error_is_unrecoverable() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
            })))
            .mount(&server)
            .await;
        let err = refresh_once(
            &Client::new(),
            &format!("{}/oauth2/token", server.uri()),
            "rt-dead",
            "cid",
            1,
            3,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, BridgeError::InvalidUpstreamCredentials(_)),
            "unexpected: {err:?}"
        );
    }
}
