//! aisix-provider-vertex::antigravity — Native Antigravity (Google Cloud Code v1internal RPC) Bridge.
//!
//! Mirrors OmniRoute's battle-tested `open-sse/executors/antigravity.ts` hand-in-hand:
//! - Google OAuth2 PKCE token refresher against `https://oauth2.googleapis.com/token`
//! - Upstream RPC: `https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse`
//! - Antigravity desktop IDE spoofing: `User-Agent: antigravity/ide/2.1.1 darwin/arm64`
//! - 429 Shield prompt sanitization: strips competitor assistant triggers that trigger Google 429s
//! - Streaming SSE parser translating candidate parts into `content` and `reasoning_content` (`thought`)

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aisix_core::Adapter;
use aisix_gateway::sse::{SseDecoder, SseEvent};
use aisix_gateway::{
    apply_request_headers, scrub_upstream_headers, Bridge, BridgeContext, BridgeError, ChatChunk,
    ChatChunkStream, ChatDelta, ChatFormat, ChatResponse, FinishReason, Role,
    UpstreamHeaderContext, UsageStats,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

fn env_or_empty(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

const GOOGLE_OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const ANTIGRAVITY_RPC_URL: &str =
    "https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse";
/// IDE version embedded in the spoofed Antigravity `User-Agent`.
/// Kept at `2.1.1` per spec; the header value is rendered from this
/// single const (pinned by `user_agent_carries_ide_version`).
const ANTIGRAVITY_IDE_VERSION: &str = "2.1.1";
const GOOG_API_CLIENT: &str = "gl-node/22.21.1";
/// Default Cloud Code project sent in the envelope. The TS executor
/// resolves this per-account via `loadCodeAssist` against its OAuth
/// account store; the gateway holds only the `ProviderKey` secret (no
/// project-id field, no account store), so per-account discovery is
/// impossible without a resource-schema change. The shared default
/// stays — removing it would break every existing key, and a missing
/// project fails closed upstream anyway.
const ANTIGRAVITY_DEFAULT_PROJECT: &str = "aicode-consumers";

// ─── Token Mint ─────────────────────────────────────────────────────────────

pub struct AntigravityTokenMint {
    client_id: String,
    client_secret: String,
    client: Client,
    cached: RwLock<HashMap<String, (String, Instant)>>,
}

/// Partition key for the token cache: hash of the refresh token so the
/// raw secret is never held as a map key and tenants never share an
/// entry. Non-cryptographic — only a partition, not a security boundary.
fn token_cache_key(refresh_token: &str) -> String {
    let mut hasher = DefaultHasher::new();
    refresh_token.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

impl Default for AntigravityTokenMint {
    fn default() -> Self {
        Self::new()
    }
}

impl AntigravityTokenMint {
    pub fn new() -> Self {
        Self {
            client_id: env_or_empty("ANTIGRAVITY_CLIENT_ID"),
            client_secret: env_or_empty("ANTIGRAVITY_CLIENT_SECRET"),
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            cached: RwLock::new(HashMap::new()),
        }
    }

    /// Retrieve a valid access token. If `credential` is already a pre-minted
    /// bearer token (starts with `ya29.`), it is returned as-is. Otherwise it
    /// is treated as an OAuth refresh token and refreshed if expired.
    /// Cache is partitioned by hash of the refresh token so tenants never
    /// share an entry.
    pub async fn get_token(&self, credential: &str) -> Result<String, BridgeError> {
        if credential.starts_with("ya29.") {
            return Ok(credential.to_string());
        }

        let key = token_cache_key(credential);
        // Fast read-path: return cached token if valid for at least 300 seconds
        {
            let guard = self.cached.read().await;
            if let Some((token, expiry)) = guard.get(&key) {
                if Instant::now() + Duration::from_secs(300) < *expiry {
                    return Ok(token.clone());
                }
            }
        }

        // Fail fast on missing OAuth client material (same shape as the
        // grok/codex mints): without it the refresh below can only fail
        // with an opaque upstream 400.
        if self.client_id.trim().is_empty() || self.client_secret.trim().is_empty() {
            return Err(BridgeError::InvalidUpstreamCredentials(
                "ANTIGRAVITY_CLIENT_ID/SECRET not configured".into(),
            ));
        }

        // No guard held across the network round-trip below: refresh
        // first, then re-acquire + re-check before inserting.
        let params = [
            ("grant_type", "refresh_token"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("refresh_token", credential),
        ];

        let resp = self
            .client
            .post(GOOGLE_OAUTH_TOKEN_URL)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                BridgeError::Transport(format!("antigravity token refresh request failed: {e}"))
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body: String = resp.text().await.unwrap_or_default();
            // Rotated/revoked refresh tokens are terminal: surface
            // re-auth instead of a retryable upstream status.
            if status == reqwest::StatusCode::BAD_REQUEST
                && (body.contains("invalid_grant") || body.contains("invalid_client"))
            {
                return Err(BridgeError::InvalidUpstreamCredentials(format!(
                    "antigravity refresh token rejected ({status}); re-authentication required"
                )));
            }
            return Err(BridgeError::upstream_status(
                status.as_u16(),
                format!("antigravity token refresh rejected ({status}): {body}"),
            ));
        }

        let payload: OAuthTokenResponse = resp.json().await.map_err(|e| {
            BridgeError::UpstreamDecode(format!("failed to parse antigravity token response: {e}"))
        })?;

        let ttl_secs = payload.expires_in.unwrap_or(3600);
        let expiry = Instant::now() + Duration::from_secs(ttl_secs);
        let token = payload.access_token;
        let mut guard = self.cached.write().await;
        if let Some((cached, cached_expiry)) = guard.get(&key) {
            if Instant::now() + Duration::from_secs(300) < *cached_expiry {
                return Ok(cached.clone());
            }
        }
        guard.insert(key, (token.clone(), expiry));

        Ok(token)
    }
}

// ─── Request Envelope & Sanitization ────────────────────────────────────────

#[derive(Serialize)]
struct AntigravityEnvelope<'a> {
    project: &'a str,
    model: &'a str,
    #[serde(rename = "userAgent")]
    user_agent: &'static str,
    #[serde(rename = "requestType")]
    request_type: &'static str,
    #[serde(rename = "requestId")]
    request_id: String,
    request: AntigravityRequest,
}

#[derive(Serialize)]
struct AntigravityRequest {
    contents: Vec<AntigravityContent>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "systemInstruction")]
    system_instruction: Option<AntigravitySystemInstruction>,
    #[serde(rename = "generationConfig")]
    generation_config: AntigravityGenConfig,
    #[serde(skip_serializing_if = "Option::is_none", rename = "sessionId")]
    session_id: Option<String>,
}

#[derive(Serialize)]
struct AntigravityContent {
    role: &'static str,
    parts: Vec<AntigravityPart>,
}

#[derive(Serialize)]
struct AntigravitySystemInstruction {
    parts: Vec<AntigravityPart>,
}

#[derive(Serialize)]
struct AntigravityPart {
    text: String,
}

#[derive(Serialize)]
struct AntigravityGenConfig {
    #[serde(rename = "topK")]
    top_k: u32,
    #[serde(rename = "topP")]
    top_p: f32,
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
}

/// 429 Shield: Sanitizes text against Google's anti-Claude heuristic filter.
/// Google Cloud Code triggers HTTP 429 RESOURCE_EXHAUSTED when system prompt
/// contains specific competitor assistant declarations.
/// Mirrors `COMPETITIVE_AGENT_PROMPT_PATTERNS` in
/// `omniroute/open-sse/executors/antigravity.ts:367-372`: case-insensitive,
/// word-boundaried, same four phrases.
fn agent_identity_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(you are a claude agent|you are claude code|you are an ai assistant created by anthropic)\b",
        )
        .expect("agent identity sanitize regex must compile")
    })
}

fn agent_sdk_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bbuilt on anthropic's claude agent sdk\b")
            .expect("agent SDK sanitize regex must compile")
    })
}

fn sanitize_prompt_text(text: &str) -> String {
    let replaced = agent_identity_re().replace_all(text, "AI Assistant");
    agent_sdk_re()
        .replace_all(&replaced, "built on standard SDK")
        .into_owned()
}

// ─── Request identity (`antigravityIdentity.ts`) ──────────────────────────

/// Process-wide uniqueness source for generated ids. The TS side uses
/// `crypto.randomBytes`; this crate has no rand dependency, so a
/// monotonic counter plays that role — the wire SHAPES below are
/// identical, only the entropy source differs.
static ANTIGRAVITY_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `generateAntigravityRequestId`: `agent/<millis>/<8 hex>`.
fn generate_request_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let n = ANTIGRAVITY_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("agent/{millis}/{n:08x}")
}

/// FNV-1a/64 rendered as signed decimal (`deriveAntigravitySessionId`:
/// offset `-3750763034362895579`, prime `1099511628211`, 64-bit
/// wrap). The TS side hashes the account email; the gateway has no
/// account identity beyond the stored credential, so the credential
/// itself is the stable per-key input — same stickiness property (one
/// session per key until the key rotates).
fn derive_session_id(account_key: &str) -> String {
    let mut hash: i64 = -3750763034362895579;
    for byte in account_key.as_bytes() {
        hash ^= *byte as i64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash.to_string()
}

/// `generateAntigravitySessionId`: negative decimal (counter mod 9e18
/// instead of rejection-sampled crypto bytes — see above).
fn generate_session_id() -> String {
    let n = ANTIGRAVITY_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("-{}", (n % 9_000_000_000_000_000_000).max(1))
}

/// `getAntigravitySessionId`: stable per-credential id, random only
/// when there is nothing to hash.
fn resolve_session_id(credential: &str) -> String {
    let key = credential.trim();
    if key.is_empty() {
        generate_session_id()
    } else {
        derive_session_id(key)
    }
}

/// Fields the unified thinking adapters may leave at the body root,
/// plus the Anthropic-only `output_config` envelope field: Google's
/// Cloud Code envelope rejects them with 400 (`antigravity.ts:821-838`,
/// issues #1926/#1944). Our envelope never carries them — the strip
/// runs on the serialized body so a future flatten cannot leak one
/// upstream.
fn strip_thinking_fields(body: &mut serde_json::Value) {
    const STRIP: &[&str] = &[
        "output_config",
        "output_format",
        "thinking",
        "reasoning_effort",
        "reasoning",
        "enable_thinking",
        "thinking_budget",
    ];
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    for key in STRIP {
        obj.remove(*key);
    }
    if let Some(serde_json::Value::Object(request)) = obj.get_mut("request") {
        for key in STRIP {
            request.remove(*key);
        }
    }
}

fn convert_chat_format<'a>(
    req: &'a ChatFormat,
    model_name: &'a str,
    credential: &str,
) -> AntigravityEnvelope<'a> {
    let mut contents = Vec::new();
    let mut system_text = String::new();

    for m in &req.messages {
        if m.is_reasoning_only() {
            continue;
        }
        let text = sanitize_prompt_text(m.content_str());
        match m.role {
            Role::System | Role::Developer => {
                if !system_text.is_empty() {
                    system_text.push_str("\n\n");
                }
                system_text.push_str(&text);
            }
            Role::User | Role::Tool => {
                contents.push(AntigravityContent {
                    role: "user",
                    parts: vec![AntigravityPart { text }],
                });
            }
            Role::Assistant => {
                contents.push(AntigravityContent {
                    role: "model",
                    parts: vec![AntigravityPart { text }],
                });
            }
        }
    }

    let system_instruction = if !system_text.is_empty() {
        Some(AntigravitySystemInstruction {
            parts: vec![AntigravityPart { text: system_text }],
        })
    } else {
        None
    };

    AntigravityEnvelope {
        project: ANTIGRAVITY_DEFAULT_PROJECT,
        model: model_name,
        user_agent: "antigravity",
        request_type: "agent",
        request_id: generate_request_id(),
        request: AntigravityRequest {
            contents,
            system_instruction,
            generation_config: AntigravityGenConfig {
                top_k: 40,
                top_p: 1.0,
                max_output_tokens: 65535,
            },
            session_id: Some(resolve_session_id(credential)),
        },
    }
}

// ─── Upstream SSE Response Types ───────────────────────────────────────────

#[derive(Deserialize)]
struct AntigravitySseResponse {
    response: Option<AntigravityCandidateContainer>,
    /// Top-level `markdown` envelope (`sseCollect.ts:82-90`).
    #[serde(default)]
    markdown: Option<String>,
}

#[derive(Deserialize)]
struct AntigravityCandidateContainer {
    candidates: Option<Vec<AntigravityCandidate>>,
    #[serde(rename = "usageMetadata")]
    usage_metadata: Option<AntigravityUsage>,
    #[serde(default)]
    markdown: Option<String>,
}

#[derive(Deserialize)]
struct AntigravityCandidate {
    content: Option<AntigravityContentPayload>,
    #[serde(rename = "finishReason")]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct AntigravityContentPayload {
    parts: Option<Vec<AntigravityResponsePart>>,
}

#[derive(Deserialize)]
struct AntigravityResponsePart {
    text: Option<String>,
    thought: Option<bool>,
    /// Native Gemini function call (Gemini 3.x answers
    /// functionDeclarations with this, usually carrying a
    /// `thoughtSignature` — `sseCollect.ts:99-115`). The request side
    /// never fabricates parts, so there is nothing to strip; the
    /// signature rides along implicitly by forwarding the call.
    #[serde(rename = "functionCall", default)]
    function_call: Option<AntigravityFunctionCall>,
    /// Parsed for wire tolerance (a part carrying a signature must
    /// still decode); not forwarded — the gateway's single-turn
    /// projection has no replay turn to echo it on. The struct would
    /// decode identically without it; the field exists so a
    /// signature-carrying part is a covered shape, not an accident.
    #[serde(rename = "thoughtSignature", default)]
    #[allow(dead_code)]
    thought_signature: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct AntigravityFunctionCall {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    args: Option<serde_json::Value>,
    #[serde(default)]
    id: Option<String>,
}

#[derive(Deserialize)]
struct AntigravityUsage {
    #[serde(rename = "promptTokenCount")]
    prompt_tokens: Option<u32>,
    #[serde(rename = "candidatesTokenCount")]
    completion_tokens: Option<u32>,
    #[serde(rename = "totalTokenCount")]
    total_tokens: Option<u32>,
    /// Folded into `completion_tokens` with `reasoning_tokens` naming
    /// the subset (`sseCollect.ts:147-155`).
    #[serde(rename = "thoughtsTokenCount", default)]
    thoughts_tokens: Option<u32>,
}

/// Build the client-facing usage from `usageMetadata`: `thoughtsTokenCount`
/// is reported BESIDE `candidatesTokenCount`, so the folded completion is
/// their sum and `reasoning_folded_into_completion` records the fold for
/// the UsageEvent path (see `UsageStats` docs).
fn usage_from_metadata(u: &AntigravityUsage) -> UsageStats {
    let thoughts = u.thoughts_tokens.unwrap_or(0);
    let total = u.total_tokens.unwrap_or(0);
    UsageStats {
        prompt_tokens: u.prompt_tokens.unwrap_or(0),
        completion_tokens: u.completion_tokens.unwrap_or(0).saturating_add(thoughts),
        total_tokens: total,
        reasoning_tokens: thoughts,
        reasoning_folded_into_completion: thoughts,
        upstream_total_tokens: total,
        ..Default::default()
    }
}

// ─── Bridge Implementation ─────────────────────────────────────────────────

pub struct AntigravityBridge {
    client: Client,
    token_mint: Arc<AntigravityTokenMint>,
}

impl Default for AntigravityBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl AntigravityBridge {
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .tcp_nodelay(true)
                .build()
                .unwrap_or_else(|_| Client::new()),
            token_mint: Arc::new(AntigravityTokenMint::new()),
        }
    }

    fn build_headers(
        &self,
        token: &str,
        request_id: &str,
        hdr: &UpstreamHeaderContext<'_>,
    ) -> Result<HeaderMap, BridgeError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
                BridgeError::Config("antigravity token contains invalid header characters".into())
            })?,
        );
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_str(&format!(
                "antigravity/ide/{ANTIGRAVITY_IDE_VERSION} darwin/arm64"
            ))
            .map_err(|_| BridgeError::Config("invalid antigravity user-agent".into()))?,
        );
        headers.insert(
            HeaderName::from_static("x-goog-api-client"),
            HeaderValue::from_static(GOOG_API_CLIENT),
        );
        headers.insert(
            HeaderName::from_static("x-aisix-request-id"),
            HeaderValue::from_str(request_id)
                .map_err(|_| BridgeError::Config("invalid request_id header".into()))?,
        );
        // Operator headers merge before the fingerprint scrub, which runs
        // last with Authorization re-inserted last.
        apply_request_headers(&mut headers, hdr);
        scrub_proxy_headers(&mut headers);
        Ok(headers)
    }
}

/// `scrubProxyAndFingerprintHeaders` (`antigravityHeaderScrub.ts`): a
/// real Antigravity (Node.js) client never sends proxy-tracing,
/// Stainless-SDK or Chromium fingerprint headers. Our map is built
/// fresh (no inbound forwarding), so this is a guard — anything on
/// the denylist is dropped if it ever arrives via a merge, the
/// Node `Accept-Encoding` is pinned, and `Authorization` is moved
/// last to match the native fingerprint.
///
/// The shared proxy/chromium pass lives in
/// [`scrub_upstream_headers`](aisix_gateway::upstream_headers::scrub_upstream_headers);
/// the Antigravity-only extras (Stainless SDK tells, referers,
/// `x-title`, the `Accept-Encoding` pin) stay here because sibling
/// bridges legitimately own some of those names (qoder's
/// `x-stainless-*`, cline's `http-referer`/`x-title`).
fn scrub_proxy_headers(headers: &mut HeaderMap) {
    scrub_upstream_headers(headers);
    const ANTIGRAVITY_ONLY: &[&str] = &[
        "x-title",
        "x-stainless-lang",
        "x-stainless-package-version",
        "x-stainless-os",
        "x-stainless-arch",
        "x-stainless-runtime",
        "x-stainless-runtime-version",
        "x-stainless-timeout",
        "x-stainless-retry-count",
        "x-stainless-helper-method",
        "http-referer",
        "referer",
        "accept-encoding",
    ];
    let auth = headers.remove(header::AUTHORIZATION);
    // `http::HeaderMap` has no `retain` — collect the denylisted keys
    // first, then remove them.
    let doomed: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            let lower = name.as_str().to_ascii_lowercase();
            // Our own correlation header is intentionally sent upstream
            // (same as the OpenAI bridge); any other gateway-internal
            // `x-aisix-*` key is an infra tell and is dropped (already
            // handled by the shared scrub; kept here for the
            // Antigravity-only re-pass).
            if lower.starts_with("x-aisix-") {
                return lower != "x-aisix-request-id";
            }
            ANTIGRAVITY_ONLY.contains(&lower.as_str())
        })
        .cloned()
        .collect();
    for name in doomed {
        headers.remove(name);
    }
    headers.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("gzip, deflate, br"),
    );
    if let Some(auth) = auth {
        headers.insert(header::AUTHORIZATION, auth);
    }
}

#[async_trait]
impl Bridge for AntigravityBridge {
    fn name(&self) -> &'static str {
        "antigravity"
    }

    fn wire_protocol(&self) -> &'static str {
        Adapter::Vertex.wire_protocol()
    }

    async fn chat(
        &self,
        req: &ChatFormat,
        ctx: &BridgeContext,
    ) -> Result<ChatResponse, BridgeError> {
        let mut stream = self.chat_stream(req, ctx).await?;
        let mut full_content = String::new();
        let mut full_reasoning = String::new();
        let mut tool_calls: Vec<serde_json::Value> = Vec::new();
        let mut finish_reason = FinishReason::Stop;
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
            // A tool-call finish must survive a trailing STOP frame:
            // once calls exist, the candidate's own reason no longer
            // decides (`sseCollect.ts:136-144`).
            if let Some(fr) = chunk.finish_reason {
                if tool_calls.is_empty() {
                    finish_reason = fr;
                }
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
        let mut message = aisix_gateway::chat::ChatMessage::assistant(full_content);
        if !tool_calls.is_empty() {
            finish_reason = FinishReason::ToolCalls;
            message.extra.insert(
                "tool_calls".to_string(),
                serde_json::Value::Array(tool_calls),
            );
        }
        Ok(ChatResponse {
            id: ctx.request_id.clone(),
            model,
            message,
            finish_reason,
            usage: final_usage.unwrap_or_default(),
        })
    }

    async fn chat_stream(
        &self,
        req: &ChatFormat,
        ctx: &BridgeContext,
    ) -> Result<ChatChunkStream, BridgeError> {
        let credential = &ctx.provider_key.api_key;
        if credential.is_empty() {
            return Err(BridgeError::InvalidUpstreamCredentials(
                "antigravity requires a refresh_token or access_token in provider_key.api_key"
                    .into(),
            ));
        }

        let access_token = self.token_mint.get_token(credential).await?;
        let request_id = ctx.request_id.clone();
        let headers = self.build_headers(&access_token, &request_id, &ctx.header_ctx())?;

        let upstream_model = ctx
            .model
            .model_name
            .as_deref()
            .unwrap_or(&ctx.model.display_name);
        let envelope = convert_chat_format(req, upstream_model, credential);
        let mut body_value = serde_json::to_value(&envelope).map_err(|e| {
            BridgeError::Config(format!(
                "failed to serialize antigravity request envelope: {e}"
            ))
        })?;
        strip_thinking_fields(&mut body_value);
        let body_json = serde_json::to_string(&body_value).map_err(|e| {
            BridgeError::Config(format!(
                "failed to re-serialize antigravity request envelope: {e}"
            ))
        })?;

        let resp = self
            .client
            .post(ANTIGRAVITY_RPC_URL)
            .headers(headers)
            .body(body_json)
            .send()
            .await
            .map_err(|e| BridgeError::Transport(format!("antigravity RPC connect error: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let err_body = resp.text().await.unwrap_or_default();
            return Err(BridgeError::upstream_status(
                status.as_u16(),
                format!("antigravity upstream error ({status}): {err_body}"),
            ));
        }

        let upstream_id_owned = upstream_model.to_string();
        let byte_stream = resp.bytes_stream();

        let stream = async_stream::try_stream! {
            let mut decoder = SseDecoder::new();
            let mut byte_stream = Box::pin(byte_stream);

            while let Some(item) = byte_stream.next().await {
                let bytes: Bytes = item.map_err(|e| {
                    BridgeError::Transport(format!("antigravity SSE stream read error: {e}"))
                })?;
                for event in decoder.feed(bytes.as_ref()).map_err(|e| {
                    BridgeError::UpstreamDecode(e.to_string())
                })? {
                    if let SseEvent::Data(data) = event {
                        if data.trim() == "[DONE]" {
                            break;
                        }
                        if let Ok(sse) = serde_json::from_str::<AntigravitySseResponse>(&data) {
                            // `markdown` envelope fold (`sseCollect.ts:82-90`).
                            let markdown = sse.markdown.as_deref().or_else(|| {
                                sse.response
                                    .as_ref()
                                    .and_then(|c| c.markdown.as_deref())
                            });
                            if let Some(md) = markdown {
                                if !md.is_empty() {
                                    yield ChatChunk {
                                        id: request_id.clone(),
                                        model: upstream_id_owned.clone(),
                                        delta: ChatDelta {
                                            content: Some(md.to_string()),
                                            ..Default::default()
                                        },
                                        finish_reason: None,
                                        usage: None,
                                    };
                                }
                            }
                            if let Some(container) = sse.response {
                                let mut usage =
                                    container.usage_metadata.as_ref().map(usage_from_metadata);

                                if let Some(candidates) = container.candidates {
                                    for candidate in candidates {
                                        let finish_reason = candidate.finish_reason.as_deref().map(|s| match s {
                                            "STOP" => FinishReason::Stop,
                                            "MAX_TOKENS" => FinishReason::Length,
                                            _ => FinishReason::Stop,
                                        });

                                        if let Some(content) = candidate.content {
                                            if let Some(parts) = content.parts {
                                                let last = parts.len().saturating_sub(1);
                                                for (index, part) in parts.into_iter().enumerate() {
                                                    // Moved on the last part, cloned otherwise:
                                                    // every emitted chunk still carries the
                                                    // frame's usage, but the final move
                                                    // avoids one clone per SSE response
                                                    // (the hot single-part case moves).
                                                    let is_last = index == last;
                                                    // Native `functionCall` part (Gemini 3.x
                                                    // answers to functionDeclarations with
                                                    // this, usually carrying a
                                                    // `thoughtSignature`):
                                                    // forward as a chat-shape tool call
                                                    // (`sseCollect.ts:99-115`).
                                                    if let Some(fc) = part.function_call.as_ref() {
                                                        if let Some(name) = fc
                                                            .name
                                                            .as_deref()
                                                            .filter(|n| !n.is_empty())
                                                        {
                                                            let args = fc.args.clone().unwrap_or(
                                                                serde_json::Value::Object(
                                                                    Default::default(),
                                                                ),
                                                            );
                                                            let call_id = fc
                                                                .id
                                                                .clone()
                                                                .filter(|s| !s.is_empty())
                                                                .unwrap_or_else(|| {
                                                                    format!(
                                                                        "{name}-{index}"
                                                                    )
                                                                });
                                                            yield ChatChunk {
                                                                id: request_id.clone(),
                                                                model: upstream_id_owned.clone(),
                                                                delta: ChatDelta {
                                                                    tool_calls: Some(vec![
                                                                        serde_json::json!({
                                                                            "id": call_id,
                                                                            "type": "function",
                                                                            "function": {
                                                                                "name": name,
                                                                                "arguments": args.to_string(),
                                                                            },
                                                                        }),
                                                                    ]),
                                                                    ..Default::default()
                                                                },
                                                                finish_reason: Some(
                                                                    FinishReason::ToolCalls,
                                                                ),
                                                                usage: if is_last {
                                                                    usage.take()
                                                                } else {
                                                                    usage.clone()
                                                                },
                                                            };
                                                            continue;
                                                        }
                                                    }
                                                    let is_thought = part.thought == Some(true);
                                                    if is_thought {
                                                        yield ChatChunk {
                                                            id: request_id.clone(),
                                                            model: upstream_id_owned.clone(),
                                                            delta: ChatDelta {
                                                                reasoning_content: part.text,
                                                                ..Default::default()
                                                            },
                                                            finish_reason: finish_reason.clone(),
                                                            usage: if is_last {
                                                                usage.take()
                                                            } else {
                                                                usage.clone()
                                                            },
                                                        };
                                                    } else if part.text.is_some() {
                                                        yield ChatChunk {
                                                            id: request_id.clone(),
                                                            model: upstream_id_owned.clone(),
                                                            delta: ChatDelta {
                                                                content: part.text,
                                                                ..Default::default()
                                                            },
                                                            finish_reason: finish_reason.clone(),
                                                            usage: if is_last {
                                                                usage.take()
                                                            } else {
                                                                usage.clone()
                                                            },
                                                        };
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
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
    fn sanitize_is_case_insensitive_with_word_boundary() {
        // Mixed register per phrase must still sanitize (old 5x `replace`
        // was case-sensitive and missed these).
        for input in [
            "YOU ARE A CLAUDE AGENT, here to help",
            "You Are Claude Code with instructions",
            "yOu ArE aN aI aSsIsTaNt CrEaTeD bY aNtHrOpIc, hello",
            "BUILT ON ANTHROPIC'S CLAUDE AGENT SDK v1",
        ] {
            let out = sanitize_prompt_text(input);
            assert!(
                !agent_identity_re().is_match(&out) && !agent_sdk_re().is_match(&out),
                "unsanitized remainder in {out:?} from {input:?}"
            );
        }
        assert_eq!(
            sanitize_prompt_text("You are a Claude agent, built today"),
            "AI Assistant, built today"
        );
        assert_eq!(
            sanitize_prompt_text("You are Claude Code!"),
            "AI Assistant!"
        );
        assert_eq!(
            sanitize_prompt_text("You are an AI assistant created by Anthropic."),
            "AI Assistant."
        );
        assert_eq!(
            sanitize_prompt_text("Built on Anthropic's Claude Agent SDK, extended"),
            "built on standard SDK, extended"
        );
    }

    #[test]
    fn sanitize_leaves_unrelated_text_untouched() {
        let plain = "You are a helpful coding assistant. Claude models are great.";
        assert_eq!(sanitize_prompt_text(plain), plain);
    }

    #[test]
    fn token_cache_keys_partition_tenants() {
        assert_ne!(
            token_cache_key("refresh-tenant-a"),
            token_cache_key("refresh-tenant-b")
        );
        assert_eq!(token_cache_key("same"), token_cache_key("same"));
    }

    #[tokio::test]
    async fn missing_oauth_client_material_fails_fast() {
        let mint = AntigravityTokenMint {
            client_id: String::new(),
            client_secret: String::new(),
            client: Client::new(),
            cached: RwLock::new(HashMap::new()),
        };
        let err = mint.get_token("some-refresh-token").await.unwrap_err();
        assert!(
            matches!(err, BridgeError::InvalidUpstreamCredentials(_)),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn user_agent_carries_ide_version() {
        let ua = format!("antigravity/ide/{ANTIGRAVITY_IDE_VERSION} darwin/arm64");
        assert_eq!(ua, "antigravity/ide/2.1.1 darwin/arm64");
    }

    #[test]
    fn request_id_matches_agent_shape() {
        let id = generate_request_id();
        assert!(id.starts_with("agent/"), "id={id}");
        assert_eq!(id.split('/').count(), 3, "id={id}");
        assert_ne!(generate_request_id(), generate_request_id());
    }

    #[test]
    fn session_id_is_stable_per_credential() {
        assert_eq!(resolve_session_id("cred-a"), resolve_session_id("cred-a"));
        assert_ne!(resolve_session_id("cred-a"), resolve_session_id("cred-b"));
        assert!(resolve_session_id("cred-a").parse::<i64>().is_ok());
        let empty = resolve_session_id("  ");
        assert!(
            empty.starts_with('-'),
            "empty credential must yield a generated id, got {empty}"
        );
    }

    #[test]
    fn thinking_fields_stripped_from_envelope() {
        let mut body = serde_json::json!({
            "project": "p",
            "output_config": {"a": 1},
            "thinking": true,
            "request": {"contents": [], "reasoning": "x", "output_config": 1},
        });
        strip_thinking_fields(&mut body);
        assert!(body.get("output_config").is_none());
        assert!(body.get("thinking").is_none());
        assert!(body["request"].get("reasoning").is_none());
        assert!(body["request"].get("output_config").is_none());
        assert_eq!(body["project"], serde_json::json!("p"));
    }

    #[test]
    fn thoughts_tokens_fold_into_completion() {
        let usage = usage_from_metadata(
            &serde_json::from_value(serde_json::json!({
                "promptTokenCount": 10,
                "candidatesTokenCount": 20,
                "totalTokenCount": 40,
                "thoughtsTokenCount": 10,
            }))
            .unwrap(),
        );
        assert_eq!(usage.prompt_tokens, 10);
        assert_eq!(usage.completion_tokens, 30);
        assert_eq!(usage.reasoning_tokens, 10);
        assert_eq!(usage.reasoning_folded_into_completion, 10);
        assert_eq!(usage.upstream_total_tokens, 40);
    }

    #[test]
    fn sse_shapes_parse_markdown_function_call_and_signature() {
        // Top-level markdown envelope.
        let sse: AntigravitySseResponse =
            serde_json::from_str(r##"{"markdown":"# hello"}"##).unwrap();
        assert_eq!(sse.markdown.as_deref(), Some("# hello"));
        // Candidate part with a native functionCall + thoughtSignature.
        let sse: AntigravitySseResponse = serde_json::from_str(
            r#"{"response":{"candidates":[{"content":{"parts":[
                {"functionCall":{"name":"search","args":{"q":"x"}},"thoughtSignature":"sig"}
            ]}}]}}"#,
        )
        .unwrap();
        let container = sse.response.expect("response envelope");
        let candidate = &container.candidates.expect("candidates")[0];
        let part = &candidate
            .content
            .as_ref()
            .expect("content")
            .parts
            .as_ref()
            .expect("parts")[0];
        assert_eq!(
            part.function_call.as_ref().unwrap().name.as_deref(),
            Some("search")
        );
        // The signature must decode (wire tolerance): a part carrying
        // one is a covered shape, not an accident. It is intentionally
        // not forwarded — the single-turn projection has no replay turn
        // to echo it on.
        assert_eq!(
            part.thought_signature.as_ref().and_then(|v| v.as_str()),
            Some("sig"),
            "thoughtSignature must survive decoding"
        );
    }

    #[test]
    fn scrub_drops_fingerprints_and_orders_auth_last() {
        use http::header::HeaderValue;
        let mut headers = HeaderMap::new();
        for (k, v) in [
            ("content-type", "application/json"),
            ("x-forwarded-for", "1.2.3.4"),
            ("sec-ch-ua", "x"),
            ("x-stainless-lang", "js"),
            ("http-referer", "https://evil/"),
            ("authorization", "Bearer t"),
            ("x-aisix-request-id", "r"),
        ] {
            headers.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        scrub_proxy_headers(&mut headers);
        for gone in [
            "x-forwarded-for",
            "sec-ch-ua",
            "x-stainless-lang",
            "http-referer",
        ] {
            assert!(!headers.contains_key(gone), "{gone} must be scrubbed");
        }
        assert_eq!(headers["x-aisix-request-id"], "r");
        assert_eq!(headers["accept-encoding"], "gzip, deflate, br");
        let keys: Vec<String> = headers.keys().map(|k| k.as_str().to_string()).collect();
        assert_eq!(
            keys.last().map(String::as_str),
            Some("authorization"),
            "authorization must land last, got {keys:?}"
        );
    }
}
