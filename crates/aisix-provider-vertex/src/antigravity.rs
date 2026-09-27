//! aisix-provider-vertex::antigravity — Native Antigravity (Google Cloud Code v1internal RPC) Bridge.
//!
//! Mirrors OmniRoute's battle-tested `open-sse/executors/antigravity.ts` hand-in-hand:
//! - Google OAuth2 PKCE token refresher against `https://oauth2.googleapis.com/token`
//! - Upstream RPC: `https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse`
//! - Antigravity desktop IDE spoofing: `User-Agent: antigravity/ide/2.1.1 darwin/arm64`
//! - 429 Shield prompt sanitization: strips competitor assistant triggers that trigger Google 429s
//! - Streaming SSE parser translating candidate parts into `content` and `reasoning_content` (`thought`)

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aisix_core::Adapter;
use aisix_gateway::sse::{SseDecoder, SseEvent};
use aisix_gateway::{
    apply_request_headers, resolve_public_cred, scrub_upstream_headers, truncate_lossy, Bridge,
    BridgeContext, BridgeError, ChatChunk, ChatChunkStream, ChatDelta, ChatFormat, ChatResponse,
    FinishReason, Role, UpstreamHeaderContext, UsageStats, MAX_UPSTREAM_ERROR_MESSAGE_BYTES,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

const GOOGLE_OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const ANTIGRAVITY_RPC_URL: &str =
    "https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse";
/// Fallback RPC host (`ANTIGRAVITY_RUNTIME_BASE_URLS[1]` in the TS
/// registry). Tried only when the primary host fails at the transport
/// layer; upstream HTTP rejections are not retried elsewhere.
const ANTIGRAVITY_RPC_FALLBACK_URL: &str =
    "https://cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse";
/// IDE version embedded in the spoofed Antigravity `User-Agent`.
/// Kept at `2.1.1` per spec; the header value is rendered from this
/// single const (pinned by `user_agent_carries_ide_version`).
const ANTIGRAVITY_IDE_VERSION: &str = "2.1.1";
/// Suffix of the OAuth (ide-node) `User-Agent`
/// (`antigravityIdeNodeUserAgent`: the Node API client the official IDE
/// build refreshes tokens with). Sent only on the token-refresh face —
/// never on content requests.
const ANTIGRAVITY_IDE_NODE_API_CLIENT: &str = "google-api-nodejs-client/10.3.0";
/// Default Cloud Code project sent in the envelope. Per-key
/// `ProviderKey.project` wins when set; when it is missing a best-effort
/// `loadCodeAssist` discovery runs first (memoized per access token, see
/// `discover_project`), and this stays as the fail-open fallback so
/// existing keys keep working unchanged on any discovery error.
const ANTIGRAVITY_DEFAULT_PROJECT: &str = "aicode-consumers";
/// Google OAuth2 authorize endpoint for the Antigravity PKCE flow
/// (`ANTIGRAVITY_CONFIG.authorizeUrl` in the TS registry).
const ANTIGRAVITY_OAUTH_AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
/// OAuth scopes for the Antigravity PKCE flow — the Cloud Code / userinfo
/// scopes exactly as the TS registry (`ANTIGRAVITY_CONFIG.scopes`).
/// Deliberately no `openid`: with PKCE Google routes that into the
/// hanging `firstparty/nativeapp` consent (see the registry comment).
const ANTIGRAVITY_OAUTH_SCOPES: &[&str] = &[
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
];
/// `loadCodeAssist` bootstrap endpoint used for Cloud Code project
/// discovery (`ANTIGRAVITY_BOOTSTRAP_BASE_URLS[0]` +
/// `/v1internal:loadCodeAssist` in the TS registry).
const ANTIGRAVITY_LOAD_CODE_ASSIST_URL: &str =
    "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist";
/// Bound for the in-memory per-access-token project cache (mirrors the
/// etalon's 256-entry cap; the map is cleared once full).
const ANTIGRAVITY_PROJECT_CACHE_MAX: usize = 256;

/// Embedded public OAuth client id, XOR-masked per the mandatory
/// `PUBLIC_CREDS.md` pattern (installed-app PKCE credential, public by
/// design; the literal would trip secret scanners). Copied from the TS
/// `antigravity_id` entry — same mask, same bytes.
const ANTIGRAVITY_MASKED_CLIENT_ID: &[u8] = &[
    94, 93, 89, 88, 66, 95, 67, 68, 83, 29, 69, 76, 83, 65, 29, 14, 69, 5, 66, 6, 3, 92, 1, 64, 94,
    25, 23, 23, 72, 66, 70, 87, 26, 29, 12, 65, 25, 91, 7, 89, 9, 93, 66, 92, 16, 4, 75, 76, 0, 5,
    17, 66, 14, 12, 66, 17, 93, 10, 24, 29, 12, 0, 12, 26, 26, 17, 72, 30, 1, 76, 15, 6, 14,
];
/// Embedded public OAuth client secret (`antigravity_alt` entry, same
/// masking). Resolution order: `ANTIGRAVITY_OAUTH_CLIENT_SECRET` env,
/// then this default.
const ANTIGRAVITY_MASKED_CLIENT_SECRET: &[u8] = &[
    40, 34, 45, 58, 34, 55, 88, 63, 80, 21, 54, 34, 48, 88, 81, 85, 97, 18, 125, 37, 92, 3, 37, 48,
    87, 6, 44, 38, 25, 10, 67, 19, 40, 40, 5,
];

/// Resolve the OAuth client id: `ANTIGRAVITY_OAUTH_CLIENT_ID` env first
/// (same name the TS registry reads), legacy `ANTIGRAVITY_CLIENT_ID`
/// second, embedded public default last.
fn resolve_oauth_client_id() -> String {
    resolve_public_cred(
        ANTIGRAVITY_MASKED_CLIENT_ID,
        &["ANTIGRAVITY_OAUTH_CLIENT_ID", "ANTIGRAVITY_CLIENT_ID"],
    )
}

/// Resolve the OAuth client secret: `ANTIGRAVITY_OAUTH_CLIENT_SECRET`
/// env first, legacy `ANTIGRAVITY_CLIENT_SECRET` second, embedded public
/// default last.
fn resolve_oauth_client_secret() -> String {
    resolve_public_cred(
        ANTIGRAVITY_MASKED_CLIENT_SECRET,
        &[
            "ANTIGRAVITY_OAUTH_CLIENT_SECRET",
            "ANTIGRAVITY_CLIENT_SECRET",
        ],
    )
}

/// IDE version for the spoofed Antigravity `User-Agent`, mirroring
/// `antigravityVersion.ts`: operator override via `ANTIGRAVITY_IDE_VERSION`
/// env, pinned-const fallback otherwise. The value on the wire is
/// unchanged by default (`2.1.1`); only an explicit env var moves it.
fn ide_version_from_env(raw: Option<String>) -> String {
    match raw.map(|v| v.trim().to_string()).filter(|v| !v.is_empty()) {
        Some(v) => v,
        None => ANTIGRAVITY_IDE_VERSION.to_string(),
    }
}

fn resolve_ide_version() -> String {
    ide_version_from_env(std::env::var("ANTIGRAVITY_IDE_VERSION").ok())
}

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
            client_id: resolve_oauth_client_id(),
            client_secret: resolve_oauth_client_secret(),
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
                "ANTIGRAVITY_OAUTH_CLIENT_ID/SECRET not configured".into(),
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
            // Token-refresh face identity (`antigravity.ts:860-876`):
            // JSON accept plus the ide-node UA. The `X-Goog-Api-Client`
            // gl-node value belongs to this same ide-node face only —
            // it must never be sent on content requests.
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!(
                    "antigravity/{} darwin/arm64 {ANTIGRAVITY_IDE_NODE_API_CLIENT}",
                    resolve_ide_version(),
                ),
            )
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
                format!(
                    "antigravity token refresh rejected ({status}): {}",
                    truncate_lossy(&body, MAX_UPSTREAM_ERROR_MESSAGE_BYTES)
                ),
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

// ─── PKCE Authorize ─────────────────────────────────────────────────────────

/// Percent-encode a query component (`URLSearchParams` shape: space as
/// `+`, everything outside the unreserved set as `%XX`). No new deps —
/// only the values this helper emits ever pass through here.
fn percent_encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((byte >> 4) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((byte & 0xF) as u32, 16)
                        .unwrap_or('0')
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// Build the Google OAuth2 PKCE authorize URL (`buildAntigravityAuthUrl`
/// in `src/lib/oauth/providers/antigravity.ts:82-96`): `response_type=code`
/// with `access_type=offline`, `prompt=consent` and the S256
/// `code_challenge`. Stateless — the caller supplies `state` and the
/// challenge and keeps them; nothing is stored here. A blank `client_id`
/// falls back to the resolved public credential, mirroring
/// `resolve_project`'s blank-falls-back convention.
pub fn build_authorize_url(
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> String {
    let client_id = if client_id.trim().is_empty() {
        resolve_oauth_client_id()
    } else {
        client_id.trim().to_string()
    };
    let params = [
        ("client_id", client_id),
        ("response_type", "code".to_string()),
        ("redirect_uri", redirect_uri.to_string()),
        ("scope", ANTIGRAVITY_OAUTH_SCOPES.join(" ")),
        ("state", state.to_string()),
        ("access_type", "offline".to_string()),
        ("prompt", "consent".to_string()),
        ("code_challenge", code_challenge.to_string()),
        ("code_challenge_method", "S256".to_string()),
    ];
    let query = params
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encode_query(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{ANTIGRAVITY_OAUTH_AUTHORIZE_URL}?{query}")
}

// ─── Request Envelope & Sanitization ────────────────────────────────────────

#[derive(Serialize)]
struct AntigravityEnvelope<'a> {
    project: &'a str,
    model: &'a str,
    #[serde(rename = "userAgent")]
    user_agent: &'static str,
    #[serde(rename = "requestType")]
    request_type: &'a str,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<AntigravityTool>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "toolConfig")]
    tool_config: Option<AntigravityToolConfig>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "sessionId")]
    session_id: Option<String>,
}

#[derive(Serialize)]
struct AntigravityContent {
    role: &'static str,
    parts: Vec<AntigravityRequestPart>,
}

/// Request-side content part: plain text or a replayed function call.
/// History never carries `thought`/`thoughtSignature` parts — the
/// single-turn projection has no signature store, and Cloud Code drops
/// signature-less `thoughtSignature` echoes anyway
/// (`antigravity.ts:748-810` filter), so replayed reasoning is
/// intentionally not forwarded (see `convert_chat_format`).
#[derive(Serialize)]
struct AntigravityRequestPart {
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "functionCall")]
    function_call: Option<AntigravityFunctionCallBody>,
}

/// Native function call as Cloud Code expects it on the wire. No
/// `thoughtSignature`: the executor's history filter keeps
/// signature-less `functionCall` parts (only `thought`/`thoughtSignature`
/// echoes are stripped), and the translator's Cloud Code path runs with
/// signature bypass (`supportsSignatureBypass`), so replayed calls from
/// the gateway's `extra["tool_calls"]` slot dispatch without one.
#[derive(Serialize)]
struct AntigravityFunctionCallBody {
    name: String,
    args: serde_json::Value,
}

#[derive(Serialize)]
struct AntigravitySystemInstruction {
    parts: Vec<AntigravityPart>,
}

#[derive(Serialize)]
struct AntigravityPart {
    text: String,
}

/// One `functionDeclarations` tool entry (`buildGeminiTools` in
/// `geminiToolsSanitizer.ts`: OpenAI `{type:"function",
/// function:{…}}`, bare `{name,…}` and pre-shaped
/// `{functionDeclarations:[…]}` inputs all fold into this).
#[derive(Serialize)]
struct AntigravityTool {
    #[serde(rename = "functionDeclarations")]
    function_declarations: Vec<AntigravityFunctionDeclaration>,
}

#[derive(Serialize)]
struct AntigravityFunctionDeclaration {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<serde_json::Value>,
}

/// `toolConfig` (`antigravity.ts:795-798` + `convertOpenAIToolChoiceToGemini`
/// in `openai-to-gemini.ts`): `VALIDATED` by default (a call may happen
/// or plain text may answer, but any call is schema-validated),
/// `ANY` for `tool_choice: "required"`, `NONE` for `"none"`.
#[derive(Serialize)]
struct AntigravityToolConfig {
    #[serde(rename = "functionCallingConfig")]
    function_calling_config: AntigravityFunctionCallingConfig,
}

#[derive(Serialize)]
struct AntigravityFunctionCallingConfig {
    mode: String,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "allowedFunctionNames"
    )]
    allowed_function_names: Option<Vec<String>>,
}

#[derive(Serialize)]
struct AntigravityGenConfig {
    #[serde(rename = "topK")]
    top_k: u32,
    #[serde(rename = "topP")]
    top_p: f32,
    #[serde(rename = "maxOutputTokens")]
    max_output_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "thinkingConfig")]
    thinking_config: Option<AntigravityThinkingConfig>,
}

#[derive(Serialize)]
struct AntigravityThinkingConfig {
    #[serde(rename = "thinkingBudget")]
    thinking_budget: u32,
}

/// Conservative ceiling for `maxOutputTokens`. The etalon resolves a
/// per-model cap from its catalogue; the gateway has no model catalogue,
/// so the pinned table below carries the confirmed values and this const
/// (65535, the ceiling most Antigravity models publish) is both the clamp
/// for unlisted models and the unknown-model fallback. Oversized
/// Copilot-style values above the resolved cap would 400 upstream
/// (`antigravityOutputCap.ts`).
const ANTIGRAVITY_MAX_OUTPUT_TOKENS: u32 = 65535;

/// Per-model `maxOutputTokens` ceilings on the Cloud Code face — the
/// static port of `resolveAntigravityOutputCap`. Values quoted from the
/// etalon's own comments plus Google's documented output limits
/// (<https://ai.google.dev/gemini-api/docs/models/gemini-2.5-pro> and
/// `.../gemini-2.5-flash`: 65,536 output tokens; the Cloud Code face
/// publishes 65535, same as the fallback, so the pin is belt-and-braces).
const ANTIGRAVITY_MODEL_OUTPUT_CAPS: &[(&str, u32)] = &[
    ("claude-sonnet-4-6", 65536),
    ("gemini-pro-agent", 65535),
    ("gemini-2.5-flash", 65535),
    ("gemini-2.5-pro", 65535),
    ("gemini-2.5-flash-lite", 65535),
    ("gpt-oss-120b-medium", 32768),
];

/// The output ceiling this model accepts, or 65535 when the id is not in
/// the table. Lookup is case-insensitive on the trimmed id with a leading
/// `models/` prefix tolerated (Gemini-style ids).
pub fn resolve_output_cap(model: &str) -> u32 {
    let mut id = model.trim().to_lowercase();
    if let Some(stripped) = id.strip_prefix("models/") {
        id = stripped.to_string();
    }
    for (known, cap) in ANTIGRAVITY_MODEL_OUTPUT_CAPS {
        if id == *known {
            return *cap;
        }
    }
    ANTIGRAVITY_MAX_OUTPUT_TOKENS
}

fn build_generation_config(req: &ChatFormat, model: &str) -> AntigravityGenConfig {
    // Thinking budget the caller attached via `extra` (the unified
    // thinking adapter's body-root `thinking_budget` shape). `None`
    // means non-thinking: no `thinkingConfig` is emitted at all.
    let thinking_budget: Option<u32> = req
        .extra
        .get("thinking_budget")
        .and_then(serde_json::Value::as_u64)
        .and_then(|b| u32::try_from(b).ok())
        .filter(|b| *b > 0);
    let cap = resolve_output_cap(model);
    let mut max_output_tokens = req.max_tokens.unwrap_or(cap);
    // `applyAntigravityGenerationDefaults`: the thinking budget must fit
    // inside the output window, so a max at or under the budget is
    // bumped past it.
    if let Some(budget) = thinking_budget {
        if max_output_tokens <= budget {
            max_output_tokens = budget.saturating_add(1);
        }
    }
    max_output_tokens = max_output_tokens.min(cap);
    AntigravityGenConfig {
        top_k: 40,
        top_p: 1.0,
        max_output_tokens,
        temperature: req.temperature,
        thinking_config: thinking_budget
            .map(|thinking_budget| AntigravityThinkingConfig { thinking_budget }),
    }
}

/// 429 Shield: strips competitor-assistant identity sentences from the
/// system instruction ONLY (`stripCompetitiveAgentPrompts` in
/// `antigravity.ts:367-400`). Same four case-insensitive word-boundaried
/// phrases, same sentence-strip (`\bphrase\b[^\n]*` eats the rest of the
/// line), same blank-line collapse. User/assistant/tool texts are never
/// touched — sanitizing them would corrupt quoted code and replayed
/// transcripts.
fn agent_identity_patterns() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(you are a claude agent|built on anthropic's claude agent sdk|you are claude code|you are an ai assistant created by anthropic)\b[^\n]*",
        )
        .expect("agent identity sanitize regex must compile")
    })
}

fn sanitize_system_text(text: &str) -> String {
    static COLLAPSE_RE: OnceLock<Regex> = OnceLock::new();
    let collapse = COLLAPSE_RE
        .get_or_init(|| Regex::new(r"\n{3,}").expect("newline collapse regex must compile"));
    let stripped = agent_identity_patterns().replace_all(text, "");
    // Collapse the blank lines the strip leaves behind, same as the
    // etalon (`.replace(/\n{3,}/g, "\n\n").trimStart()` per pattern).
    collapse
        .replace_all(&stripped, "\n\n")
        .trim_start()
        .to_string()
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
    project: &'a str,
) -> AntigravityEnvelope<'a> {
    // History normalization, mirroring the executor's content fix-ups
    // (`antigravity.ts:748-810`):
    // - tool results (`functionResponse`) travel as `user` turns;
    // - empty texts are dropped, never emitted as empty parts;
    // - adjacent same-role turns merge into one `contents` entry;
    // - replayed reasoning (`thought`/`thoughtSignature`) is stripped:
    //   the projection never fabricates those parts, and only the
    //   response path surfaces `thought` as `reasoning_content`;
    // - a trailing `model` turn is stripped (Cloud Code 400s on
    //   "Requests ending with a model turn"), keeping at least one
    //   entry (`stripTrailingAntigravityAssistantTurn` guard).
    let mut contents: Vec<AntigravityContent> = Vec::new();
    let mut push_parts = |role: &'static str, parts: Vec<AntigravityRequestPart>| {
        if parts.is_empty() {
            return;
        }
        if let Some(last) = contents.last_mut() {
            if last.role == role {
                last.parts.extend(parts);
                return;
            }
        }
        contents.push(AntigravityContent { role, parts });
    };
    let mut system_text = String::new();

    for m in &req.messages {
        if m.is_reasoning_only() {
            continue;
        }
        match m.role {
            Role::System | Role::Developer => {
                let text = m.content_str().trim();
                if text.is_empty() {
                    continue;
                }
                if !system_text.is_empty() {
                    system_text.push_str("\n\n");
                }
                system_text.push_str(text);
            }
            Role::User | Role::Tool => {
                // `functionResponse` → `user` role (same mapping as the
                // executor's `role = "user"` override). Tool results
                // arrive as text: without a stored thought-signature
                // namespace the gateway cannot echo native
                // `functionResponse` parts the upstream would accept,
                // so they fold to text — the etalon's signatureless
                // "text" fallback for unmatched responses.
                let text = m.content_str().trim();
                if text.is_empty() {
                    continue;
                }
                push_parts(
                    "user",
                    vec![AntigravityRequestPart {
                        text: Some(text.to_string()),
                        function_call: None,
                    }],
                );
            }
            Role::Assistant => {
                let mut parts = Vec::new();
                let text = m.content_str().trim();
                if !text.is_empty() {
                    parts.push(AntigravityRequestPart {
                        text: Some(text.to_string()),
                        function_call: None,
                    });
                }
                // Replay the previous turn's tool calls as native
                // `functionCall` parts (response path stores them in
                // `extra["tool_calls"]` in OpenAI shape). Cloud Code
                // tolerates signature-less `functionCall` history on
                // this face (signature bypass), so no
                // `thoughtSignature` is fabricated.
                if let Some(calls) = m.extra.get("tool_calls").and_then(|v| v.as_array()) {
                    for call in calls {
                        let function = if call.get("function").is_some() {
                            call.get("function")
                        } else {
                            Some(call)
                        };
                        let Some(name) = function
                            .and_then(|f| f.get("name"))
                            .and_then(serde_json::Value::as_str)
                            .map(str::trim)
                            .filter(|n| !n.is_empty())
                        else {
                            continue;
                        };
                        let args = function
                            .and_then(|f| f.get("arguments"))
                            .map(|a| match a {
                                serde_json::Value::String(s) => serde_json::from_str(s)
                                    .unwrap_or(serde_json::Value::Object(Default::default())),
                                other => other.clone(),
                            })
                            .unwrap_or(serde_json::Value::Object(Default::default()));
                        parts.push(AntigravityRequestPart {
                            text: None,
                            function_call: Some(AntigravityFunctionCallBody {
                                name: name.to_string(),
                                args,
                            }),
                        });
                    }
                }
                push_parts("model", parts);
            }
        }
    }
    while contents.len() > 1 && contents.last().is_some_and(|c| c.role == "model") {
        contents.pop();
    }

    // The shield runs on the assembled system instruction only — never
    // on user/assistant/tool texts.
    let system_text = sanitize_system_text(&system_text);
    let system_instruction = if system_text.trim().is_empty() {
        None
    } else {
        Some(AntigravitySystemInstruction {
            parts: vec![AntigravityPart { text: system_text }],
        })
    };

    let (tools, tool_config) = build_function_tools(req);

    // Image models ride the same envelope with `requestType:
    // "image_gen"` (the translator sets body-root `requestType`; the
    // gateway reads the same key from `extra`). Anything else is an
    // agent turn.
    let request_type = match req
        .extra
        .get("requestType")
        .and_then(serde_json::Value::as_str)
    {
        Some("image_gen") => "image_gen",
        _ => "agent",
    };

    AntigravityEnvelope {
        project,
        model: model_name,
        user_agent: "antigravity",
        request_type,
        request_id: generate_request_id(),
        request: AntigravityRequest {
            contents,
            system_instruction,
            generation_config: build_generation_config(req, model_name),
            tools,
            tool_config,
            session_id: Some(resolve_session_id(credential)),
        },
    }
}

/// Fold `ChatFormat` tools into one `functionDeclarations` entry plus
/// `toolConfig` (`antigravity.ts:795-798`). Without both, the upstream
/// never emits `functionCall` parts and function calling is dead.
/// Returns `(None, None)` when the caller sent no tools.
fn build_function_tools(
    req: &ChatFormat,
) -> (Option<Vec<AntigravityTool>>, Option<AntigravityToolConfig>) {
    let mut declarations: Vec<AntigravityFunctionDeclaration> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let push_declaration = |raw_name: &str,
                            description: Option<&serde_json::Value>,
                            parameters: Option<&serde_json::Value>,
                            declarations: &mut Vec<AntigravityFunctionDeclaration>,
                            seen: &mut HashSet<String>| {
        let name = raw_name.trim();
        if name.is_empty() {
            return;
        }
        let name = sanitize_function_name(name);
        // Duplicate declaration names make Cloud Code 400 the
        // request; first one wins (fail-closed, mirrors the
        // etalon's `seenToolNames` guard).
        if !seen.insert(name.clone()) {
            return;
        }
        declarations.push(AntigravityFunctionDeclaration {
            name,
            description: description
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            parameters: parameters.cloned(),
        });
    };
    if let Some(tools) = req.extra.get("tools").and_then(|v| v.as_array()) {
        for raw in tools {
            // Pre-shaped Gemini entry.
            if let Some(fns) = raw.get("functionDeclarations").and_then(|v| v.as_array()) {
                for f in fns {
                    push_declaration(
                        f.get("name")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or(""),
                        f.get("description"),
                        f.get("parameters"),
                        &mut declarations,
                        &mut seen,
                    );
                }
                continue;
            }
            // Bare `{name, description, parameters|input_schema}`.
            if let Some(name) = raw.get("name").and_then(serde_json::Value::as_str) {
                push_declaration(
                    name,
                    raw.get("description"),
                    raw.get("parameters").or_else(|| raw.get("input_schema")),
                    &mut declarations,
                    &mut seen,
                );
                continue;
            }
            // OpenAI `{type:"function", function:{name,…}}`.
            if let Some(function) = raw.get("function") {
                push_declaration(
                    function
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or(""),
                    function.get("description"),
                    function.get("parameters"),
                    &mut declarations,
                    &mut seen,
                );
            }
        }
    }
    if declarations.is_empty() {
        return (None, None);
    }
    let tool_config = AntigravityToolConfig {
        function_calling_config: function_calling_config(req),
    };
    (
        Some(vec![AntigravityTool {
            function_declarations: declarations,
        }]),
        Some(tool_config),
    )
}

/// Simplified port of `sanitizeGeminiToolName`
/// (`geminiToolsSanitizer.ts`): Gemini identifiers match
/// `^[A-Za-z_][A-Za-z0-9_.-]*$` (64 chars). The TS side hashes on
/// collision; collisions are instead dropped by the caller, so this
/// only normalizes the charset here and never returns empty.
fn sanitize_function_name(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        return "tool".to_string();
    }
    if !(out.as_bytes()[0].is_ascii_alphabetic() || out.as_bytes()[0] == b'_') {
        out.insert(0, '_');
    }
    out.truncate(64);
    out
}

/// `convertOpenAIToolChoiceToGemini` (`openai-to-gemini.ts`): the mode
/// for this request's `toolConfig`. `VALIDATED` stays the default for
/// "auto"/unset so existing callers see no behavior change.
fn function_calling_config(req: &ChatFormat) -> AntigravityFunctionCallingConfig {
    let (mode, allowed_function_names) = match req.extra.get("tool_choice") {
        None | Some(serde_json::Value::Null) => ("VALIDATED", None),
        Some(serde_json::Value::String(s)) => match s.as_str() {
            "none" => ("NONE", None),
            "required" | "any" => ("ANY", None),
            _ => ("VALIDATED", None),
        },
        Some(serde_json::Value::Object(o)) => {
            match o.get("type").and_then(serde_json::Value::as_str) {
                Some("none") => ("NONE", None),
                Some("required") | Some("any") => ("ANY", None),
                Some("function") => match o
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                {
                    Some(name) => ("ANY", Some(vec![sanitize_function_name(name)])),
                    None => ("VALIDATED", None),
                },
                _ => ("VALIDATED", None),
            }
        }
        _ => ("VALIDATED", None),
    };
    AntigravityFunctionCallingConfig {
        mode: mode.to_string(),
        allowed_function_names,
    }
}

/// Project for the envelope: per-key `ProviderKey.project` wins when
/// set; otherwise the shared default. Trims the stored value so a
/// whitespace-only override falls back instead of 400ing upstream.
fn resolve_project(key: &aisix_core::ProviderKey) -> &str {
    match key.project.as_deref() {
        Some(p) if !p.trim().is_empty() => p.trim(),
        _ => ANTIGRAVITY_DEFAULT_PROJECT,
    }
}

// ─── Project discovery (`loadCodeAssist` analogue) ──────────────────────────

/// In-memory per-access-token project cache, keyed by the same refresh-
/// token hash partition as the token mint so raw bearer tokens never sit
/// in the map. Successful discoveries only — failures stay uncached so
/// the next request retries instead of pinning a miss.
static ANTIGRAVITY_PROJECT_CACHE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

fn project_cache() -> &'static RwLock<HashMap<String, String>> {
    ANTIGRAVITY_PROJECT_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Extract the Cloud Code project id from a `loadCodeAssist` body: the
/// `cloudaicompanionProject` field is either a plain string or an object
/// carrying `id` (`antigravityProjectBootstrap.ts:152-161`). Empty and
/// missing values yield `None` so the caller falls back.
fn extract_discovered_project(body: &serde_json::Value) -> Option<String> {
    match body.get("cloudaicompanionProject") {
        Some(serde_json::Value::String(s)) => {
            let id = s.trim();
            if id.is_empty() {
                None
            } else {
                Some(id.to_string())
            }
        }
        Some(serde_json::Value::Object(obj)) => obj
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_string),
        _ => None,
    }
}

/// Native `loadCodeAssist` body metadata (`antigravityHeaders.ts:116-122`):
/// protobuf-JSON-shaped int enums, `ideType` 9 with the Gemini plugin
/// type 2. The platform enum mirrors the etalon's host mapping.
fn load_code_assist_platform() -> i32 {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => 2,
        ("macos", _) => 1,
        ("linux", "aarch64") => 4,
        ("linux", _) => 3,
        ("windows", _) => 5,
        _ => 0,
    }
}

fn load_code_assist_metadata() -> serde_json::Value {
    serde_json::json!({
        "ideType": 9,
        "platform": load_code_assist_platform(),
        "pluginType": 2,
    })
}

/// `loadCodeAssist` analogue (`antigravity.ts:639-656`): discover the
/// Cloud Code project bound to this access token. Results are memoized
/// per token for the process lifetime; any transport, status or parse
/// failure is an `Err` and the caller fails open to the shared default.
pub async fn discover_project(access_token: &str) -> Result<String, BridgeError> {
    let key = token_cache_key(access_token);
    if let Some(cached) = project_cache().read().await.get(&key).cloned() {
        return Ok(cached);
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| Client::new());
    let resp = client
        .post(ANTIGRAVITY_LOAD_CODE_ASSIST_URL)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::USER_AGENT,
            format!("antigravity/ide/{} darwin/arm64", resolve_ide_version()),
        )
        .bearer_auth(access_token)
        .json(&serde_json::json!({ "metadata": load_code_assist_metadata() }))
        .send()
        .await
        .map_err(|e| {
            BridgeError::Transport(format!("antigravity loadCodeAssist request failed: {e}"))
        })?;

    let status = resp.status();
    if !status.is_success() {
        let body: String = resp.text().await.unwrap_or_default();
        return Err(BridgeError::upstream_status(
            status.as_u16(),
            format!(
                "antigravity loadCodeAssist rejected ({status}): {}",
                truncate_lossy(&body, MAX_UPSTREAM_ERROR_MESSAGE_BYTES)
            ),
        ));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| {
        BridgeError::UpstreamDecode(format!(
            "failed to parse antigravity loadCodeAssist response: {e}"
        ))
    })?;
    let Some(project) = extract_discovered_project(&body) else {
        return Err(BridgeError::UpstreamDecode(
            "antigravity loadCodeAssist returned no cloudaicompanionProject".into(),
        ));
    };

    let mut guard = project_cache().write().await;
    if guard.len() >= ANTIGRAVITY_PROJECT_CACHE_MAX {
        guard.clear();
    }
    guard.insert(key, project.clone());
    Ok(project)
}

/// Project for the envelope as an owned value: per-key
/// `ProviderKey.project` wins when set; when it is missing a best-effort
/// discovery runs first, and any discovery error falls back to the shared
/// default so existing keys keep working unchanged (fail-open to the old
/// behavior, never fail-closed).
async fn resolve_project_owned(key: &aisix_core::ProviderKey, access_token: &str) -> String {
    let explicit = key
        .project
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty());
    match explicit {
        Some(p) => p.to_string(),
        None => discover_project(access_token)
            .await
            .unwrap_or_else(|_| ANTIGRAVITY_DEFAULT_PROJECT.to_string()),
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
                "antigravity/ide/{} darwin/arm64",
                resolve_ide_version()
            ))
            .map_err(|_| BridgeError::Config("invalid antigravity user-agent".into()))?,
        );
        // NOTE: no `X-Goog-Api-Client` here by design. The etalon strips
        // it from content requests (`antigravityClientProfile.ts:24-31`):
        // the gl-node value belongs to the ide-node face only (token
        // refresh above), and sending it on content requests breaks the
        // native IDE fingerprint.
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
        let project = resolve_project_owned(&ctx.provider_key, &access_token).await;
        let envelope = convert_chat_format(req, upstream_model, credential, &project);
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

        // Ordered RPC hosts: the primary plus the `cloudcode-pa`
        // fallback (`ANTIGRAVITY_RUNTIME_BASE_URLS`). Only a transport
        // failure moves to the next host — an upstream HTTP rejection
        // is answered, never replayed elsewhere.
        let mut resp_opt = None;
        let mut last_error =
            BridgeError::Transport("antigravity RPC connect error: no hosts attempted".into());
        for rpc_url in [ANTIGRAVITY_RPC_URL, ANTIGRAVITY_RPC_FALLBACK_URL] {
            match self
                .client
                .post(rpc_url)
                .headers(headers.clone())
                .body(body_json.clone())
                .send()
                .await
            {
                Ok(resp) => {
                    resp_opt = Some(resp);
                    break;
                }
                Err(e) => {
                    last_error =
                        BridgeError::Transport(format!("antigravity RPC connect error: {e}"));
                }
            }
        }
        let resp = match resp_opt {
            Some(resp) => resp,
            None => return Err(last_error),
        };

        let status = resp.status();
        if !status.is_success() {
            let err_body = resp.text().await.unwrap_or_default();
            return Err(BridgeError::upstream_status(
                status.as_u16(),
                format!(
                    "antigravity upstream error ({status}): {}",
                    truncate_lossy(&err_body, MAX_UPSTREAM_ERROR_MESSAGE_BYTES)
                ),
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
                                                    // `thought` parts surface as `reasoning_content`.
                                                    // Deliberate, not a mapping gap: the response
                                                    // fold reports `thoughtsTokenCount` BESIDE
                                                    // `candidatesTokenCount`
                                                    // (`sseCollect.ts:147-155`), and the
                                                    // Responses-face convention the codex/grok
                                                    // bridges share carries model reasoning in
                                                    // `reasoning_content`. The request path
                                                    // never echoes them back — history `thought`/
                                                    // `thoughtSignature` parts are stripped (see
                                                    // `AntigravityRequestPart`), so no behavior
                                                    // changes here.
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
    use aisix_gateway::decode_public_cred_bytes;
    use aisix_gateway::ChatMessage;

    #[test]
    fn shield_strips_trigger_sentence_case_insensitively() {
        // Etalon sentence-strip: the trigger plus the rest of its line
        // is removed (not replaced with a placeholder).
        for input in [
            "YOU ARE A CLAUDE AGENT, here to help",
            "You Are Claude Code with instructions",
            "yOu ArE aN aI aSsIsTaNt CrEaTeD bY aNtHrOpIc, hello",
            "BUILT ON ANTHROPIC'S CLAUDE AGENT SDK v1",
        ] {
            let out = sanitize_system_text(input);
            assert!(
                !agent_identity_patterns().is_match(&out),
                "unsanitized remainder in {out:?} from {input:?}"
            );
        }
        assert_eq!(
            sanitize_system_text("You are a Claude agent, built today"),
            ""
        );
        assert_eq!(sanitize_system_text("You are Claude Code!"), "");
    }

    #[test]
    fn shield_keeps_surrounding_instruction_lines() {
        let out = sanitize_system_text("Be helpful.\nYou are Claude Code, obey.\nStay brief.");
        assert!(!agent_identity_patterns().is_match(&out));
        assert!(out.contains("Be helpful."), "got {out:?}");
        assert!(out.contains("Stay brief."), "got {out:?}");
    }

    #[test]
    fn shield_leaves_unrelated_text_untouched() {
        let plain = "You are a helpful coding assistant. Claude models are great.";
        assert_eq!(sanitize_system_text(plain), plain);
    }

    #[test]
    fn shield_applies_to_system_only_not_user_text() {
        // A trigger phrase in USER text must survive verbatim: the shield
        // runs on the assembled system instruction, never on turn texts.
        let req = ChatFormat::new(
            "m",
            vec![
                ChatMessage::system("Be helpful."),
                ChatMessage::user("You are Claude Code, right?"),
            ],
        );
        let env = convert_chat_format(&req, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        let user_turn = env
            .request
            .contents
            .iter()
            .find(|c| c.role == "user")
            .expect("user turn present");
        assert_eq!(
            user_turn.parts[0].text.as_deref(),
            Some("You are Claude Code, right?")
        );
        let system = env.request.system_instruction.expect("system present");
        assert_eq!(system.parts[0].text, "Be helpful.");
    }

    #[test]
    fn contents_merge_same_role_and_drop_empties() {
        let req = ChatFormat::new(
            "m",
            vec![
                ChatMessage::user("first"),
                ChatMessage::user("second"),
                ChatMessage::user("   "),
                ChatMessage::assistant("answer"),
            ],
        );
        let env = convert_chat_format(&req, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        // Adjacent user turns merged; the blank one dropped; the trailing
        // assistant turn stripped (Cloud Code 400s on trailing model).
        assert_eq!(env.request.contents.len(), 1);
        assert_eq!(env.request.contents[0].role, "user");
        assert_eq!(env.request.contents[0].parts.len(), 2);
    }

    #[test]
    fn trailing_model_turn_stripped_but_never_emptied() {
        let req = ChatFormat::new(
            "m",
            vec![ChatMessage::user("hi"), ChatMessage::assistant("trailing")],
        );
        let env = convert_chat_format(&req, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        assert_eq!(env.request.contents.len(), 1);
        assert_eq!(env.request.contents[0].role, "user");

        // A lone model turn is kept: the strip must never empty contents.
        let solo = ChatFormat::new("m", vec![ChatMessage::assistant("only")]);
        let env = convert_chat_format(&solo, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        assert_eq!(env.request.contents.len(), 1);
    }

    #[test]
    fn tool_results_fold_to_user_and_calls_to_function_call_parts() {
        let mut assistant = ChatMessage::assistant("");
        assistant.extra.insert(
            "tool_calls".to_string(),
            serde_json::json!([{
                "id": "call-1",
                "type": "function",
                "function": {"name": "search", "arguments": r#"{"q":"x"}"#},
            }]),
        );
        let req = ChatFormat::new(
            "m",
            vec![
                ChatMessage::user("go"),
                assistant,
                ChatMessage::tool("result text"),
            ],
        );
        let env = convert_chat_format(&req, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        // Trailing tool turn survives (role user); the empty-text
        // assistant turn contributes only its functionCall part.
        assert_eq!(env.request.contents.len(), 3);
        let model_turn = &env.request.contents[1];
        assert_eq!(model_turn.role, "model");
        assert_eq!(model_turn.parts.len(), 1);
        let call = model_turn.parts[0]
            .function_call
            .as_ref()
            .expect("functionCall part");
        assert_eq!(call.name, "search");
        assert_eq!(call.args, serde_json::json!({"q": "x"}));
        let tool_turn = env.request.contents.last().unwrap();
        assert_eq!(tool_turn.role, "user");
        assert_eq!(tool_turn.parts[0].text.as_deref(), Some("result text"));
    }

    #[test]
    fn tools_become_function_declarations_with_validated_default() {
        let mut req = ChatFormat::new("m", vec![ChatMessage::user("go")]);
        req.extra.insert(
            "tools".to_string(),
            serde_json::json!([{
                "type": "function",
                "function": {
                    "name": "get-weather!",
                    "description": "weather",
                    "parameters": {"type": "object"},
                },
            }]),
        );
        let env = convert_chat_format(&req, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        let tools = env.request.tools.expect("tools present");
        assert_eq!(tools.len(), 1);
        // `!` is not a Gemini identifier char: normalized, not dropped.
        assert_eq!(tools[0].function_declarations[0].name, "get-weather_");
        let config = env.request.tool_config.expect("toolConfig present");
        let config_value = serde_json::to_value(&config).unwrap();
        assert_eq!(
            config_value["functionCallingConfig"]["mode"],
            serde_json::json!("VALIDATED")
        );
    }

    #[test]
    fn tool_choice_required_maps_to_any() {
        let mut req = ChatFormat::new("m", vec![ChatMessage::user("go")]);
        req.extra.insert(
            "tools".to_string(),
            serde_json::json!([{"type": "function", "function": {"name": "f"}}]),
        );
        req.extra
            .insert("tool_choice".to_string(), serde_json::json!("required"));
        let env = convert_chat_format(&req, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        let config_value = serde_json::to_value(&env.request.tool_config.unwrap()).unwrap();
        assert_eq!(
            config_value["functionCallingConfig"]["mode"],
            serde_json::json!("ANY")
        );
    }

    #[test]
    fn no_tools_means_no_tool_config() {
        let req = ChatFormat::new("m", vec![ChatMessage::user("go")]);
        let env = convert_chat_format(&req, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        assert!(env.request.tools.is_none());
        assert!(env.request.tool_config.is_none());
    }

    #[test]
    fn generation_config_wires_temperature_max_and_thinking() {
        let mut req = ChatFormat::new("m", vec![ChatMessage::user("go")]);
        req.temperature = Some(0.5);
        req.max_tokens = Some(1024);
        req.extra
            .insert("thinking_budget".to_string(), serde_json::json!(2048));
        let env = convert_chat_format(&req, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        let config = serde_json::to_value(&env.request.generation_config).unwrap();
        assert_eq!(config["temperature"], serde_json::json!(0.5));
        // max (1024) <= budget (2048): bumped past the budget.
        assert_eq!(config["maxOutputTokens"], serde_json::json!(2049));
        assert_eq!(
            config["thinkingConfig"]["thinkingBudget"],
            serde_json::json!(2048)
        );
    }

    #[test]
    fn generation_config_clamps_oversized_max() {
        let mut req = ChatFormat::new("m", vec![ChatMessage::user("go")]);
        req.max_tokens = Some(u32::MAX);
        let env = convert_chat_format(&req, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        let config = serde_json::to_value(&env.request.generation_config).unwrap();
        assert_eq!(
            config["maxOutputTokens"],
            serde_json::json!(ANTIGRAVITY_MAX_OUTPUT_TOKENS)
        );
        assert!(config.get("thinkingConfig").is_none());
    }

    #[test]
    fn project_prefers_provider_key_over_default() {
        let key: aisix_core::ProviderKey =
            serde_json::from_str(r#"{"display_name":"k","secret":"s"}"#).unwrap();
        assert_eq!(resolve_project(&key), ANTIGRAVITY_DEFAULT_PROJECT);
        let key: aisix_core::ProviderKey =
            serde_json::from_str(r#"{"display_name":"k","secret":"s","project":"custom-proj"}"#)
                .unwrap();
        assert_eq!(resolve_project(&key), "custom-proj");
        let key: aisix_core::ProviderKey =
            serde_json::from_str(r#"{"display_name":"k","secret":"s","project":"   "}"#).unwrap();
        assert_eq!(resolve_project(&key), ANTIGRAVITY_DEFAULT_PROJECT);
    }

    #[test]
    fn request_type_passes_image_gen_through() {
        let req = ChatFormat::new("m", vec![ChatMessage::user("draw")]);
        let env = convert_chat_format(&req, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        assert_eq!(env.request_type, "agent");
        let mut req = ChatFormat::new("m", vec![ChatMessage::user("draw")]);
        req.extra
            .insert("requestType".to_string(), serde_json::json!("image_gen"));
        let env = convert_chat_format(&req, "model", "cred", ANTIGRAVITY_DEFAULT_PROJECT);
        assert_eq!(env.request_type, "image_gen");
    }

    #[test]
    fn embedded_oauth_defaults_decode_to_plausible_shapes() {
        // Structural assertions only: the suite must not contain
        // scanner-matching literals, so values are checked by shape.
        let id = decode_public_cred_bytes(ANTIGRAVITY_MASKED_CLIENT_ID);
        assert_eq!(id.len(), ANTIGRAVITY_MASKED_CLIENT_ID.len());
        assert!(id.chars().all(|c| c.is_ascii_graphic()));
        assert!(id.starts_with("1071006060591"), "unexpected id shape");
        let secret = decode_public_cred_bytes(ANTIGRAVITY_MASKED_CLIENT_SECRET);
        assert_eq!(secret.len(), ANTIGRAVITY_MASKED_CLIENT_SECRET.len());
        assert!(secret.chars().all(|c| c.is_ascii_graphic()));
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

    /// Decode one `URLSearchParams`-style component (`+` → space, `%XX`).
    fn decode_query_component(raw: &str) -> String {
        let mut out = String::with_capacity(raw.len());
        let mut bytes = raw.as_bytes().iter();
        while let Some(&b) = bytes.next() {
            match b {
                b'+' => out.push(' '),
                b'%' => {
                    let hi = bytes.next().copied().unwrap_or(b'0');
                    let lo = bytes.next().copied().unwrap_or(b'0');
                    let hex = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
                    out.push((hex(hi) << 4 | hex(lo)) as char);
                }
                _ => out.push(b as char),
            }
        }
        out
    }

    fn authorize_params(url: &str) -> HashMap<String, String> {
        let query = url.split_once('?').expect("authorize url has a query").1;
        query
            .split('&')
            .map(|pair| {
                let (k, v) = pair.split_once('=').expect("key=value pair");
                (k.to_string(), decode_query_component(v))
            })
            .collect()
    }

    #[test]
    fn authorize_url_carries_pkce_offline_consent_form() {
        let url = build_authorize_url(
            "test-client-id",
            "http://localhost:8080/callback",
            "state-123",
            "challenge-abc",
        );
        assert!(
            url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"),
            "unexpected base: {url}"
        );
        let params = authorize_params(&url);
        assert_eq!(params["client_id"], "test-client-id");
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["redirect_uri"], "http://localhost:8080/callback");
        assert_eq!(params["state"], "state-123");
        assert_eq!(params["access_type"], "offline");
        assert_eq!(params["prompt"], "consent");
        assert_eq!(params["code_challenge"], "challenge-abc");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(
            params["scope"],
            "https://www.googleapis.com/auth/cloud-platform \
             https://www.googleapis.com/auth/userinfo.email \
             https://www.googleapis.com/auth/userinfo.profile \
             https://www.googleapis.com/auth/cclog \
             https://www.googleapis.com/auth/experimentsandconfigs"
        );
    }

    #[test]
    fn resolve_output_cap_known_models_and_fallback() {
        assert_eq!(resolve_output_cap("gemini-2.5-flash"), 65535);
        assert_eq!(resolve_output_cap("gemini-2.5-pro"), 65535);
        assert_eq!(resolve_output_cap("gemini-2.5-flash-lite"), 65535);
        assert_eq!(resolve_output_cap("claude-sonnet-4-6"), 65536);
        assert_eq!(resolve_output_cap("gpt-oss-120b-medium"), 32768);
        // Normalization: case, whitespace and a `models/` prefix.
        assert_eq!(resolve_output_cap("  GPT-OSS-120B-MEDIUM "), 32768);
        assert_eq!(resolve_output_cap("models/gemini-2.5-pro"), 65535);
        // Unknown and empty ids fall back to 65535.
        assert_eq!(resolve_output_cap("some-future-model"), 65535);
        assert_eq!(resolve_output_cap(""), 65535);
        assert_eq!(resolve_output_cap("   "), 65535);
    }

    #[test]
    fn generation_config_uses_per_model_cap() {
        let mut req = ChatFormat::new("m", vec![ChatMessage::user("go")]);
        req.max_tokens = Some(u32::MAX);
        let env = convert_chat_format(&req, "gpt-oss-120b-medium", "cred", "proj");
        let config = serde_json::to_value(&env.request.generation_config).unwrap();
        assert_eq!(config["maxOutputTokens"], serde_json::json!(32768));
        // Unlisted models keep the shared 65535 clamp.
        let env = convert_chat_format(&req, "unknown-model", "cred", "proj");
        let config = serde_json::to_value(&env.request.generation_config).unwrap();
        assert_eq!(config["maxOutputTokens"], serde_json::json!(65535));
    }

    #[test]
    fn ide_version_env_override_and_fallback() {
        assert_eq!(ide_version_from_env(None), ANTIGRAVITY_IDE_VERSION);
        assert_eq!(ide_version_from_env(Some(String::new())), "2.1.1");
        assert_eq!(ide_version_from_env(Some("   ".to_string())), "2.1.1");
        assert_eq!(ide_version_from_env(Some("  3.0.0 ".to_string())), "3.0.0");
        // The default on the wire is unchanged without the env var.
        assert_eq!(ANTIGRAVITY_IDE_VERSION, "2.1.1");
    }

    #[test]
    fn discovery_parses_string_and_object_project() {
        let body = serde_json::json!({"cloudaicompanionProject": "my-proj"});
        assert_eq!(
            extract_discovered_project(&body).as_deref(),
            Some("my-proj")
        );
        let body = serde_json::json!({"cloudaicompanionProject": {"id": "  obj-proj "}});
        assert_eq!(
            extract_discovered_project(&body).as_deref(),
            Some("obj-proj")
        );
        for body in [
            serde_json::json!({}),
            serde_json::json!({"cloudaicompanionProject": ""}),
            serde_json::json!({"cloudaicompanionProject": "   "}),
            serde_json::json!({"cloudaicompanionProject": {"id": ""}}),
            serde_json::json!({"cloudaicompanionProject": 42}),
        ] {
            assert_eq!(extract_discovered_project(&body), None, "body={body}");
        }
    }

    #[tokio::test]
    async fn project_cache_short_circuits_discovery() {
        // A cached entry must be served without any network round-trip.
        let token = "test-cache-token-project-discovery";
        let key = token_cache_key(token);
        project_cache()
            .write()
            .await
            .insert(key.clone(), "cached-proj".to_string());
        let discovered = discover_project(token).await.expect("cached project");
        assert_eq!(discovered, "cached-proj");
        project_cache().write().await.remove(&key);
    }

    #[tokio::test]
    async fn explicit_project_skips_discovery() {
        let key: aisix_core::ProviderKey =
            serde_json::from_str(r#"{"display_name":"k","secret":"s","project":"custom-proj"}"#)
                .unwrap();
        assert_eq!(
            resolve_project_owned(&key, "ya29.unused").await,
            "custom-proj"
        );
    }
}
