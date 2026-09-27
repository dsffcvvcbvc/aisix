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
//! - Namespace-tool flatten/restore runs on a per-request identity map
//!   (the TS executor threads one map through `execute` the same way);
//!   cross-request continuity (`previous_response_id` turns that never
//!   re-declare tools) additionally falls back to the `mcp__`
//!   wire-name split, mirroring `resolveRequestToolIdentity`.
//! - Over-long (>64 char) flattened wire names are hash-truncated with
//!   a std-only FNV-1a suffix instead of sha256 (same `_<7hex>` shape
//!   and cap; no new dependency for one suffix).

use std::collections::{HashMap, HashSet};
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

// ─── Namespace tools ────────────────────────────────────────────────
// Ports `executors/grokCliNamespaceTools.ts` (+ the wire-name scheme
// from `translator/request/openai-responses/namespaceFlatten.ts` and
// the restore side from
// `translator/response/openai-responses/functionCallIdentity.ts` /
// `requestToolIdentity.ts` / `collaborationPlaintextMarker.ts`).
//
// Codex CLI declares MCP servers as Responses `{type: "namespace"}`
// groups; Grok Build rejects the whole request with `422
// tools[N].type: unknown variant 'namespace'`. Flatten each child
// into a function tool before send, then restore the
// `{namespace, name}` identity on the calls Grok returns.
//
// Adaptation: the bridge yields parsed [`ChatChunk`]s, not a raw
// `Response`, so restore rewrites `function.name` + stamps
// `namespace` on the chat-shape tool call instead of re-serializing
// SSE frames. Runs only on this bridge — `responses_wire` is shared
// with Codex and stays untouched.

/// Wire name for one `namespace` child
/// (`flattenNamespaceToolName`, `namespaceFlatten.ts:33-41`).
fn flatten_namespace_tool_name(ns_name: &str, leaf: &str) -> String {
    const MAX_TOOL_NAME_LEN: usize = 64;
    if ns_name.is_empty() {
        return leaf.to_string();
    }
    if leaf.contains("__") {
        return leaf.to_string();
    }
    let qualified = if ns_name.ends_with("__") {
        format!("{ns_name}{leaf}")
    } else {
        format!("{ns_name}__{leaf}")
    };
    if qualified.len() <= MAX_TOOL_NAME_LEN {
        return qualified;
    }
    // Deterministic std-only stand-in for the TS sha256 suffix (see
    // module docs): FNV-1a over the qualified name, same `_<7hex>`
    // shape and 64-char cap.
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in qualified.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let hex = format!("{hash:016x}");
    let mut cut = MAX_TOOL_NAME_LEN - 8;
    while !qualified.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}_{}", &qualified[..cut], &hex[..7])
}

/// One flattened child: `(tool, wire_name, namespace, leaf)`; `None`
/// for children Grok must never see (non-`function` types like
/// `custom`, or unnamed).
fn flatten_namespace_child(
    ns_name: &str,
    child: &Value,
) -> Option<(Value, String, String, String)> {
    let child_obj = child.as_object()?;
    if child_obj
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("function")
        != "function"
    {
        return None;
    }
    let leaf = child_obj.get("name").and_then(Value::as_str)?;
    if leaf.is_empty() {
        return None;
    }
    let wire_name = flatten_namespace_tool_name(ns_name, leaf);
    let mut flat = serde_json::Map::new();
    flat.insert("type".to_string(), Value::String("function".to_string()));
    flat.insert("name".to_string(), Value::String(wire_name.clone()));
    flat.insert(
        "parameters".to_string(),
        child_obj
            .get("parameters")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"type": "object", "properties": {}})),
    );
    for key in ["description", "strict"] {
        if let Some(value) = child_obj.get(key) {
            flat.insert(key.to_string(), value.clone());
        }
    }
    Some((
        Value::Object(flat),
        wire_name,
        ns_name.to_string(),
        leaf.to_string(),
    ))
}

/// Rename namespaced `function_call` history items to their flattened
/// wire names (`flattenNamespacedHistory`,
/// `grokCliNamespaceTools.ts:55-67`).
fn flatten_namespaced_history(input: &mut Vec<Value>) -> bool {
    let mut changed = false;
    for item in input.iter_mut() {
        let Some(obj) = item.as_object_mut() else {
            continue;
        };
        if obj.get("type").and_then(Value::as_str) != Some("function_call") {
            continue;
        }
        let namespace = obj
            .get("namespace")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let name = obj
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if namespace.is_empty() || name.is_empty() {
            continue;
        }
        obj.remove("namespace");
        obj.insert(
            "name".to_string(),
            Value::String(flatten_namespace_tool_name(&namespace, &name)),
        );
        changed = true;
    }
    changed
}

/// `flattenGrokBuildNamespaceTools`
/// (`grokCliNamespaceTools.ts:77-100`): namespace groups become flat
/// function tools, namespaced history calls are renamed to match. The
/// map is `Some` whenever a group was flattened (even one whose
/// children all dropped — mirrors the truthy TS `Map`); `None`
/// otherwise, in which case no restore runs downstream.
fn flatten_grok_build_namespace_tools(
    body: &mut Value,
) -> Option<HashMap<String, (String, String)>> {
    let obj = body.as_object_mut()?;
    let mut identity_map: Option<HashMap<String, (String, String)>> = None;
    let has_namespace = obj
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(|tools| {
            tools
                .iter()
                .any(|t| t.get("type").and_then(Value::as_str) == Some("namespace"))
        });
    if has_namespace {
        let tools = obj.get("tools").and_then(Value::as_array).cloned()?;
        let mut map = HashMap::new();
        let mut flat_tools = Vec::with_capacity(tools.len());
        for tool in &tools {
            let is_namespace = tool.get("type").and_then(Value::as_str) == Some("namespace");
            if !is_namespace {
                flat_tools.push(tool.clone());
                continue;
            }
            let ns_name = tool.get("name").and_then(Value::as_str).unwrap_or("");
            let children = tool
                .get("tools")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for child in &children {
                if let Some((flat, wire_name, ns, leaf)) = flatten_namespace_child(ns_name, child) {
                    if !ns.is_empty() {
                        map.insert(wire_name, (ns, leaf));
                    }
                    flat_tools.push(flat);
                }
            }
        }
        obj.insert("tools".to_string(), Value::Array(flat_tools));
        identity_map = Some(map);
    }
    if let Some(Value::Array(input)) = obj.get_mut("input") {
        flatten_namespaced_history(input);
    }
    identity_map
}

/// Resolve a flattened wire name back to `(namespace, leaf)`
/// (`resolveRequestToolIdentity`, `requestToolIdentity.ts:59-83`):
/// direct map hit, then the `namespace.leaf` dotted spelling some
/// model parsers render, then the `mcp__` last-`__` split fallback
/// (`#12996`).
fn resolve_request_tool_identity(
    map: &HashMap<String, (String, String)>,
    tool_name: &str,
) -> Option<(String, String)> {
    if tool_name.is_empty() {
        return None;
    }
    if let Some((ns, leaf)) = map.get(tool_name) {
        return Some((ns.clone(), leaf.clone()));
    }
    for (ns, leaf) in map.values() {
        if format!("{ns}.{leaf}") == tool_name {
            return Some((ns.clone(), leaf.clone()));
        }
    }
    if tool_name.starts_with("mcp__") {
        if let Some(sep) = tool_name.rfind("__") {
            let (ns, leaf) = (&tool_name[..sep], &tool_name[sep + 2..]);
            if !ns.is_empty() && !leaf.is_empty() {
                return Some((ns.to_string(), leaf.to_string()));
            }
        }
    }
    None
}

/// Restore `{namespace, name}` on one chat-shape tool call
/// (`restoreFunctionCall` + `applyFunctionCallIdentity` +
/// `plaintextCollaborationFields`): the leaf goes back into
/// `function.name`, the namespace rides alongside, and collaboration
/// spawn/send/followup calls gain the `encrypted_function_args: []`
/// plaintext marker Codex requires (`#14154`). Returns whether the
/// call changed.
fn restore_tool_call_namespace(call: &mut Value, map: &HashMap<String, (String, String)>) -> bool {
    let already_namespaced = call
        .get("namespace")
        .and_then(Value::as_str)
        .is_some_and(|ns| !ns.is_empty());
    if already_namespaced {
        return false;
    }
    let name = call
        .get("function")
        .and_then(|f| f.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return false;
    }
    let Some((ns, leaf)) = resolve_request_tool_identity(map, &name) else {
        return false;
    };
    let Some(func) = call.get_mut("function").and_then(|f| f.as_object_mut()) else {
        return false;
    };
    func.insert("name".to_string(), Value::String(leaf.clone()));
    let Some(obj) = call.as_object_mut() else {
        return false;
    };
    obj.insert("namespace".to_string(), Value::String(ns.clone()));
    if ns == "collaboration"
        && matches!(
            leaf.as_str(),
            "spawn_agent" | "send_message" | "followup_task"
        )
    {
        obj.insert(
            "encrypted_function_args".to_string(),
            Value::Array(Vec::new()),
        );
    }
    true
}

/// Rewrite flattened namespace calls on one outgoing chunk
/// (`restoreGrokBuildNamespaceToolCalls` adapted to chunks — see the
/// note on [`restore_tool_call_namespace`]). No-op without a map, so
/// the shared `responses_wire` event mapping stays untouched.
fn restore_chunk_tool_calls(
    chunk: &mut ChatChunk,
    map: Option<&HashMap<String, (String, String)>>,
) {
    let Some(map) = map else {
        return;
    };
    let Some(calls) = chunk.delta.tool_calls.as_mut() else {
        return;
    };
    for call in calls.iter_mut() {
        restore_tool_call_namespace(call, map);
    }
}

// ─── Foreign reasoning replay ─────────────────────────────────────────
// Port of `stripForeignGrokBuildReasoning`
// (`executors/grokCliReasoningReplay.ts`): a combo turn served by
// another Responses provider leaves an `encrypted_content` blob Grok
// cannot decrypt (`400 Could not decrypt the provided
// encrypted_content`), wedging the conversation. Drop the blob from
// every reasoning item Grok Build did not produce — its own items
// are `rs_<uuid>` (or server-side tool reasoning with a `tco_`
// id/blob prefix) — and ensure `summary: []` so the replay still
// decodes. Fails closed by design: dropping one of Grok's own blobs
// only costs continuity, forwarding a foreign one is a hard 400.

/// `rs_<uuid>` (`GROK_BUILD_REASONING_ID_RE`): 8-4-4-4-12 hex.
fn is_grok_build_reasoning_id(id: &str) -> bool {
    let Some(hex) = id.strip_prefix("rs_") else {
        return false;
    };
    let parts: Vec<&str> = hex.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    const LENS: [usize; 5] = [8, 4, 4, 4, 12];
    parts
        .iter()
        .zip(LENS)
        .all(|(p, len)| p.len() == len && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Whether a reasoning item carries Grok Build's own identity
/// (`isGrokBuildReasoning`, `grokCliReasoningReplay.ts:30-38`).
fn is_grok_build_reasoning(item: &Value) -> bool {
    let id = item.get("id").and_then(Value::as_str).unwrap_or("");
    let blob = item
        .get("encrypted_content")
        .and_then(Value::as_str)
        .unwrap_or("");
    is_grok_build_reasoning_id(id) || id.starts_with("tco_") || blob.starts_with("tco_")
}

/// Strip one foreign blob; returns whether the item changed.
fn strip_foreign_reasoning_item(item: &mut Value) -> bool {
    if item.get("type").and_then(Value::as_str) != Some("reasoning") {
        return false;
    }
    if item.get("encrypted_content").is_none() {
        return false;
    }
    if is_grok_build_reasoning(item) {
        return false;
    }
    let Some(obj) = item.as_object_mut() else {
        return false;
    };
    obj.remove("encrypted_content");
    if !obj.get("summary").is_some_and(|s| s.is_array()) {
        obj.insert("summary".to_string(), Value::Array(Vec::new()));
    }
    true
}

// ─── Tool-schema root-union repair ────────────────────────────────────
// Port of `normalizeGrokBuildToolSchemas`
// (`executors/grokCliToolSchema.ts`): Grok Build refuses a function
// tool whose `parameters` root is an `anyOf`/`oneOf` union with a
// non-object branch (`400 [invalid_client_tool_schema]`, e.g. Codex
// desktop's `automation_update` with `$ref` branches). Local `$ref`
// branches are inlined (keywords next to the `$ref` combined with the
// target), nested unions expanded, never-object branches dropped,
// typeless object branches pinned to `type: "object"`, and the root's
// shared `properties` / `required` / `additionalProperties` moved
// into every branch. Unions inside `properties` / `$defs` are never
// touched; schemas with non-`$defs` refs or over 64 root branches
// pass through unchanged.

const DEFINITION_REF_PREFIXES: &[&str] = &["#/$defs/", "#/definitions/"];
const MAX_REF_HOPS: usize = 32;
const MAX_UNION_DEPTH: usize = 8;
const MAX_ROOT_BRANCHES: usize = 64;

fn schema_string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn schema_type_allows_object(ty: Option<&Value>) -> bool {
    match ty {
        None => true,
        Some(Value::String(s)) => s == "object",
        Some(Value::Array(types)) => types.iter().any(|t| t.as_str() == Some("object")),
        Some(_) => false,
    }
}

/// Whether a local `$ref` anywhere points outside `$defs` /
/// `definitions` (`hasRootRelativeRef`).
fn schema_has_root_relative_ref(node: &Value) -> bool {
    match node {
        Value::Array(items) => items.iter().any(schema_has_root_relative_ref),
        Value::Object(map) => {
            if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                if reference.starts_with('#')
                    && !DEFINITION_REF_PREFIXES
                        .iter()
                        .any(|prefix| reference.starts_with(prefix))
                {
                    return true;
                }
            }
            map.values().any(schema_has_root_relative_ref)
        }
        _ => false,
    }
}

/// Resolve a local JSON pointer (`#/$defs/Name`) against the schema
/// root (`resolveLocalRef`).
fn resolve_local_ref<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    if !reference.starts_with("#/") {
        return None;
    }
    let mut node = root;
    for segment in reference[2..].split('/') {
        let key = segment.replace("~1", "/").replace("~0", "~");
        node = node.as_object()?.get(&key)?;
    }
    Some(node)
}

/// Combine the keywords next to a `$ref` with its target
/// (`mergeRefSiblings`): `properties` and `required` merge,
/// annotations next to the `$ref` win.
fn merge_ref_siblings(target: &Value, siblings: &serde_json::Map<String, Value>) -> Value {
    let mut merged = target.as_object().cloned().unwrap_or_default();
    for (key, value) in siblings {
        merged.insert(key.clone(), value.clone());
    }
    if let (Some(Value::Object(target_props)), Some(Value::Object(sibling_props))) =
        (target.get("properties"), siblings.get("properties"))
    {
        let mut props = target_props.clone();
        for (key, value) in sibling_props {
            props.insert(key.clone(), value.clone());
        }
        merged.insert("properties".to_string(), Value::Object(props));
    }
    let mut required = schema_string_list(target.get("required"));
    for name in schema_string_list(siblings.get("required")) {
        if !required.contains(&name) {
            required.push(name);
        }
    }
    if !required.is_empty() {
        merged.insert(
            "required".to_string(),
            Value::Array(required.into_iter().map(Value::String).collect()),
        );
    }
    Value::Object(merged)
}

/// Inline a branch's chain of local `$ref`s, each expanded at most
/// once per root union (cycle guard); `None` for external, missing,
/// cyclic or already-expanded references (`dereferenceBranch`).
fn dereference_branch(
    root: &Value,
    branch: &Value,
    expanded: &mut HashSet<String>,
) -> Option<Value> {
    let mut current = branch.clone();
    let mut hops = 0;
    while let Some(reference) = current
        .get("$ref")
        .and_then(Value::as_str)
        .map(str::to_string)
    {
        if !expanded.insert(reference.clone()) {
            return None;
        }
        hops += 1;
        if hops > MAX_REF_HOPS {
            return None;
        }
        let target = resolve_local_ref(root, &reference)?;
        if !target.is_object() {
            return None;
        }
        let mut siblings = current.as_object().cloned().unwrap_or_default();
        siblings.remove("$ref");
        current = merge_ref_siblings(target, &siblings);
    }
    Some(current)
}

/// Pin a branch to `type: "object"`, or `None` when it can never
/// match a tool call's (always-object) arguments (`asObjectBranch`).
fn as_object_branch(branch: &Value) -> Option<Value> {
    const OBJECT_KEYWORDS: &[&str] = &[
        "properties",
        "required",
        "additionalProperties",
        "patternProperties",
        "propertyNames",
        "minProperties",
        "maxProperties",
    ];
    const ANNOTATION_KEYWORDS: &[&str] =
        &["title", "description", "$comment", "examples", "default"];
    let obj = branch.as_object()?;
    match obj.get("type") {
        Some(Value::String(ty)) if ty == "object" => Some(branch.clone()),
        Some(Value::Array(types)) if types.iter().any(|t| t.as_str() == Some("object")) => {
            let mut next = obj.clone();
            next.insert("type".to_string(), Value::String("object".to_string()));
            Some(Value::Object(next))
        }
        Some(_) => None,
        None => {
            let describes_object = OBJECT_KEYWORDS.iter().any(|k| obj.contains_key(*k))
                || obj
                    .keys()
                    .all(|k| ANNOTATION_KEYWORDS.contains(&k.as_str()));
            if !describes_object {
                return None;
            }
            let mut next = obj.clone();
            next.insert("type".to_string(), Value::String("object".to_string()));
            Some(Value::Object(next))
        }
    }
}

/// The branches of a schema that is nothing but an
/// object-compatible `anyOf`/`oneOf` (`pureUnionBranches`).
fn pure_union_branches(
    schema: &serde_json::Map<String, Value>,
) -> Option<(&'static str, Vec<Value>)> {
    const UNION_ANNOTATION_KEYWORDS: &[&str] = &["type", "title", "description", "$comment"];
    for keyword in ["anyOf", "oneOf"] {
        if let Some(Value::Array(branches)) = schema.get(keyword) {
            if !schema_type_allows_object(schema.get("type")) {
                return None;
            }
            let pure = schema
                .keys()
                .all(|k| k == keyword || UNION_ANNOTATION_KEYWORDS.contains(&k.as_str()));
            return pure.then(|| (keyword, branches.clone()));
        }
    }
    None
}

/// Append the inline object schemas one root-union branch stands
/// for (`collectObjectBranches`).
fn collect_object_branches(
    root: &Value,
    branch: &Value,
    depth: usize,
    expanded: &mut HashSet<String>,
    out: &mut Vec<Value>,
) {
    if out.len() > MAX_ROOT_BRANCHES {
        return;
    }
    if !branch.is_object() {
        return;
    }
    let Some(resolved) = dereference_branch(root, branch, expanded) else {
        return;
    };
    let nested = resolved.as_object().and_then(pure_union_branches);
    match nested {
        None => {
            if let Some(object_branch) = as_object_branch(&resolved) {
                out.push(object_branch);
            }
        }
        Some((_, branches)) => {
            if depth >= MAX_UNION_DEPTH {
                return;
            }
            for child in &branches {
                collect_object_branches(root, child, depth + 1, expanded, out);
            }
        }
    }
}

/// Add the root's shared object keywords to one branch (the branch's
/// own win) — `withSharedShape`.
fn with_shared_shape(
    branch: &Value,
    properties: &serde_json::Map<String, Value>,
    required: &[String],
    additional_properties: Option<&Value>,
) -> Value {
    let obj = branch.as_object().cloned().unwrap_or_default();
    let add_additional =
        additional_properties.is_some() && !obj.contains_key("additionalProperties");
    if properties.is_empty() && required.is_empty() && !add_additional {
        return branch.clone();
    }
    let mut next = obj;
    if !properties.is_empty() {
        let mut props = properties.clone();
        if let Some(Value::Object(branch_props)) = next.get("properties") {
            for (key, value) in branch_props {
                props.insert(key.clone(), value.clone());
            }
        }
        next.insert("properties".to_string(), Value::Object(props));
    }
    if !required.is_empty() {
        let mut merged = required.to_vec();
        for name in schema_string_list(next.get("required")) {
            if !merged.contains(&name) {
                merged.push(name);
            }
        }
        next.insert(
            "required".to_string(),
            Value::Array(merged.into_iter().map(Value::String).collect()),
        );
    }
    if add_additional {
        next.insert(
            "additionalProperties".to_string(),
            additional_properties
                .expect("guarded by add_additional")
                .clone(),
        );
    }
    Value::Object(next)
}

/// Rewrite one function tool's `parameters` root unions into the
/// shape Grok Build accepts (`normalizeRootUnions`); returns the
/// schema unchanged when there is nothing to reshape.
fn normalize_root_unions(schema: &Value) -> Value {
    const ROOT_OBJECT_KEYWORDS: &[&str] =
        &["type", "properties", "required", "additionalProperties"];
    let Some(obj) = schema.as_object() else {
        return schema.clone();
    };
    let has_union = ["anyOf", "oneOf"]
        .iter()
        .any(|k| obj.get(*k).is_some_and(|v| v.is_array()));
    if !has_union || schema_has_root_relative_ref(schema) {
        return schema.clone();
    }
    let properties = obj
        .get("properties")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let required = schema_string_list(obj.get("required"));
    let additional_properties = obj.get("additionalProperties").cloned();
    let mut changed = ROOT_OBJECT_KEYWORDS.iter().any(|k| obj.contains_key(*k));
    let mut next = obj.clone();
    for keyword in ["anyOf", "oneOf"] {
        let Some(Value::Array(branches)) = obj.get(keyword) else {
            continue;
        };
        let mut collected = Vec::new();
        let mut expanded = HashSet::new();
        for branch in branches {
            collect_object_branches(schema, branch, 0, &mut expanded, &mut collected);
        }
        // Too wide to reshape safely: leave the schema as sent.
        if collected.len() > MAX_ROOT_BRANCHES {
            return schema.clone();
        }
        let kept: Vec<Value> = collected
            .iter()
            .map(|branch| {
                with_shared_shape(
                    branch,
                    &properties,
                    &required,
                    additional_properties.as_ref(),
                )
            })
            .collect();
        if kept.len() != branches.len()
            || kept
                .iter()
                .zip(branches.iter())
                .any(|(kept_branch, branch)| kept_branch != branch)
        {
            changed = true;
        }
        if kept.is_empty() {
            next.remove(keyword);
        } else {
            next.insert(keyword.to_string(), Value::Array(kept));
        }
    }
    if !changed {
        return schema.clone();
    }
    if ["anyOf", "oneOf"].iter().any(|k| next.contains_key(*k)) {
        for keyword in ROOT_OBJECT_KEYWORDS {
            next.remove(*keyword);
        }
    } else {
        next.insert("type".to_string(), Value::String("object".to_string()));
        if !next.get("properties").is_some_and(|v| v.is_object()) {
            next.insert(
                "properties".to_string(),
                Value::Object(serde_json::Map::new()),
            );
        }
    }
    Value::Object(next)
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
            let item_type = item
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if item_type == "reasoning" {
                if let Some(obj) = item.as_object_mut() {
                    if obj.get("content").is_some_and(|c| c.is_null()) {
                        obj.remove("content");
                        changed = true;
                    }
                }
                // A combo turn served by another Responses provider
                // replays its `encrypted_content` here; Grok cannot
                // decrypt it, so the foreign blob is dropped (kept for
                // Grok's own `rs_<uuid>` / `tco_` items).
                if strip_foreign_reasoning_item(&mut item) {
                    changed = true;
                }
            } else if item_type == "function_call_output" {
                if let Some(obj) = item.as_object_mut() {
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
    // `search_context_size`), the 200-tool cap, then the root-union
    // repair for function tool schemas (`grok-cli.ts:371-383` order:
    // strip, cap, normalize).
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
            if tool.get("type").and_then(Value::as_str) == Some("function") {
                if let Some(params) = tool.get("parameters").cloned().filter(|p| p.is_object()) {
                    let next_params = normalize_root_unions(&params);
                    if next_params != params {
                        if let Some(obj) = tool.as_object_mut() {
                            obj.insert("parameters".to_string(), next_params);
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
        // Namespace groups flatten before the request sanitizer
        // (`GrokCliExecutor.execute` flattens before `transformRequest`;
        // the sanitizer below then caps + normalizes the flat tools).
        let mut pre_body = raw_body;
        let namespace_map = flatten_grok_build_namespace_tools(&mut pre_body);
        if namespace_map.is_some() {
            if let Some(count) = pre_body
                .get("tools")
                .and_then(|t| t.as_array())
                .map(Vec::len)
            {
                if count > MAX_TOOLS {
                    tracing::warn!(
                        tools = count,
                        "flattened namespace tools exceed the Grok Build limit: sending {MAX_TOOLS} of {count} tools"
                    );
                }
            }
        }
        let body = sanitize_responses_body(pre_body, upstream_model);
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
            // The identity map outlives the request the same way the TS
            // executor's does (one map per `execute`); cloned for the
            // stream generator below and the JSON branch after it.
            let stream_map = namespace_map.clone();
            let stream = async_stream::try_stream! {
                let mut decoder = SseDecoder::new();
                let mut stream = Box::pin(byte_stream);
                while let Some(next) = stream.next().await {
                    let chunk = next.map_err(|e| BridgeError::Transport(aisix_gateway::transport_error_message(&e)))?;
                    for event in decoder.feed(chunk.as_ref()).map_err(|e| BridgeError::UpstreamDecode(e.to_string()))? {
                        match event {
                            SseEvent::Done => break,
                            SseEvent::Data(payload) => {
                                if let Some(mut chunk) = stream_event_into_chat_chunk(&payload, &model_owned, &request_id) {
                                    restore_chunk_tool_calls(&mut chunk, stream_map.as_ref());
                                    yield chunk;
                                }
                            }
                        }
                    }
                }
                if let Some(SseEvent::Data(payload)) = decoder.finish().map_err(|e| BridgeError::UpstreamDecode(e.to_string()))? {
                    if let Some(mut chunk) = stream_event_into_chat_chunk(&payload, &model_owned, &request_id) {
                        restore_chunk_tool_calls(&mut chunk, stream_map.as_ref());
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
            let mut response = response_into_chat_response(&raw, &request_id, &model_owned);
            if let Some(map) = namespace_map.as_ref() {
                if let Some(Value::Array(calls)) = response.message.extra.get_mut("tool_calls") {
                    for call in calls.iter_mut() {
                        restore_tool_call_namespace(call, map);
                    }
                }
            }
            let response = response;
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
                "tools": [{"type": "web_search", "external_web_access": true, "search_context_size": "high"}]
            }),
            "grok-4.7",
        );
        assert!(body.get("presence_penalty").is_none());
        assert!(body.get("reasoning_effort").is_none());
        assert!(body["tools"][0].get("external_web_access").is_none());
        assert!(body["tools"][0].get("search_context_size").is_none());
        assert_eq!(body["tools"][0]["type"], serde_json::json!("web_search"));
    }

    #[test]
    fn tools_capped_at_two_hundred() {
        let tools: Vec<Value> = (0..250)
            .map(|i| serde_json::json!({"type": "function", "name": format!("f{i}")}))
            .collect();
        let body = sanitize_responses_body(
            serde_json::json!({"model": "grok-4.7", "tools": tools}),
            "grok-4.7",
        );
        assert_eq!(body["tools"].as_array().unwrap().len(), MAX_TOOLS);
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

    #[test]
    fn tool_schema_root_union_with_refs_is_reshaped() {
        // Codex-desktop shape: root `oneOf` of `$defs` refs plus a
        // `{type: "null"}` branch Grok rejects as "root cannot be
        // nullable"; shared root keywords move into every branch.
        let params = serde_json::json!({
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
            "oneOf": [
                {"$ref": "#/$defs/ModeA"},
                {"$ref": "#/$defs/ModeB"},
                {"type": "null"}
            ],
            "$defs": {
                "ModeA": {"type": "object", "properties": {"mode": {"const": "a"}}, "required": ["mode"]},
                "ModeB": {"type": "object", "properties": {"mode": {"const": "b"}}}
            }
        });
        let next = normalize_root_unions(&params);
        let branches = next["oneOf"].as_array().unwrap();
        assert_eq!(branches.len(), 2, "null branch dropped: {next}");
        for branch in branches {
            assert_eq!(branch["type"], serde_json::json!("object"));
            assert!(
                branch["properties"].get("id").is_some(),
                "shared props moved: {branch}"
            );
            assert!(branch["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "id"));
        }
        // Root object keywords are gone while a union remains; `$defs`
        // stays so nested refs keep resolving.
        assert!(next.get("properties").is_none());
        assert!(next.get("required").is_none());
        assert!(next.get("$defs").is_some());
    }

    #[test]
    fn tool_schema_without_union_passes_through() {
        let params = serde_json::json!({
            "type": "object",
            "properties": {"q": {"type": "string"}}
        });
        assert_eq!(normalize_root_unions(&params), params);
        // Non-function tools and tools without object parameters are
        // never touched. Driven through the send-path sanitizer, which is
        // where the tool repair actually runs: its `changed` flag stays
        // false, so `tools` comes back byte-identical.
        let body = serde_json::json!({
            "tools": [
                {"type": "web_search"},
                {"type": "function", "name": "f", "parameters": params},
                {"type": "function", "name": "g"},
            ]
        });
        let out = sanitize_responses_body(body.clone(), "grok-4.7");
        assert_eq!(out["tools"], body["tools"], "tools untouched: {out}");
    }

    #[test]
    fn tool_schema_with_foreign_ref_passes_through() {
        let params = serde_json::json!({
            "oneOf": [{"$ref": "#/elsewhere/Mode"}],
            "$defs": {"Mode": {"type": "object", "properties": {}}}
        });
        assert_eq!(normalize_root_unions(&params), params);
    }

    #[test]
    fn namespace_tools_flatten_with_identity_map() {
        let mut body = serde_json::json!({
            "model": "grok-4.7",
            "tools": [
                {"type": "function", "name": "plain"},
                {"type": "namespace", "name": "mcp__srv", "tools": [
                    {"type": "function", "name": "search", "description": "s",
                     "parameters": {"type": "object", "properties": {}}},
                    {"type": "custom", "name": "freeform"},
                    {"type": "function", "name": ""}
                ]},
                {"type": "namespace", "name": "", "tools": [
                    {"name": "bare", "parameters": {"type": "object", "properties": {}}}
                ]}
            ],
            "input": [
                {"type": "function_call", "namespace": "mcp__srv", "name": "search",
                 "call_id": "c1", "arguments": "{}"}
            ]
        });
        let map = flatten_grok_build_namespace_tools(&mut body).expect("group flattened");
        assert_eq!(
            map.get("mcp__srv__search"),
            Some(&("mcp__srv".to_string(), "search".to_string()))
        );
        let names: Vec<&str> = body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect();
        // Plain + one flattened function; the `custom` child and the
        // unnamed child are dropped, never forwarded.
        assert_eq!(names, vec!["plain", "mcp__srv__search", "bare"]);
        // History renamed to the wire name so it matches the tools.
        assert_eq!(
            body["input"][0]["name"],
            serde_json::json!("mcp__srv__search")
        );
        assert!(body["input"][0].get("namespace").is_none());
    }

    #[test]
    fn no_namespace_tools_yields_no_map() {
        let mut body = serde_json::json!({
            "tools": [{"type": "function", "name": "f"}],
        });
        assert!(flatten_grok_build_namespace_tools(&mut body).is_none());
    }

    #[test]
    fn restore_rewrites_wire_names_to_namespace_identity() {
        let map: HashMap<String, (String, String)> = [
            (
                "mcp__srv__search".to_string(),
                ("mcp__srv".to_string(), "search".to_string()),
            ),
            (
                "collaboration__spawn_agent".to_string(),
                ("collaboration".to_string(), "spawn_agent".to_string()),
            ),
        ]
        .into_iter()
        .collect();
        let mut direct = serde_json::json!({
            "id": "c1", "type": "function",
            "function": {"name": "mcp__srv__search", "arguments": "{}"}
        });
        assert!(restore_tool_call_namespace(&mut direct, &map));
        assert_eq!(direct["function"]["name"], serde_json::json!("search"));
        assert_eq!(direct["namespace"], serde_json::json!("mcp__srv"));
        // Dotted spelling resolves against the map; the mcp__ split
        // fallback covers turns that never re-declared the tools.
        let mut dotted = serde_json::json!({
            "id": "c2", "type": "function",
            "function": {"name": "mcp__srv.search", "arguments": "{}"}
        });
        assert!(restore_tool_call_namespace(&mut dotted, &map));
        assert_eq!(dotted["namespace"], serde_json::json!("mcp__srv"));
        let mut split = serde_json::json!({
            "id": "c3", "type": "function",
            "function": {"name": "mcp__other__tool", "arguments": "{}"}
        });
        assert!(restore_tool_call_namespace(&mut split, &HashMap::new()));
        assert_eq!(split["function"]["name"], serde_json::json!("tool"));
        assert_eq!(split["namespace"], serde_json::json!("mcp__other"));
        // Collaboration calls gain the plaintext marker.
        let mut spawn = serde_json::json!({
            "id": "c4", "type": "function",
            "function": {"name": "collaboration__spawn_agent", "arguments": "{}"}
        });
        assert!(restore_tool_call_namespace(&mut spawn, &map));
        assert_eq!(spawn["encrypted_function_args"], serde_json::json!([]));
        // Unknown names and already-namespaced calls pass through.
        let mut unknown = serde_json::json!({
            "id": "c5", "type": "function",
            "function": {"name": "plain", "arguments": "{}"}
        });
        assert!(!restore_tool_call_namespace(&mut unknown, &map));
        let mut stamped = serde_json::json!({
            "id": "c6", "type": "function", "namespace": "mcp__srv",
            "function": {"name": "search", "arguments": "{}"}
        });
        assert!(!restore_tool_call_namespace(&mut stamped, &map));
    }

    #[test]
    fn foreign_reasoning_blob_stripped_grok_blob_kept() {
        // OpenAI `rs_` hex blob (a codex combo turn): dropped, summary added.
        let mut foreign = serde_json::json!({
            "type": "reasoning",
            "id": "rs_0123456789abcdef0123456789abcdef",
            "encrypted_content": "opaque-openai-blob",
        });
        assert!(strip_foreign_reasoning_item(&mut foreign));
        assert!(foreign.get("encrypted_content").is_none());
        assert_eq!(foreign["summary"], serde_json::json!([]));
        // Grok's own uuid item and tco_ tool reasoning survive.
        let grok_id = "rs_12345678-1234-1234-1234-1234567890ab";
        assert!(is_grok_build_reasoning_id(grok_id));
        assert!(!is_grok_build_reasoning_id("rs_0123456789abcdef"));
        let mut own = serde_json::json!({
            "type": "reasoning", "id": grok_id, "encrypted_content": "grok-blob",
        });
        assert!(!strip_foreign_reasoning_item(&mut own));
        let mut tool_reasoning = serde_json::json!({
            "type": "reasoning", "id": "tco_abc", "encrypted_content": "tco_blob",
        });
        assert!(!strip_foreign_reasoning_item(&mut tool_reasoning));
        // Items without a blob are never touched.
        let mut plain = serde_json::json!({"type": "reasoning", "summary": []});
        assert!(!strip_foreign_reasoning_item(&mut plain));
    }

    #[test]
    fn sanitize_drops_foreign_encrypted_content_from_input() {
        let body = sanitize_responses_body(
            serde_json::json!({
                "model": "grok-4.7",
                "input": [
                    {"type": "reasoning", "id": "rs_0123456789abcdef0123456789abcdef",
                     "encrypted_content": "foreign"}
                ]
            }),
            "grok-4.7",
        );
        assert!(body["input"][0].get("encrypted_content").is_none());
        assert_eq!(body["input"][0]["summary"], serde_json::json!([]));
    }

    #[test]
    fn flattened_wire_name_rules() {
        assert_eq!(flatten_namespace_tool_name("", "leaf"), "leaf");
        assert_eq!(flatten_namespace_tool_name("ns", "a__b"), "a__b");
        assert_eq!(flatten_namespace_tool_name("ns__", "leaf"), "ns__leaf");
        assert_eq!(flatten_namespace_tool_name("ns", "leaf"), "ns__leaf");
        // Over-long names truncate deterministically to the 64-char cap.
        let (ns, leaf) = ("n".repeat(30), "l".repeat(40));
        let first = flatten_namespace_tool_name(&ns, &leaf);
        assert_eq!(first.len(), 64, "wire={first}");
        assert_eq!(first, flatten_namespace_tool_name(&ns, &leaf));
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
