//! Shared OpenAI Responses-API wire helpers for the CLI-bridge vendors.
//!
//! Both Grok-CLI (`cli-chat-proxy.grok.com/v1/responses`, see
//! `open-sse/config/grokBuild.ts`) and Codex
//! (`chatgpt.com/backend-api/codex/responses`, see
//! `open-sse/config/providers/registry/codex/index.ts`) speak the
//! OpenAI Responses shape rather than `/chat/completions`. The gateway
//! dispatches [`ChatFormat`](aisix_gateway::ChatFormat), so this module
//! projects chat turns onto Responses `input` items and folds Responses
//! `output` items (streaming deltas and the terminal object alike) back
//! into [`ChatChunk`] / [`ChatResponse`].
//!
//! Byte-parity notes vs `open-sse` (deliberate, documented divergences):
//! - The TS executors forward client `instructions`, `tools` and
//!   `reasoning` verbatim. Here `req.extra` is flattened into the body
//!   (same convention as [`crate::wire::build_request`]) so an operator
//!   or client CAN pass those through; the per-bridge sanitizers then
//!   strip what their upstream rejects.
//! - Tool calls surface as `delta.tool_calls` (chat-shape) rather than
//!   Responses `function_call` items; the proxy layer re-encodes them
//!   for the client.

use aisix_gateway::{
    ChatChunk, ChatDelta, ChatFormat, ChatResponse, FinishReason, Role, UsageStats,
};
use serde_json::Value;

/// Build the Responses request body from a normalised chat request.
///
/// `effort` seeds `reasoning.effort` when the caller did not set a
/// `reasoning` object in `extra` (Grok-CLI defaults to `"high"` per
/// `GROK_BUILD_DEFAULT_REASONING_EFFORT`; Codex passes `None` and lets
/// the client decide).
pub fn build_responses_body(
    req: &ChatFormat,
    upstream_model: &str,
    stream: bool,
    effort: Option<&str>,
) -> Value {
    let mut instructions = String::new();
    let mut input: Vec<Value> = Vec::new();
    for m in &req.messages {
        if m.is_reasoning_only() {
            continue;
        }
        let text = m.content_str();
        match m.role {
            Role::System | Role::Developer => {
                if !instructions.is_empty() {
                    instructions.push_str("\n\n");
                }
                instructions.push_str(text);
            }
            Role::User | Role::Tool => {
                input.push(serde_json::json!({"type": "message", "role": "user", "content": text}));
            }
            Role::Assistant => {
                input.push(
                    serde_json::json!({"type": "message", "role": "assistant", "content": text}),
                );
            }
        }
    }

    let mut body = serde_json::json!({
        "model": upstream_model,
        "input": input,
        "stream": stream,
    });
    if !instructions.is_empty() {
        body["instructions"] = Value::String(instructions);
    }
    if let Some(t) = req.temperature {
        body["temperature"] = serde_json::json!(t);
    }
    if let Some(p) = req.top_p {
        body["top_p"] = serde_json::json!(p);
    }
    if let Some(m) = req.max_tokens {
        body["max_output_tokens"] = serde_json::json!(m);
    }
    // Client/operator extras ride along (tools, reasoning, verbosity,
    // instructions …); per-bridge sanitizers strip what their upstream
    // rejects. Never overwrites the fields assembled above.
    if let Some(obj) = body.as_object_mut() {
        for (k, v) in &req.extra {
            if !obj.contains_key(k) {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    if let Some(effort) = effort {
        if body.get("reasoning").is_none() {
            body["reasoning"] = serde_json::json!({"effort": effort});
        }
    }
    body
}

/// Folded text of one Responses `output` item into `(content, reasoning)`.
///
/// Handles the shapes the two CLI proxies emit: `message` items with
/// `content: [{type: "output_text", text}]`, bare `output_text` items,
/// and `reasoning` items carrying `summary[].text`.
pub fn output_item_text(item: &Value) -> (String, String) {
    let mut content = String::new();
    let mut reasoning = String::new();
    let item_type = item.get("type").and_then(Value::as_str).unwrap_or("");
    match item_type {
        "message" | "output_text" => {
            let blocks: Vec<&Value> = match item.get("content") {
                Some(Value::Array(arr)) => arr.iter().collect(),
                Some(other) => vec![other],
                None => match item.get("text") {
                    Some(t) => vec![t],
                    None => vec![],
                },
            };
            for b in blocks {
                if let Some(t) = b.get("text").and_then(Value::as_str) {
                    content.push_str(t);
                } else if let Some(s) = b.as_str() {
                    content.push_str(s);
                }
            }
        }
        "reasoning" => {
            if let Some(Value::Array(summary)) = item.get("summary") {
                for s in summary {
                    if let Some(t) = s.get("text").and_then(Value::as_str) {
                        reasoning.push_str(t);
                    }
                }
            }
        }
        _ => {}
    }
    (content, reasoning)
}

/// Extract one `function_call` output item into a chat-shape tool call
/// value, or `None` when the item is not a function call.
pub fn output_item_tool_call(item: &Value) -> Option<Value> {
    if item.get("type").and_then(Value::as_str)? != "function_call" {
        return None;
    }
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return None;
    }
    let call_id = item
        .get("call_id")
        .or_else(|| item.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let arguments = match item.get("arguments") {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => "{}".to_string(),
    };
    Some(serde_json::json!({
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": arguments},
    }))
}

fn responses_usage(value: &Value) -> UsageStats {
    let usage = value.get("usage");
    let prompt = usage
        .and_then(|u| u.get("input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;
    let output = usage
        .and_then(|u| u.get("output_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;
    let total = usage
        .and_then(|u| u.get("total_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;
    // `output_tokens_details.reasoning_tokens` names the reasoning subset
    // (Responses shape of the Chat `completion_tokens_details` field).
    // Tolerate the singular `output_token_details` spelling some proxies
    // emit, plus a flattened top-level `reasoning_tokens`.
    let reasoning = usage
        .and_then(|u| {
            u.get("output_tokens_details")
                .or_else(|| u.get("output_token_details"))
        })
        .and_then(|d| d.get("reasoning_tokens"))
        .and_then(Value::as_u64)
        .or_else(|| {
            usage
                .and_then(|u| u.get("reasoning_tokens"))
                .and_then(Value::as_u64)
        })
        .unwrap_or(0) as u32;
    // Beside-vs-subset: the Responses backends that report reasoning
    // BESIDE `output_tokens` state `total == prompt + output + reasoning`
    // (Gemini-shape, cf. Antigravity `usage_from_metadata`); the ones
    // that already include it state `total == prompt + output`. Fold only
    // in the beside case so a subset is never double-counted.
    let beside = reasoning > 0 && total == prompt.saturating_add(output).saturating_add(reasoning);
    UsageStats {
        prompt_tokens: prompt,
        completion_tokens: if beside {
            output.saturating_add(reasoning)
        } else {
            output
        },
        total_tokens: total,
        reasoning_tokens: reasoning,
        reasoning_folded_into_completion: if beside { reasoning } else { 0 },
        upstream_total_tokens: total,
        ..Default::default()
    }
}

/// Convert a terminal (non-streaming) Responses object into a
/// [`ChatResponse`]. `id`/`model` fall back to the request context when
/// the upstream omits them.
pub fn response_into_chat_response(raw: &Value, id: &str, model: &str) -> ChatResponse {
    let mut content = String::new();
    let mut reasoning = String::new();
    let mut tool_calls: Vec<Value> = Vec::new();
    if let Some(Value::Array(output)) = raw.get("output") {
        for item in output {
            let (text, think) = output_item_text(item);
            content.push_str(&text);
            reasoning.push_str(&think);
            if let Some(call) = output_item_tool_call(item) {
                tool_calls.push(call);
            }
        }
    }
    // Some proxies answer with a bare `{output_text, ...}` or plain
    // `{text}` object instead of the `output` array.
    if content.is_empty() && reasoning.is_empty() && tool_calls.is_empty() {
        if let Some(t) = raw.get("output_text").and_then(Value::as_str) {
            content.push_str(t);
        } else if let Some(t) = raw.get("text").and_then(Value::as_str) {
            content.push_str(t);
        }
    }
    let finish_reason = if tool_calls.is_empty() {
        FinishReason::Stop
    } else {
        FinishReason::ToolCalls
    };
    let mut message = aisix_gateway::ChatMessage::assistant(content);
    if !tool_calls.is_empty() {
        message
            .extra
            .insert("tool_calls".to_string(), Value::Array(tool_calls));
    }
    if !reasoning.is_empty() {
        message
            .extra
            .insert("reasoning_content".to_string(), Value::String(reasoning));
    }
    ChatResponse {
        id: raw
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or(id)
            .to_string(),
        model: raw
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(model)
            .to_string(),
        message,
        finish_reason,
        usage: responses_usage(raw),
    }
}

/// Map one Responses SSE `data:` payload onto a [`ChatChunk`].
///
/// Recognises `response.output_text.delta` (`{delta}`) content frames,
/// reasoning-summary deltas, terminal `response.completed` /
/// `response.incomplete` frames (usage + finish reason), and the
/// `response.function_call_arguments.done` tool-call frame. Returns
/// `None` for keep-alive / bookkeeping events the client must not see.
///
/// A payload that is not JSON at all is a corrupt frame, not
/// bookkeeping: it is warn-logged (with a capped snippet) and dropped
/// rather than silently swallowed, so a systematic upstream shape drift
/// shows up in operator logs instead of surfacing as empty completions.
pub fn stream_event_into_chat_chunk(payload: &str, model: &str, id: &str) -> Option<ChatChunk> {
    let value: Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(_) => {
            if !payload.trim().is_empty() {
                let snippet: String = payload.chars().take(200).collect();
                tracing::warn!(
                    responses_event = %snippet,
                    "responses SSE data frame failed to parse as JSON; dropping frame"
                );
            }
            return None;
        }
    };
    let event_type = value.get("type").and_then(Value::as_str).unwrap_or("");
    match event_type {
        "response.output_text.delta" => {
            let delta = value.get("delta").and_then(Value::as_str).unwrap_or("");
            if delta.is_empty() {
                return None;
            }
            Some(ChatChunk {
                id: id.to_string(),
                model: model.to_string(),
                delta: ChatDelta {
                    content: Some(delta.to_string()),
                    ..Default::default()
                },
                finish_reason: None,
                usage: None,
            })
        }
        "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => {
            let delta = value.get("delta").and_then(Value::as_str).unwrap_or("");
            if delta.is_empty() {
                return None;
            }
            Some(ChatChunk {
                id: id.to_string(),
                model: model.to_string(),
                delta: ChatDelta {
                    reasoning_content: Some(delta.to_string()),
                    ..Default::default()
                },
                finish_reason: None,
                usage: None,
            })
        }
        "response.function_call_arguments.done" => {
            let name = value.get("name").and_then(Value::as_str).unwrap_or("");
            let call_id = value.get("call_id").and_then(Value::as_str).unwrap_or("");
            let arguments = value
                .get("arguments")
                .and_then(Value::as_str)
                .unwrap_or("{}");
            Some(ChatChunk {
                id: id.to_string(),
                model: model.to_string(),
                delta: ChatDelta {
                    tool_calls: Some(vec![serde_json::json!({
                        "id": call_id,
                        "type": "function",
                        "function": {"name": name, "arguments": arguments},
                    })]),
                    ..Default::default()
                },
                finish_reason: Some(FinishReason::ToolCalls),
                usage: None,
            })
        }
        "response.completed" | "response.incomplete" | "response.failed" => {
            let response = value.get("response").unwrap_or(&value);
            let mut content = String::new();
            let mut reasoning = String::new();
            let mut tool_calls: Vec<Value> = Vec::new();
            if let Some(Value::Array(output)) = response.get("output") {
                for item in output {
                    let (text, think) = output_item_text(item);
                    content.push_str(&text);
                    reasoning.push_str(&think);
                    if let Some(call) = output_item_tool_call(item) {
                        tool_calls.push(call);
                    }
                }
            }
            // A terminal frame that only carries usage (the deltas
            // already delivered the text) must not re-emit an empty
            // content delta — yield usage with no delta instead.
            // Moved (not cloned) into the delta: these locals die here.
            let has_tools = !tool_calls.is_empty();
            let delta = ChatDelta {
                content: (!content.is_empty()).then_some(content),
                reasoning_content: (!reasoning.is_empty()).then_some(reasoning),
                tool_calls: has_tools.then_some(tool_calls),
                ..Default::default()
            };
            let finish_reason = if has_tools {
                Some(FinishReason::ToolCalls)
            } else if event_type == "response.incomplete" {
                Some(FinishReason::Length)
            } else {
                Some(FinishReason::Stop)
            };
            Some(ChatChunk {
                id: id.to_string(),
                model: model.to_string(),
                delta,
                finish_reason,
                usage: Some(responses_usage(response)),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_response_folds_output_items() {
        let raw = serde_json::json!({
            "id": "resp-1",
            "model": "grok-4.7",
            "output": [
                {"type": "message", "content": [{"type": "output_text", "text": "hello"}]},
                {"type": "function_call", "call_id": "c1", "name": "search", "arguments": "{\"q\":\"x\"}"}
            ],
            "usage": {"input_tokens": 3, "output_tokens": 5, "total_tokens": 8}
        });
        let resp = response_into_chat_response(&raw, "req-1", "fallback");
        assert_eq!(resp.id, "resp-1");
        assert_eq!(resp.message.content_str(), "hello");
        assert_eq!(resp.finish_reason, FinishReason::ToolCalls);
        assert_eq!(resp.usage.total_tokens, 8);
        assert_eq!(resp.usage.upstream_total_tokens, 8);
    }

    #[test]
    fn beside_reasoning_folds_into_completion() {
        // `total == prompt + output + reasoning`: reasoning reported
        // BESIDE the completion (Gemini-shape) folds in.
        let raw = serde_json::json!({
            "id": "resp-2",
            "model": "grok-4.7",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "hi"}]}],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "total_tokens": 40,
                "output_tokens_details": {"reasoning_tokens": 10}
            }
        });
        let resp = response_into_chat_response(&raw, "req-1", "fallback");
        assert_eq!(resp.usage.prompt_tokens, 10);
        assert_eq!(resp.usage.completion_tokens, 30);
        assert_eq!(resp.usage.reasoning_tokens, 10);
        assert_eq!(resp.usage.reasoning_folded_into_completion, 10);
        assert_eq!(resp.usage.upstream_total_tokens, 40);
    }

    #[test]
    fn subset_reasoning_is_not_double_counted() {
        // `total == prompt + output`: reasoning already inside the
        // completion (OpenAI subset shape) must not be added again.
        let raw = serde_json::json!({
            "id": "resp-3",
            "model": "codex",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "hi"}]}],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "total_tokens": 30,
                "output_tokens_details": {"reasoning_tokens": 8}
            }
        });
        let resp = response_into_chat_response(&raw, "req-1", "fallback");
        assert_eq!(resp.usage.completion_tokens, 20);
        assert_eq!(resp.usage.reasoning_tokens, 8);
        assert_eq!(resp.usage.reasoning_folded_into_completion, 0);
        assert_eq!(resp.usage.upstream_total_tokens, 30);
    }

    #[test]
    fn delta_event_maps_to_content_chunk() {
        let chunk = stream_event_into_chat_chunk(
            r#"{"type":"response.output_text.delta","delta":"hi"}"#,
            "m",
            "r",
        )
        .expect("delta must map");
        assert_eq!(chunk.delta.content.as_deref(), Some("hi"));
        assert!(chunk.finish_reason.is_none());
    }

    #[test]
    fn terminal_event_carries_usage_without_duplicate_text() {
        let chunk = stream_event_into_chat_chunk(
            r#"{"type":"response.completed","response":{"output":[],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}}"#,
            "m",
            "r",
        )
        .expect("completed must map");
        assert!(chunk.delta.content.is_none());
        assert_eq!(chunk.usage.map(|u| u.total_tokens), Some(3));
    }
}
