//! aisix-provider-openai — OpenAI provider [`OpenAiBridge`] impl.
//!
//! This crate is also the transport used by other OpenAI-compatible
//! upstreams (DeepSeek today, Gemini's OpenAI-compat endpoint later).
//! Those provider crates can wrap [`OpenAiBridge`] with their own
//! `api_base` and metrics label rather than duplicating the transport.
//!
//! See the `Bridge` trait in `aisix-gateway` for the contract this crate
//! implements against.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

mod bridge;
pub mod clinepass;
pub mod codex;
pub mod cohere;
pub mod grok_cli;
pub mod overrides;
pub mod qoder;
pub mod reasoning;
pub mod responses_wire;
pub mod wire;

pub use bridge::{close_strict_response_format_schema, OpenAiBridge, OPENAI_DEFAULT_BASE};
pub use clinepass::{ClineBridge, ClinepassBridge, CLINE_DEFAULT_BASE};
pub use codex::{CodexBridge, CODEX_CLIENT_VERSION, CODEX_DEFAULT_BASE};
pub use grok_cli::{GrokCliBridge, GROK_CLIENT_VERSION, GROK_DEFAULT_BASE};
pub use qoder::{QoderBridge, QODER_DEFAULT_BASE};
