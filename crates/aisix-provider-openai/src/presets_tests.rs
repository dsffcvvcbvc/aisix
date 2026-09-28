#![cfg(test)]
//! Tests for the embedded preset-provider catalog.
//!
//! The point of the catalog is that its values are *right about other
//! people's servers*, so the assertions here are byte-level against the
//! source registry rather than against a hand-copied expectation: a
//! transposed host, a dropped path segment or a wrong header name makes a
//! preset that fails on the first real request, and no amount of internal
//! self-consistency would notice.
//!
//! The inner `#![cfg(test)]` is load-bearing, not decoration: without it
//! this file's imports and fixtures are compiled into a normal build, where
//! every `#[test]` has been stripped and they are dead code the crate
//! warns about. `lib.rs` declares the module unconditionally, so the gate
//! belongs on this side of that line.
//!
//! `SPOT_CHECK` is a spread across the alphabet plus, deliberately, every
//! vendor that is not boring: all three non-`Bearer` auth shapes (the two
//! header-name rows and the one `Authorization`-scheme row), the two rows
//! whose registry `authHeader` is deliberately NOT honoured on the chat
//! surface, and all seven vendors carrying custom headers. A bug that only
//! affects an interesting row would otherwise hide behind 181 identical
//! bearer rows. The remaining "not boring" axis — which `base_url` rows are
//! a base rather than a full endpoint — is not a spot check's job, because
//! `every_row_dispatches_to_its_own_base_url` already walks every row.

use super::presets::{find_preset, PresetAuth, PresetProvider, PRESET_ALIASES, PRESET_PROVIDERS};

/// `(id, base_url, auth, headers)` transcribed from
/// `omniroute/open-sse/config/providers/registry/<id>/index.ts`.
type Expected = (
    &'static str,
    &'static str,
    PresetAuth,
    &'static [(&'static str, &'static str)],
);

const SPOT_CHECK: &[Expected] = &[
        ("agnes", "https://apihub.agnes-ai.com/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("aihorde", "https://oai.aihorde.net/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("alibaba", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("anyapi", "https://api.anyapi.ai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("baichuan", "https://api.baichuan-ai.com/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("baseten", "https://inference.baseten.co/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("chutes", "https://llm.chutes.ai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("cohere", "https://api.cohere.com/compatibility/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("cerebras", "https://api.cerebras.ai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("deepseek", "https://api.deepseek.com/chat/completions", PresetAuth::Bearer, &[]),
        ("deepinfra", "https://api.deepinfra.com/v1/openai/chat/completions", PresetAuth::Bearer, &[]),
        ("fireworks", "https://api.fireworks.ai/inference/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("groq", "https://api.groq.com/openai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("huggingface", "https://router.huggingface.co/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("hyperbolic", "https://api.hyperbolic.xyz/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("lambda-ai", "https://api.lambda.ai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("mistral", "https://api.mistral.ai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("modal", "https://api.modal.ai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("nebius", "https://api.tokenfactory.nebius.com/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("nvidia", "https://integrate.api.nvidia.com/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("novita", "https://api.novita.ai/openai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("openai", "https://api.openai.com/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("openrouter", "https://openrouter.ai/api/v1/chat/completions", PresetAuth::Bearer, &[("HTTP-Referer", "https://endpoint-proxy.local"), ("X-Title", "Endpoint Proxy")]),
        ("perplexity", "https://api.perplexity.ai/chat/completions", PresetAuth::Bearer, &[]),
        ("poolside", "https://inference.poolside.ai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("qwen-cloud", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("requesty", "https://router.requesty.ai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("sambanova", "https://api.sambanova.ai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("scaleway", "https://api.scaleway.ai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("together", "https://api.together.xyz/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("venice", "https://api.venice.ai/api/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("vercel-ai-gateway", "https://ai-gateway.vercel.sh/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("writer", "https://api.writer.com/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("xai", "https://api.x.ai/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("baidu", "https://qianfan.baidubce.com/v2/chat/completions", PresetAuth::Bearer, &[]),
        ("qianfan", "https://qianfan.baidubce.com/v2/chat/completions", PresetAuth::Bearer, &[]),
        ("tencent", "https://api.hunyuan.cloud.tencent.com/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("volcengine", "https://ark.cn-beijing.volces.com/api/v3/chat/completions", PresetAuth::Bearer, &[]),
        ("doubao", "https://ark.cn-beijing.volces.com/api/v3/chat/completions", PresetAuth::Bearer, &[]),
        ("siliconflow", "https://api.siliconflow.com/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("modelscope", "https://api-inference.modelscope.cn/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("ollama-cloud", "https://ollama.com/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("v0-vercel", "https://api.v0.dev/v1/chat/completions", PresetAuth::Bearer, &[]),
        ("zenmux", "https://zenmux.ai/api/v1/chat/completions", PresetAuth::Bearer, &[]),
        // `HAIPER_KEY` / `Api-Key` are the registry's `authHeader` values and
        // the reference honours them — from its image/video handlers, never
        // from a chat path, which Bearer-falls-back on both. See the
        // `haiper` and `ideogram` rows in `presets.rs` and
        // `bridge::tests::a_registry_auth_header_the_reference_ignores_on_chat_stays_bearer`.
        ("haiper", "https://api.haiper.ai/v1", PresetAuth::Bearer, &[]),
        ("ideogram", "https://api.ideogram.ai", PresetAuth::Bearer, &[]),
        ("maritalk", "https://chat.maritaca.ai/api", PresetAuth::AuthorizationScheme("Key"), &[]),
        ("pioneer", "https://api.pioneer.ai/v1/chat/completions", PresetAuth::ApiKeyHeader("x-api-key"), &[]),
        ("uc-direct", "https://api.uncensored.com/api/v1", PresetAuth::ApiKeyHeader("x-api-key"), &[]),
        ("api-airforce", "https://api.airforce/v1/chat/completions", PresetAuth::Bearer, &[("HTTP-Referer", "https://endpoint-proxy.local"), ("X-Title", "Endpoint Proxy")]),
        ("orcarouter", "https://api.orcarouter.ai/v1/chat/completions", PresetAuth::Bearer, &[("HTTP-Referer", "https://endpoint-proxy.local"), ("X-Title", "Endpoint Proxy")]),
        ("gitlawb", "https://opengateway.gitlawb.com/v1/xiaomi-mimo", PresetAuth::Bearer, &[("User-Agent", "OpenClaude/1.0 (linux; x86_64)"), ("X-Title", "OpenClaude CLI"), ("HTTP-Referer", "https://github.com/Gitlawb/openclaude")]),
        ("navy", "https://api.navy/v1/chat/completions", PresetAuth::Bearer, &[("User-Agent", "OmniRoute/1.0")]),
        ("routeway", "https://api.routeway.ai/v1/chat/completions", PresetAuth::Bearer, &[("User-Agent", "Mozilla/5.0 OmniRoute/1.0")]),
        ("mlx-gemma", "http://localhost:11435/v1", PresetAuth::Bearer, &[]),
        ("mlx-qwen", "http://localhost:11436/v1", PresetAuth::Bearer, &[]),
];

/// `(alias, canonical_id)` from the same registry entries.
const ALIAS_CHECK: &[(&str, &str)] = &[
    ("ds", "deepseek"),
    ("pplx", "perplexity"),
    ("oc", "opencode"),
    ("hf", "huggingface"),
    ("zm", "zenmux"),
    ("vag", "vercel-ai-gateway"),
    ("llmkiwi", "llm-kiwi"),
    ("meta", "meta-llama"),
    ("scw", "scaleway"),
    ("v0", "v0-vercel"),
    ("pn", "pioneer"),
];

#[test]
fn spot_checked_vendors_match_the_registry_byte_for_byte() {
    assert!(
        SPOT_CHECK.len() >= 25,
        "the spot-check must cover at least 25 vendors, got {}",
        SPOT_CHECK.len()
    );
    for &(id, base_url, auth, headers) in SPOT_CHECK {
        let p = find_preset(id)
            .unwrap_or_else(|| panic!("{id} is in the spot-check but missing from the catalog"));
        assert_eq!(p.id, id, "lookup returned the wrong row for {id}");
        assert_eq!(p.base_url, base_url, "base_url drift for {id}");
        assert_eq!(p.auth, auth, "auth shape drift for {id}");
        assert_eq!(p.headers, headers, "custom headers drift for {id}");
    }
}

#[test]
fn every_spot_checked_vendor_appears_exactly_once() {
    for &(id, ..) in SPOT_CHECK {
        let hits = PRESET_PROVIDERS.iter().filter(|p| p.id == id).count();
        assert_eq!(hits, 1, "{id} appears {hits} times in the catalog");
    }
}

#[test]
fn lookup_is_case_insensitive() {
    for &(id, base_url, ..) in SPOT_CHECK.iter().take(10) {
        // UPPER, lower, and a hand-mixed Title-Case: a case-folding bug that
        // only mishandles one of those would otherwise slip through.
        let mut mixed = String::with_capacity(id.len());
        let mut start_of_word = true;
        for ch in id.chars() {
            if ch == '-' || ch == '_' {
                start_of_word = true;
                mixed.push(ch);
            } else if start_of_word {
                mixed.extend(ch.to_uppercase());
                start_of_word = false;
            } else {
                mixed.push(ch);
            }
        }
        let probes: Vec<String> = vec![id.to_ascii_uppercase(), id.to_ascii_lowercase(), mixed];
        for probe in probes {
            assert_eq!(
                find_preset(&probe).map(|p| p.base_url),
                Some(base_url),
                "case-insensitive lookup failed for {probe}"
            );
        }
    }
}

#[test]
fn lookup_resolves_registry_aliases() {
    assert!(!ALIAS_CHECK.is_empty());
    for &(alias, canonical) in ALIAS_CHECK {
        let p = find_preset(alias).unwrap_or_else(|| panic!("alias {alias} does not resolve"));
        assert_eq!(
            p.id, canonical,
            "alias {alias} resolved to the wrong vendor"
        );
        // An alias must not shadow a real id: resolving the canonical id has
        // to land on the same row, and it must not be reachable by any other
        // vendor's alias.
        assert_eq!(find_preset(canonical).map(|q| q.id), Some(canonical));
    }
}

#[test]
fn alias_lookup_is_case_insensitive_too() {
    for &(alias, canonical) in ALIAS_CHECK {
        assert_eq!(
            find_preset(&alias.to_ascii_uppercase()).map(|p| p.id),
            Some(canonical),
            "upper-cased alias {alias} did not resolve"
        );
    }
}

#[test]
fn catalog_ids_are_unique() {
    let mut ids: Vec<&str> = PRESET_PROVIDERS.iter().map(|p| p.id).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "the catalog contains a duplicate id");
}

#[test]
fn aliases_are_unique_and_all_point_at_a_real_vendor() {
    let mut aliases: Vec<&str> = PRESET_ALIASES.iter().map(|(a, _)| *a).collect();
    let total = aliases.len();
    aliases.sort_unstable();
    aliases.dedup();
    assert_eq!(
        aliases.len(),
        total,
        "the alias table contains a duplicate alias"
    );

    for &(alias, canonical) in PRESET_ALIASES {
        let p = find_preset(canonical)
            .unwrap_or_else(|| panic!("alias {alias} points at unknown vendor {canonical}"));
        assert_eq!(
            p.id, canonical,
            "alias {alias} points at a row whose id differs"
        );
    }
}

#[test]
fn no_alias_shadows_a_catalog_id() {
    // Otherwise `find_preset` would answer two different vendors with the
    // same input, and the id scan silently wins for one of them.
    for p in PRESET_PROVIDERS {
        assert!(
            !PRESET_ALIASES
                .iter()
                .any(|(a, _)| a.eq_ignore_ascii_case(p.id)),
            "alias shadows catalog id {}",
            p.id
        );
    }
}

#[test]
fn every_row_is_internally_well_formed() {
    for p in PRESET_PROVIDERS {
        assert!(!p.id.is_empty(), "empty id");
        assert_eq!(
            p.id.to_ascii_lowercase(),
            p.id,
            "id {} is not lowercase, so case-insensitive lookup would be ambiguous",
            p.id
        );
        assert!(!p.display_name.is_empty(), "{} has no display name", p.id);
        assert!(
            p.base_url.starts_with("https://") || p.base_url.starts_with("http://"),
            "{} has a non-HTTP base_url {:?}",
            p.id,
            p.base_url
        );
        if let PresetAuth::ApiKeyHeader(name) = p.auth {
            assert!(
                !name.is_empty(),
                "{} has an empty api-key header name",
                p.id
            );
            assert!(
                !name.contains(char::is_whitespace),
                "{} has whitespace in its api-key header name {:?}",
                p.id,
                name
            );
        }
        for &(k, v) in p.headers {
            assert!(
                !k.is_empty() && !v.is_empty(),
                "{} has an empty header",
                p.id
            );
        }
    }
}

#[test]
fn no_row_carries_a_bearer_prefix_in_its_auth() {
    // `PresetAuth::Bearer` already *is* `Authorization: Bearer <key>`, so a
    // row that also spelled the scheme out in its custom headers would send
    // the prefix twice.
    for p in PRESET_PROVIDERS {
        for &(k, v) in p.headers {
            assert!(
                !(k.eq_ignore_ascii_case("authorization")
                    && v.to_ascii_lowercase().contains("bearer")),
                "{} would send a doubled Bearer prefix",
                p.id
            );
        }
    }
}

#[test]
fn unknown_and_excluded_ids_do_not_resolve_to_a_preset() {
    // `None` is the load-bearing answer for the excluded classes: the caller
    // must fall through to a dedicated bridge rather than get a preset that
    // describes a browser port or a placeholder URL.
    for id in [
        "",
        "not-a-vendor",
        // web scrapers
        "chatgpt-web",
        "grok-web",
        "tinycms-web",
        "zai-web",
        "duckduckgo-web",
        // yellow zone / already bridged
        "cline",
        "clinepass",
        "qoder",
        "grok-cli",
        "codex",
        "xai-oauth",
        "devin-desktop",
        "codebuddy-cn",
        // oauth-only, no expressible auth shape
        "github",
        "gitlab-duo",
        "kilocode",
        "trae",
        // non-REST or non-callable base_url
        "cloudflare-ai",
        "cloudflare-playground",
        "uc",
        "maxai",
        "promptql",
        "snowflake",
        "bedrock",
        // endpoints the family bridge cannot reach
        "command-code",
        "free-ai",
        "inner-ai",
        "muse-code",
        "nlpcloud",
        "oneminai",
    ] {
        assert!(
            find_preset(id).is_none(),
            "{id} must not resolve to a preset"
        );
    }
}

#[test]
fn no_alias_points_at_an_excluded_vendor() {
    // "pql" was promptql's registry alias; the vendor is excluded, so the
    // alias must be gone with it rather than dangling into the table — and
    // an alias that resolved would be the worst kind of leak, because
    // `aliases_are_unique_and_all_point_at_a_real_vendor` only proves the
    // target EXISTS, never that it belongs in the catalog. `cmd`,
    // `nlpc`, `in-ai` and `1min` are the four this has already caught.
    for (class, ids) in EXCLUDED_IDS {
        for (alias, canonical) in PRESET_ALIASES {
            assert!(
                !ids.contains(canonical),
                "alias {alias} -> {canonical} points into the {class:?} exclusion class; drop \
                 the alias with the row"
            );
        }
    }
    assert!(find_preset("pql").is_none());
    assert!(find_preset("cmd").is_none());
    assert!(find_preset("nlpc").is_none());
    assert!(find_preset("in-ai").is_none());
    assert!(find_preset("1min").is_none());
}

#[test]
fn the_none_auth_shape_is_representable() {
    // No catalog row uses it — every keyless vendor in the registry is a
    // browser or socket port we exclude. The variant is still part of the
    // contract, so assert it is distinguishable from the other two rather
    // than equal to either, which is what the admin serializer's match on.
    let local = PresetProvider {
        id: "local-probe",
        display_name: "Local Probe",
        base_url: "http://localhost:11434/v1",
        auth: PresetAuth::None,
        headers: &[],
    };
    assert_ne!(local.auth, PresetAuth::Bearer);
    assert_ne!(local.auth, PresetAuth::ApiKeyHeader("Authorization"));
    assert!(PRESET_PROVIDERS.iter().all(|p| p.auth != PresetAuth::None));
}

/// Vendors the source registry carries that the catalog deliberately
/// leaves out, by exclusion class. The point of this list is not to
/// document the classes — the module docs do that — but to make the
/// decision *mechanically* checkable: a row added from one of these classes
/// fails here, so the catalog cannot be padded toward a number without a
/// test going red. Kept in the same order as the module's exclusion
/// bullets, with the per-class counts the reconciliation is derived from.
const EXCLUDED_IDS: &[(&str, &[&str])] = &[
    // already-bridged vendors and their registry twins (18)
    (
        "already-bridged",
        &[
            "agy",
            "antigravity",
            "cline",
            "clinepass",
            "codebuddy-cn",
            "codex",
            "codex-app-server",
            "cursor",
            "cursor-api",
            "devin-cli",
            "devin-cli-agentic",
            "devin-desktop",
            "ghe-copilot",
            "grok-cli",
            "kiro",
            "qoder",
            "xai-oauth",
            "zed-hosted",
        ],
    ),
    // web scrapers / cookie-auth entries / browser-driven ports (24)
    (
        "web-scraper",
        &[
            "adapta-web",
            "auggie",
            "chatgpt-web",
            "chatgpt-web-codex",
            "conol-web",
            "copilot-m365-web",
            "copilot-web",
            "duckduckgo-web",
            "grok-web",
            "huggingchat",
            "hyperagent",
            "lmarena",
            "maxai",
            "muse-spark-web",
            "notion-web",
            "t3-web",
            "tencent-aistudio-web",
            "tinycms-web",
            "udio",
            "veoaifree-web",
            "yuanbao-web",
            "zai-web",
            "zcode",
            "zenmux-free",
        ],
    ),
    // non-OpenAI wire formats (11)
    (
        "non-openai-format",
        &[
            "agentrouter",
            "anthropic",
            "bailian-coding-plan",
            "clova-studio",
            "deepai",
            "gemini",
            "magnific",
            "tabitoken",
            "vertex",
            "wafer",
            "zai",
        ],
    ),
    // oauth-only upstreams (6)
    (
        "oauth-only",
        &[
            "claude",
            "github",
            "gitlab-duo",
            "kilocode",
            "openference",
            "trae",
        ],
    ),
    // non-REST or non-callable `base_url` (7)
    (
        "non-callable-url",
        &[
            "bedrock",
            "cloudflare-ai",
            "cloudflare-playground",
            "databricks",
            "promptql",
            "snowflake",
            "uc",
        ],
    ),
    // endpoints the OpenAI family bridge cannot reach (6), for two provable
    // reasons. (1) The row's `base_url` already ends in a path segment that
    // is not one of the seven OpenAI operations `strip_known_endpoint`
    // knows, so the family bridge extends it into a URL the vendor does not
    // serve (`…/v1/responses/chat/completions`,
    // `…/chat-with-ai/chat/completions`, `…/chat/chat/completions`) —
    // `free-ai`, `inner-ai`, `muse-code`, `oneminai`. (2) The reference
    // reaches the vendor on a path the bridge cannot produce at all:
    // `command-code`'s registry `chatPath` is
    // `/provider/v1/chat/completions` (and `executors/commandCode.ts`
    // appends it to the base), and `executors/nlpcloud.ts` builds
    // `<base>/<model>/chatbot` — so `<base_url>/chat/completions` is a URL
    // the reference never requests for either. The criterion is
    // "provable from the reference source", never a guess about a live
    // vendor. `every_row_dispatches_to_its_own_base_url` is the invariant
    // that keeps the class honest; this list is what stops a row that now
    // qualifies from being re-added on autopilot.
    (
        "family-bridge-unreachable",
        &[
            "command-code",
            "free-ai",
            "inner-ai",
            "muse-code",
            "nlpcloud",
            "oneminai",
        ],
    ),
    // a second id for an endpoint the catalog already carries (1). The
    // registry spells this vendor twice; counting it as another vendor
    // inflates the total without adding a reachable endpoint, and it is
    // the concrete shape several of the differences between a raw registry
    // count and a vendor count take.
    ("duplicate-endpoint", &["kimi-k3"]),
];

/// Ids that share one `base_url` on purpose: the source registry spells
/// each of these vendors twice. Every repeated endpoint in the catalog is
/// one of these pairs — an unexplained duplicate is a row that inflates
/// the total without adding reachability, which is the whole reason a raw
/// registry count and a vendor count disagree.
const ENDPOINT_FAMILIES: &[&[&str]] = &[
    &["alibaba", "qwen-cloud"],
    &["baidu", "qianfan"],
    &["doubao", "volcengine"],
    &["iflytek", "sparkdesk"],
    &["kimi", "moonshot"],
    &["naga-ac", "naga-ai"],
];

#[test]
fn the_catalog_is_the_reconciled_size() {
    // A decision, not a placeholder: the module's "Reconciling the count"
    // section derives 184 from the source registry by subtracting each
    // exclusion class. A count larger than the source is not a count of a
    // subset, so there is no pool of "missing" vendors to add — and the
    // assertions below are what make that a hard failure rather than a
    // comment.
    assert_eq!(
        PRESET_PROVIDERS.len(),
        super::presets::PRESET_PROVIDER_COUNT
    );
    assert_eq!(
        PRESET_PROVIDERS.len(),
        184,
        "the catalog size changed; update the reconciliation table in the module docs in the same \
         commit, with the per-class counts that justify the new number"
    );
}

#[test]
fn the_excluded_classes_are_still_excluded() {
    for (class, ids) in EXCLUDED_IDS {
        for id in *ids {
            assert!(
                find_preset(id).is_none(),
                "{id:?} belongs to the {class:?} exclusion class and must not be in the catalog; \
                 if it now qualifies, delete it from EXCLUDED_IDS and say why in the module docs"
            );
        }
    }
    // The duplicate-endpoint class is not just an exclusion: `kimi-k3`
    // resolves nowhere NEW. The ids it shadows are present, and present
    // the same endpoint — which is what makes it a model tier rather than
    // a vendor.
    let shadowed = ["kimi", "moonshot"];
    let endpoints: std::collections::BTreeSet<&str> = shadowed
        .iter()
        .map(|canonical| {
            find_preset(canonical)
                .unwrap_or_else(|| {
                    panic!("{canonical:?} is named as the canonical row for kimi-k3")
                })
                .base_url
        })
        .collect();
    assert_eq!(
        endpoints.len(),
        1,
        "kimi-k3 duplicates {} — which do not share one endpoint",
        shadowed.join(", ")
    );
    // The guarded sets must sum to what the module's reconciliation table
    // claims, so the documented arithmetic cannot drift from them.
    let excluded: usize = EXCLUDED_IDS.iter().map(|(_, ids)| ids.len()).sum();
    assert_eq!(
        excluded,
        73,
        "the exclusion classes no longer sum to the 73 the module docs subtract"
    );
    assert_eq!(
        EXCLUDED_IDS.len(),
        7,
        "a new exclusion class needs a matching bullet in the module docs"
    );
}

/// The rows whose `base_url` is a **base** the family bridge extends, rather
/// than the full chat-completions endpoint the row already names. Every other
/// row is a full endpoint, which is 169 of 184 and the reason nothing in the
/// product has to know about this list.
///
/// Listing the bases is what makes the contract checkable in both
/// directions: a row that is neither a full endpoint nor a declared base is a
/// row the bridge would extend into a URL the vendor does not serve, and a
/// declared base the bridge now reproduces verbatim is a stale entry rather
/// than a silent pass. Membership is transcribed from the source registry's
/// `baseUrl` — the same field either form is taken from.
const BASE_URL_ROWS: &[&str] = &[
    "dify",
    "freebuff",
    "gigachat",
    "gitlawb",
    "haiper",
    "ideogram",
    "leonardo",
    "maritalk",
    "mlx-gemma",
    "mlx-qwen",
    "opencode",
    "regolo",
    "uc-direct",
    "xiaomi-mimo",
    "xiaomi-mimo-token-plan",
];

/// Path segments a vendor never publishes as a BASE, because by the time a
/// path ends in one of them it IS the operation, not a prefix. The reference
/// draws the same line and in the same words:
/// `open-sse/executors/default/urlNormalizers.ts` returns `…/chat` and
/// `…/responses` **verbatim** rather than extending them, because appending
/// an operation to a complete endpoint is the doubling the
/// `family-bridge-unreachable` class exists for.
const OPERATION_SEGMENTS: &[&str] = &["chat", "responses", "completions"];

/// The catalog's central promise, held against the code that has to honour
/// it: pasting `base_url` into a ProviderKey's `api_base` must make the
/// family bridge dispatch to the URL the catalog names.
///
/// Two forms satisfy it, and both are the reference's own forms:
///
/// * a **full endpoint** — `strip_known_endpoint` + `/chat/completions` is
///   the identity on it, so the dispatched URL is byte-identical to
///   `base_url`. Asserted on every row that is one.
/// * a **base** listed in [`BASE_URL_ROWS`] — the bridge appends
///   `/chat/completions`, and the dispatched URL is
///   `<base_url>/chat/completions`.
///
/// A base that already names an operation fails even when it is listed: a
/// base ending in `/chat` is an endpoint, and extending it is the
/// `…/chat/chat/completions` doubling that put `free-ai`, `inner-ai`,
/// `muse-code` and `oneminai` in the `family-bridge-unreachable` class. The
/// class's other two members (`command-code`, `nlpcloud`) are not caught by
/// this rule — their `base_url` is a clean base — but by the registry's own
/// `chatPath` and by `executors/nlpcloud.ts`, so no amount of reading the
/// base alone can rescue them. That is why the class is documented as two
/// reasons and not one.
#[test]
fn every_row_dispatches_to_its_own_base_url() {
    for p in PRESET_PROVIDERS {
        let dispatched = format!(
            "{}/chat/completions",
            super::bridge::resolve_base_for(p.id, p.base_url)
        );
        if dispatched == p.base_url {
            assert!(
                !BASE_URL_ROWS.contains(&p.id),
                "{}: declared a base, but the bridge now reproduces the catalog URL verbatim — \
                 remove it from BASE_URL_ROWS",
                p.id
            );
            continue;
        }
        assert!(
            BASE_URL_ROWS.contains(&p.id),
            "{}: the bridge dispatched to {dispatched:?}, which is neither the catalog's URL nor \
             a base the catalog declares. Either the row is a full endpoint the bridge can \
             reproduce (fix `base_url`), or it is a base (add it to BASE_URL_ROWS) — a row the \
             family bridge extends into a URL the vendor does not serve is the \
             `family-bridge-unreachable` exclusion class, not a catalog row.",
            p.id
        );
        assert_eq!(
            dispatched,
            format!("{}/chat/completions", p.base_url.trim_end_matches('/')),
            "{}: the bridge did not extend the declared base either — the two readings of \
             base_url disagree",
            p.id
        );
        let last_segment = p
            .base_url
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default();
        assert!(
            !OPERATION_SEGMENTS.contains(&last_segment),
            "{}: base_url {:?} already ends in the {last_segment:?} operation, so it is an \
             endpoint the family bridge cannot reproduce — the bridge would dispatch to \
             {dispatched:?}. Exclude the row or teach the bridge the vendor's path; do not \
             widen OPENAI_ENDPOINT_SUFFIXES to hide it.",
            p.id,
            p.base_url
        );
    }
    for id in BASE_URL_ROWS {
        let p = find_preset(id)
            .unwrap_or_else(|| panic!("BASE_URL_ROWS names unknown id {id:?}"));
        assert_ne!(
            format!(
                "{}/chat/completions",
                super::bridge::resolve_base_for(p.id, p.base_url)
            ),
            p.base_url,
            "{id} is listed as a base but the bridge reproduces it as a full endpoint — the \
             list has a dead entry"
        );
    }
}

/// Every declared non-Bearer shape names something the bridge can actually
/// build a header from, and the two shapes stay distinguishable. `maritalk`
/// is why they are separate variants: its registry value `key` is an
/// `Authorization` SCHEME, so a consumer that reads one shape as the other
/// sends the secret to a header the vendor never reads — and the type is
/// the only place that distinction is still provable.
#[test]
fn a_non_bearer_auth_shape_is_a_valid_header_name() {
    for p in PRESET_PROVIDERS {
        match p.auth {
            PresetAuth::Bearer | PresetAuth::None => continue,
            PresetAuth::ApiKeyHeader(name) => assert!(
                http::HeaderName::from_bytes(name.as_bytes()).is_ok(),
                "{}: {name:?} is catalogued as a header name but is not one",
                p.id
            ),
            PresetAuth::AuthorizationScheme(scheme) => {
                assert!(
                    !scheme.is_empty() && !scheme.contains(char::is_whitespace),
                    "{}: {scheme:?} is catalogued as an Authorization scheme but is not one",
                    p.id
                );
                assert!(
                    !scheme.eq_ignore_ascii_case("bearer"),
                    "{}: Bearer is its own variant; spelling it out here would render the \
                     prefix twice",
                    p.id
                );
            }
        }
    }
}

#[test]
fn every_row_is_a_plain_rest_endpoint() {
    // The mechanical half of the "non-REST / non-callable" exclusion: a
    // socket, a stdio bridge, a custom scheme or an un-substituted
    // placeholder host is a row whose `base_url` a provider key cannot be
    // pointed at, so it fails on the first real request.
    for p in PRESET_PROVIDERS {
        assert!(
            p.base_url.starts_with("https://") || p.base_url.starts_with("http://localhost"),
            "{}: base_url {:?} is not a plain REST endpoint",
            p.id,
            p.base_url
        );
        assert!(
            !p.base_url.contains('{')
                && !p.base_url.contains('<')
                && !p.base_url.contains("00000000"),
            "{}: base_url {:?} still carries a placeholder host or path",
            p.id,
            p.base_url
        );
        // A fabricated no-op credential reads as "this vendor needs no
        // key", which is a different — and wrong — answer.
        assert_ne!(
            p.auth,
            PresetAuth::None,
            "{}: no preset uses PresetAuth::None; the keyless ports are all excluded",
            p.id
        );
    }
}

#[test]
fn every_repeated_endpoint_is_a_known_vendor_family() {
    let mut by_url: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
    for p in PRESET_PROVIDERS {
        by_url.entry(p.base_url).or_default().push(p.id);
    }
    let families: std::collections::BTreeSet<&str> = ENDPOINT_FAMILIES
        .iter()
        .flat_map(|f| f.iter().copied())
        .collect();
    for (url, mut ids) in by_url {
        if ids.len() < 2 {
            continue;
        }
        ids.sort_unstable();
        for id in &ids {
            assert!(
                families.contains(id),
                "{url:?} is offered under {} but {id:?} is not a member of a declared vendor \
                 family; a second id for one endpoint inflates the vendor count without adding \
                 reachability — declare the family in ENDPOINT_FAMILIES or use a distinct URL",
                ids.join(", ")
            );
        }
    }
    // And every declared family really is one family, so the allowlist
    // cannot rot into permitting a duplicate.
    for family in ENDPOINT_FAMILIES {
        let urls: std::collections::BTreeSet<&str> = family
            .iter()
            .map(|id| {
                find_preset(id)
                    .unwrap_or_else(|| panic!("ENDPOINT_FAMILIES names unknown id {id:?}"))
                    .base_url
            })
            .collect();
        assert_eq!(
            urls.len(),
            1,
            "{} is declared a family but its members do not share one endpoint",
            family.join(", ")
        );
    }
}

#[test]
fn display_names_are_distinct_enough_to_pick_from() {
    // Two vendors rendering the same label make a provider picker
    // ambiguous. Ids remain unique (asserted above); this catches the
    // cosmetic half of the same problem.
    let mut names: Vec<&str> = PRESET_PROVIDERS.iter().map(|p| p.display_name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(names.len(), before, "two vendors share a display name");
}
