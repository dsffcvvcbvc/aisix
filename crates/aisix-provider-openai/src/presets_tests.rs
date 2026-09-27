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
//! vendor that is not boring: all six non-`Bearer` auth shapes and all
//! seven vendors carrying custom headers. A bug that only affects an
//! interesting row would otherwise hide behind 184 identical bearer rows.

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
        ("haiper", "https://api.haiper.ai/v1", PresetAuth::ApiKeyHeader("HAIPER_KEY"), &[]),
        ("ideogram", "https://api.ideogram.ai", PresetAuth::ApiKeyHeader("Api-Key"), &[]),
        ("maritalk", "https://chat.maritaca.ai/api", PresetAuth::ApiKeyHeader("key"), &[]),
        ("oneminai", "https://api.1min.ai/api/chat-with-ai", PresetAuth::ApiKeyHeader("api-key"), &[]),
        ("pioneer", "https://api.pioneer.ai/v1/chat/completions", PresetAuth::ApiKeyHeader("x-api-key"), &[]),
        ("uc-direct", "https://api.uncensored.com/api/v1", PresetAuth::ApiKeyHeader("x-api-key"), &[]),
        ("api-airforce", "https://api.airforce/v1/chat/completions", PresetAuth::Bearer, &[("HTTP-Referer", "https://endpoint-proxy.local"), ("X-Title", "Endpoint Proxy")]),
        ("orcarouter", "https://api.orcarouter.ai/v1/chat/completions", PresetAuth::Bearer, &[("HTTP-Referer", "https://endpoint-proxy.local"), ("X-Title", "Endpoint Proxy")]),
        ("gitlawb", "https://opengateway.gitlawb.com/v1/xiaomi-mimo", PresetAuth::Bearer, &[("User-Agent", "OpenClaude/1.0 (linux; x86_64)"), ("X-Title", "OpenClaude CLI"), ("HTTP-Referer", "https://github.com/Gitlawb/openclaude")]),
        ("navy", "https://api.navy/v1/chat/completions", PresetAuth::Bearer, &[("User-Agent", "OmniRoute/1.0")]),
        ("routeway", "https://api.routeway.ai/v1/chat/completions", PresetAuth::Bearer, &[("User-Agent", "Mozilla/5.0 OmniRoute/1.0")]),
        ("muse-code", "https://api.meta.ai/v1/responses", PresetAuth::Bearer, &[("User-Agent", "muse-build/1.3.0 (interactive; macos-aarch64; build ac7280f2aca67769d1455a8847bb502b617d50f6)")]),
        ("mlx-gemma", "http://localhost:11435/v1", PresetAuth::Bearer, &[]),
        ("mlx-qwen", "http://localhost:11436/v1", PresetAuth::Bearer, &[]),
];

/// `(alias, canonical_id)` from the same registry entries.
const ALIAS_CHECK: &[(&str, &str)] = &[
    ("ds", "deepseek"),
    ("pplx", "perplexity"),
    ("oc", "opencode"),
    ("hf", "huggingface"),
    ("1min", "oneminai"),
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
        "databricks",
        "bedrock",
    ] {
        assert!(
            find_preset(id).is_none(),
            "{id} must not resolve to a preset"
        );
    }
}

#[test]
fn alias_of_an_excluded_vendor_does_not_resolve() {
    // "pql" was promptql's registry alias; the vendor is excluded, so the
    // alias must be gone with it rather than dangling into the table.
    assert!(find_preset("pql").is_none());
    assert!(!PRESET_ALIASES.iter().any(|(a, _)| *a == "pql"));
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
    // section derives 190 from the source registry by subtracting each
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
        190,
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
        excluded, 67,
        "the exclusion classes no longer sum to the 67 the module docs subtract"
    );
    assert_eq!(
        EXCLUDED_IDS.len(),
        6,
        "a new exclusion class needs a matching bullet in the module docs"
    );
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
