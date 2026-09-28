//! Embedded catalog of standard OpenAI-compatible REST provider presets.
//!
//! Implements the AGENT.md §4.1 intent: vendors whose upstream is a plain
//! OpenAI-shaped REST endpoint need **zero custom code** — no bridge, no
//! executor. This table carries the three facts a dashboard needs to onboard
//! such a vendor, and nothing else:
//!
//! 1. the canonical `base_url` (see `PresetProvider::base_url` for the two
//!    forms it may take),
//! 2. the *shape* of the auth header (never the credential itself),
//! 3. any static non-secret headers the vendor requires on every request.
//!
//! **No secret is reachable from this table.** There is no key, no token, no
//! OAuth client id/secret anywhere in `PRESET_PROVIDERS`; the operator mints
//! those and stores them on the connection, exactly as for a hand-written
//! provider. Only base URLs, header *names*, and public header *values*
//! (User-Agent strings, OpenRouter's `HTTP-Referer`/`X-Title`) live here.
//!
//! # Scope — what is deliberately NOT here
//!
//! `base_url`/`auth`/`headers` describe an endpoint that answers a normal
//! OpenAI chat request over HTTP(S) with the caller's own API key. That
//! excludes six classes, each for a concrete reason rather than by taste:
//!
//! * **Web scrapers** — `chatgpt-web`, `grok-web`, `tinycms-web`, the
//!   cookie-auth entries (`udio`, `hyperagent`, `zenmux-free`), and the
//!   `wss://` / stdio / headless-Chromium ports (`auggie`,
//!   `zcode`). These drive a browser session, not an API; a bearer-shaped
//!   preset would be a lie about what the caller must do. `maxai` belongs
//!   here too and is the clearest case in the table: the source registry
//!   records it with a plain `baseUrl` and `apikey`/`bearer`, but its
//!   executor reproduces the web app's *signed* request with a
//!   per-request signature, Firefox identity headers and an OAuth token
//!   minted by a browser-login flow, over a residential IP only — a
//!   datacentre address is bot-banned. The registry's `baseUrl` is a
//!   constant it ignores, not an endpoint it serves.
//! * **Already-bridged vendors** — the yellow zone (`cline`,
//!   `clinepass`, `qoder`, `grok-cli`, `codex`, `agy`, `antigravity`)
//!   plus their registry twins and siblings (`xai-oauth`, `codebuddy-cn`,
//!   `devin-cli`, `devin-cli-agentic`, `devin-desktop`, `codex-app-server`,
//!   `cursor`, `cursor-api`, `kiro`, `ghe-copilot`, `zed-hosted`). They
//!   already have `Bridge` impls in this workspace; a second, weaker
//!   description of the same vendor is a second thing to keep in sync.
//! * **OAuth-only upstreams** — `github`, `gitlab-duo`, `kilocode`,
//!   `trae`, `openference`, `claude`. `PresetAuth` models "where does the
//!   key go", and OAuth needs a token-exchange lifecycle no variant can
//!   express.
//! * **Non-REST / non-callable `base_url`** — `cloudflare-ai` (the executor
//!   splices an account id into the path), `snowflake` and `databricks`
//!   (`{account}` / all-zeros placeholder hosts), `bedrock` (no URL at
//!   all — a native AWS SDK client), plus ports that need something other
//!   than a plain HTTPS request: `cloudflare-playground` (headless
//!   Chromium driving a `cf_agent` WebSocket), `uc` (a Clerk-JWT socket
//!   minted from a browser login) and `promptql` (a reverse-engineered
//!   GraphQL playground endpoint).
//! * **Endpoints the OpenAI family bridge cannot reach** — six rows, for
//!   two provable reasons, and in both the family bridge would build a URL
//!   the reference never builds for that vendor:
//!
//!   1. the row's `base_url` already ends in an operation the bridge does
//!      not know, so extending it doubles the path — `muse-code`
//!      (`…/v1/responses`, a Responses-API endpoint), `oneminai`
//!      (`…/api/chat-with-ai`, which the registry itself documents as a
//!      non-OpenAI wire format — a single `promptObject.prompt` string and
//!      `event:`/`data:` SSE framing — behind a translating executor),
//!      `inner-ai` (`…/chat`, plus a dedicated `inner-ai` executor in the
//!      reference) and `free-ai` (`…/v1/chat/`). `strip_known_endpoint`
//!      knows the seven OpenAI operations and no others, so these dispatch
//!      to `…/responses/chat/completions`, `…/chat-with-ai/chat/completions`
//!      or `…/chat/chat/completions`.
//!   2. the reference reaches the vendor on a path the bridge cannot
//!      produce at all — `command-code` (registry `chatPath:
//!      "/provider/v1/chat/completions"`, and `executors/commandCode.ts`
//!      appends it to the base) and `nlpcloud`
//!      (`executors/nlpcloud.ts` builds `<base>/<model>/chatbot`, which is
//!      model-scoped and not an OpenAI operation). For both, `<base_url>/
//!      chat/completions` is a URL the reference does not request.
//!
//!   The class is a *bridge-capability* limit, not a judgement about the
//!   vendor: `cohere` shows the shape that IS expressible (a base the bridge
//!   rewrites before extending it, see `crate::cohere`), and a row like
//!   these becomes onboardable again the day the bridge learns the vendor's
//!   operation. `presets_tests::every_row_dispatches_to_its_own_base_url`
//!   is what keeps the class from rotting in either direction.
//!
//! **Non-OpenAI wire formats** are excluded on the same grounds: the
//! entries whose registry `format` is `claude` (`anthropic`, `agentrouter`,
//! `bailian-coding-plan`, `tabitoken`, `wafer`, `zai`), `gemini`
//! (`gemini`, `vertex`), `clova` (`clova-studio`), `custom` (`deepai`) or
//! `magnific-image` (`magnific`) do not answer an OpenAI-shaped request,
//! and a `base_url` that 400s on the first real call is worse than no row.
//!
//! **A second id for an endpoint already listed** is excluded last, and it
//! is the smallest class with the most explanatory power: `kimi-k3` is a
//! registry entry whose `base_url` and auth are byte-identical to the rows
//! the table already carries under `kimi` and `moonshot`. It is a model
//! tier, not a vendor.
//!
//! # Reconciling the count — 184, and why
//!
//! An architecture spec claimed **216** "standard REST providers" (78% of
//! a claimed 274 total). The table here is **184**, and 184 is the correct
//! number; the 216 is a stale snapshot, not 32 missing vendors. Reproduced
//! against the source registry (`open-sse/config/providers/registry/*/index.ts`)
//! at the time of writing:
//!
//! ```text
//! registry entries (256 directories; `mlx/` and `tinycms/` each hold an
//!   entry under a second id, and `devin`/`segmind`/`stability-ai` hold
//!   none)                                            257
//!   less already-bridged vendors and registry twins   -18
//!   less web scrapers / cookie-auth / browser ports  -24
//!   less non-OpenAI wire formats                      -11
//!   less oauth-only upstreams                         -6
//!   less non-REST or non-callable `base_url`          -7
//!   less endpoints the family bridge cannot reach     -6
//!   less a second id for an endpoint already listed   -1
//!                                                    -----
//! PRESET_PROVIDERS                                    184
//! ```
//!
//! `184 = 257 − 73`, and `presets_tests::the_excluded_classes_are_still_
//! excluded` asserts the classes sum to exactly 73, so this arithmetic and
//! the guarded set cannot drift apart.
//!
//! The classes that moved, and why, are settled by the source registry's
//! own text rather than by a re-run judgement:
//!
//! * **endpoints the family bridge cannot reach is new**, and holds six
//!   rows: `muse-code`, `oneminai`, `inner-ai` and `free-ai` because their
//!   `base_url` ends in a path segment outside the seven OpenAI operations
//!   the bridge knows, plus `command-code` and `nlpcloud` because the
//!   reference reaches them on a path the bridge cannot produce at all (see
//!   the scope bullet above).
//!   `presets_tests::every_row_dispatches_to_its_own_base_url` is what makes
//!   the class mechanical rather than a comment: a row that would be
//!   extended into a URL its vendor does not serve fails that test, and a
//!   row that *is* expressible fails the `EXCLUDED_IDS` guard, so neither
//!   side of the class can rot.
//!
//! Three facts make the 216 unreproducible rather than merely optimistic:
//!
//! * **The set is closed.** Every one of the 184 ids is a registry entry
//!   id, and the registry contributes nothing that is not accounted for
//!   above — so there is no pool of 32 un-added vendors to draw from. A
//!   count larger than its source is not a count of a subset.
//! * **The source has moved.** The registry the 216 was measured against
//!   predates the current one; the same spec's total-provider figure is
//!   stale in the same way.
//! * **The registry counts aliases separately.** `kimi-k3` is a second
//!   entry id for an endpoint the table already carries twice (`kimi` and
//!   `moonshot`, byte-identical `base_url` and auth). Counting it as a
//!   vendor inflates the total without adding a reachable endpoint — which
//!   is the shape several of the differences between the two numbers have.
//!
//! So the number is pinned as a decision with a derivation rather than as a
//! bare count: `presets_tests` asserts the total, asserts every row is a
//! well-formed REST endpoint, and asserts that no id belonging to an
//! excluded class has crept in — the guard that makes padding the table
//! fail rather than merely look better.
//!
//! A consequence worth knowing: no entry here uses `PresetAuth::None`. The
//! only `authType: "none"` vendors in the registry are the browser/socket
//! ports above, which are excluded. The variant stays because local,
//! keyless OpenAI-compatible servers (Ollama, LM Studio) are the obvious next
//! thing to add, and the dashboard serializer has to handle them anyway.
//!
//! # Lookup
//!
//! [`find_preset`] is case-insensitive and also resolves the legacy short
//! aliases vendors were registered under (62 of them, in
//! [`PRESET_ALIASES`]) so an old config or a copied `model` string keeps
//! resolving. It is a linear scan: the table is a few hundred short strings,
//! this is a dashboard/selection path rather than a per-token hot path, and a
//! scan needs no allocation and no unsafe.

/// The shape of the credential a preset provider expects on the wire.
///
/// The value is never stored here — only *where it goes*. See the module
/// docs on why no secret is reachable from this crate's preset table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetAuth {
    /// `Authorization: Bearer <key>`. The default OpenAI-compatible shape,
    /// and what 181 of the 184 `PRESET_PROVIDERS` entries use.
    ///
    /// A registry `authHeader` this table does NOT spell literally falls
    /// here, and that is the reference's own rule rather than a second
    /// opinion about the vendor: `open-sse/executors/default.ts` and
    /// `open-sse/services/provider.ts` — the two independent places the
    /// reference builds chat-surface auth from a registry entry — honour
    /// `x-api-key`, `key` and `x-goog-api-key` by name and
    /// **Bearer-fall-back on everything else**. `haiper`'s `HAIPER_KEY` and
    /// `ideogram`'s `Api-Key` are honoured only by the reference's image and
    /// video generation handlers, never by a chat path, so a chat row that
    /// declared them would promise a header nothing sends.
    Bearer,
    /// The key goes out in a header that is **not** `Authorization: Bearer`:
    /// `<name>: <key>`. The payload is a header NAME, which is why it
    /// cannot share a variant with [`PresetAuth::AuthorizationScheme`].
    ///
    /// Exactly two of the 184 entries need this — `pioneer` and
    /// `uc-direct`, both `x-api-key` — and both are cases where the
    /// reference's generic arm agrees, because the registry value *is* one
    /// of the two names that arm honours. Each vendor's own registry
    /// comment says the same in prose (`pioneer`: "Bearer also accepted
    /// upstream"; `uc-direct`: "NOT Bearer").
    ApiKeyHeader(&'static str),
    /// The key goes out in `Authorization` under a scheme that is **not**
    /// `Bearer`: `Authorization: <scheme> <key>`. The payload is a scheme
    /// name, NOT a header name.
    ///
    /// There is exactly one such entry, `maritalk`, whose registry value is
    /// `key` — the upstream expects `Authorization: Key <key>`. BOTH of the
    /// reference's chat-surface auth builders make the same distinction:
    /// `executors/default.ts` with a hard-coded per-vendor case (`case
    /// "maritalk": headers["Authorization"] = \`Key ${token}\`;`) and
    /// `services/provider.ts` generically (`else if (authHeader === "key")
    /// headers["Authorization"] = \`Key ${token}\`;`). Merging the two shapes
    /// back into one variant loses exactly that fact: a consumer that
    /// honours `ApiKeyHeader("key")` literally puts the secret in a header
    /// named `key`, which the vendor does not read.
    AuthorizationScheme(&'static str),
    /// No credential is sent. Unused by the current table — see the module
    /// docs — but part of the contract so keyless local servers can be
    /// onboarded without another breaking change.
    None,
}

// The table below is 184 rows; spelling the common shapes in short keeps it
// scannable and diffable.
use PresetAuth::{ApiKeyHeader, AuthorizationScheme, Bearer};

/// A vendor whose upstream is a plain OpenAI-shaped REST endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresetProvider {
    /// Canonical vendor id, as the dashboard and `config.example.yaml`
    /// spell it. Lowercase; the lookup key.
    pub id: &'static str,
    /// Human label for provider pickers.
    pub display_name: &'static str,
    /// **The rule: `base_url` is a BASE.** Point the connection's `api_base`
    /// at it and the OpenAI family bridge appends `/chat/completions` to
    /// reach the vendor's chat endpoint.
    ///
    /// A full endpoint is *tolerated* on the way in, not published as the
    /// contract: the bridge's `strip_known_endpoint` removes a known OpenAI
    /// operation (`/chat/completions`, `/embeddings`, …) before extending,
    /// so `https://api.openai.com/v1/chat/completions` and
    /// `https://api.openai.com/v1` both dispatch to the same place. The
    /// reference draws the same line in the same words, with
    /// `stripTrailingSlashes(...).replace(/\/chat\/(?:completions|inference)$/,
    /// "")` before re-appending — see `open-sse/config/maritalk.ts`'s
    /// `normalizeMaritalkBaseUrl` / `buildMaritalkChatUrl`, and
    /// `open-sse/executors/default/urlNormalizers.ts`'s
    /// `normalizeXiaomiMimoChatUrl`.
    ///
    /// Because the source registry spells the field inconsistently — 169 of
    /// these rows are the full endpoint and 15 are a base, both taken
    /// byte-identical from `open-sse/config/providers/registry/*/index.ts` —
    /// `presets_tests::BASE_URL_ROWS` names the base-form rows explicitly
    /// and `every_row_dispatches_to_its_own_base_url` holds both forms
    /// against `bridge::resolve_base_for` itself.
    ///
    /// What is NOT a valid `base_url` is a path whose trailing segment
    /// already names a different operation (`/v1/responses`, `/chat`,
    /// `/api/chat-with-ai`) or a chat path the bridge cannot produce at all
    /// (`command-code`'s `/provider/v1/chat/completions`, `nlpcloud`'s
    /// `/<model>/chatbot`): extending such a row yields a URL the vendor
    /// does not serve. Those vendors are in the
    /// *endpoints the OpenAI family bridge cannot reach* exclusion class.
    /// Cohere shows the shape that IS expressible: a base the bridge
    /// rewrites before extending it (`crate::cohere`).
    pub base_url: &'static str,
    /// Which header carries the credential — see [`PresetAuth`].
    pub auth: PresetAuth,
    /// Static non-secret headers every request to this vendor must carry,
    /// e.g. `HTTP-Referer`/`X-Title` for OpenRouter. Empty when the
    /// endpoint needs nothing beyond `auth`.
    pub headers: &'static [(&'static str, &'static str)],
}

const fn preset(
    id: &'static str,
    display_name: &'static str,
    base_url: &'static str,
    auth: PresetAuth,
    headers: &'static [(&'static str, &'static str)],
) -> PresetProvider {
    PresetProvider {
        id,
        display_name,
        base_url,
        auth,
        headers,
    }
}

/// Every onboardable zero-custom-code vendor, sorted by `id`.
#[rustfmt::skip]
pub const PRESET_PROVIDERS: &[PresetProvider] = &[
    preset("agnes", "Agnes", "https://apihub.agnes-ai.com/v1/chat/completions", Bearer, &[]),
    preset("ai21", "AI21", "https://api.ai21.com/studio/v1/chat/completions", Bearer, &[]),
    preset("aihorde", "AI Horde", "https://oai.aihorde.net/v1/chat/completions", Bearer, &[]),
    preset("aimlapi", "AIMLAPI", "https://api.aimlapi.com/v1/chat/completions", Bearer, &[]),
    preset("ainative", "AI Native", "https://api.ainative.studio/api/v1/chat/completions", Bearer, &[]),
    preset("aion", "Aion Labs", "https://api.aionlabs.ai/v1/chat/completions", Bearer, &[]),
    preset("alibaba", "Alibaba DashScope (Intl)", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions", Bearer, &[]),
    preset("ant-ling", "Ant Ling", "https://api.ant-ling.com/v1/chat/completions", Bearer, &[]),
    preset("anyapi", "AnyAPI", "https://api.anyapi.ai/v1/chat/completions", Bearer, &[]),
    preset("api-airforce", "Airforce", "https://api.airforce/v1/chat/completions", Bearer, &[("HTTP-Referer", "https://endpoint-proxy.local"), ("X-Title", "Endpoint Proxy")]),
    preset("arcee-ai", "Arcee AI", "https://api.arcee.ai/api/v1/chat/completions", Bearer, &[]),
    preset("auriko", "Auriko", "https://api.auriko.ai/v1/chat/completions", Bearer, &[]),
    preset("bai", "Bai", "https://api.b.ai/v1/chat/completions", Bearer, &[]),
    preset("baichuan", "Baichuan", "https://api.baichuan-ai.com/v1/chat/completions", Bearer, &[]),
    preset("baidu", "Baidu Qianfan", "https://qianfan.baidubce.com/v2/chat/completions", Bearer, &[]),
    preset("baseten", "Baseten", "https://inference.baseten.co/v1/chat/completions", Bearer, &[]),
    preset("bazaarlink", "BazaarLink", "https://bazaarlink.ai/api/v1/chat/completions", Bearer, &[]),
    preset("blackbox", "Blackbox", "https://api.blackbox.ai/v1/chat/completions", Bearer, &[]),
    preset("bluesminds", "Bluesminds", "https://api.bluesminds.com/v1/chat/completions", Bearer, &[]),
    preset("byteplus", "Byteplus", "https://ark.ap-southeast.bytepluses.com/api/v3/chat/completions", Bearer, &[]),
    preset("bytez", "Bytez", "https://api.bytez.com/models/v2/openai/v1/chat/completions", Bearer, &[]),
    preset("cerebras", "Cerebras", "https://api.cerebras.ai/v1/chat/completions", Bearer, &[]),
    preset("charm-hyper", "Charm Hyper", "https://hyper.charm.land/v1/chat/completions", Bearer, &[]),
    preset("chat-oripe", "Chat Oripe", "https://api.oriper.com/v1/chat/completions", Bearer, &[]),
    preset("chatanywhere", "ChatAnywhere", "https://api.chatanywhere.org/v1/chat/completions", Bearer, &[]),
    preset("cheaperinference", "Cheaper Inference", "https://api.cheaperinference.com/v1/chat/completions", Bearer, &[]),
    preset("chenzk", "Chenzk", "https://chenzk.top/v1/chat/completions", Bearer, &[]),
    preset("chutes", "Chutes", "https://llm.chutes.ai/v1/chat/completions", Bearer, &[]),
    preset("cloudcode-one", "Cloudcode One", "https://api.cloudcode.one/v1/chat/completions", Bearer, &[]),
    preset("codestral", "Codestral", "https://codestral.mistral.ai/v1/chat/completions", Bearer, &[]),
    preset("cohere", "Cohere", "https://api.cohere.com/compatibility/v1/chat/completions", Bearer, &[]),
    preset("coze", "Coze", "https://api.coze.com/v1/chat/completions", Bearer, &[]),
    preset("crof", "Crof", "https://crof.ai/v1/chat/completions", Bearer, &[]),
    preset("dahl", "Dahl", "https://inference.dahl.global/v1/chat/completions", Bearer, &[]),
    preset("deepinfra", "Deepinfra", "https://api.deepinfra.com/v1/openai/chat/completions", Bearer, &[]),
    preset("deepseek", "DeepSeek", "https://api.deepseek.com/chat/completions", Bearer, &[]),
    preset("dgrid", "DGrid", "https://api.dgrid.ai/v1/chat/completions", Bearer, &[]),
    preset("dify", "Dify", "https://api.dify.ai", Bearer, &[]),
    preset("digitalocean", "DigitalOcean", "https://inference.do-ai.run/v1/chat/completions", Bearer, &[]),
    preset("dit", "Dit", "https://api.dit.ai/v1/chat/completions", Bearer, &[]),
    preset("doubao", "Doubao", "https://ark.cn-beijing.volces.com/api/v3/chat/completions", Bearer, &[]),
    preset("dxnt", "DXNT", "https://www.dxnt.com/v1/chat/completions", Bearer, &[]),
    preset("electronhub", "ElectronHub", "https://api.electronhub.ai/v1/chat/completions", Bearer, &[]),
    preset("eurouter", "EuroRouter", "https://api.eurouter.ai/v1/chat/completions", Bearer, &[]),
    preset("factory", "Factory", "https://api.factory.ai/v1/chat/completions", Bearer, &[]),
    preset("fastrouter", "Fastrouter", "https://api.fastrouter.ai/api/v1/chat/completions", Bearer, &[]),
    preset("featherless-ai", "Featherless AI", "https://api.featherless.ai/v1/chat/completions", Bearer, &[]),
    preset("fireworks", "Fireworks", "https://api.fireworks.ai/inference/v1/chat/completions", Bearer, &[]),
    preset("freeaiapikey", "FreeAI API Key", "https://api.freeaiapikey.com/v1/chat/completions", Bearer, &[]),
    preset("freebuff", "Codebuff Free", "https://www.codebuff.com/api/v1", Bearer, &[]),
    preset("freeinference", "Freeinference", "https://freeinference.org/v1/chat/completions", Bearer, &[]),
    preset("freemodel-dev", "FreeModel.dev", "https://api.freemodel.dev/v1/chat/completions", Bearer, &[]),
    preset("freetheai", "Freetheai", "https://api.freetheai.xyz/v1/chat/completions", Bearer, &[]),
    preset("friendliai", "FriendliAI", "https://api.friendli.ai/serverless/v1/chat/completions", Bearer, &[]),
    preset("g4f-gemini", "GPT4Free Gemini", "https://g4f.space/api/gemini/v1/chat/completions", Bearer, &[]),
    preset("g4f-groq", "GPT4Free Groq", "https://g4f.space/api/groq/v1/chat/completions", Bearer, &[]),
    preset("g4f-nvidia", "GPT4Free NVIDIA", "https://g4f.space/api/nvidia/v1/chat/completions", Bearer, &[]),
    preset("g4f-ollama", "GPT4Free Ollama", "https://g4f.space/api/ollama/v1/chat/completions", Bearer, &[]),
    preset("g4f-pollinations", "GPT4Free Pollinations", "https://g4f.space/api/pollinations/v1/chat/completions", Bearer, &[]),
    preset("galadriel", "Galadriel", "https://api.galadriel.ai/v1/chat/completions", Bearer, &[]),
    preset("gigachat", "GigaChat", "https://gigachat.devices.sberbank.ru/api/v1", Bearer, &[]),
    preset("gitlawb", "Gitlawb", "https://opengateway.gitlawb.com/v1/xiaomi-mimo", Bearer, &[("User-Agent", "OpenClaude/1.0 (linux; x86_64)"), ("X-Title", "OpenClaude CLI"), ("HTTP-Referer", "https://github.com/Gitlawb/openclaude")]),
    preset("glm", "GLM", "https://api.z.ai/api/coding/paas/v4/chat/completions", Bearer, &[]),
    preset("greenpt", "GreenPT", "https://api.greenpt.ai/v1/chat/completions", Bearer, &[]),
    preset("groq", "Groq", "https://api.groq.com/openai/v1/chat/completions", Bearer, &[]),
    // `HAIPER_KEY` is the registry's `authHeader`, but it names the vendor's
    // IMAGE/VIDEO api, not its chat surface: the reference sends the key in
    // `HAIPER_KEY` from `handlers/imageGeneration/providers/haiper.ts` and
    // `handlers/videoGeneration.ts`, and its chat executor
    // (`executors/default.ts`, `services/provider.ts`) honours only
    // `x-api-key` / `x-goog-api-key` and Bearer-falls-back on everything
    // else. Recording the header here would promise the operator something
    // no chat path in either implementation ever sends.
    preset("haiper", "Haiper", "https://api.haiper.ai/v1", Bearer, &[]),
    preset("hcnsec", "HCNSEC", "https://api.hcnsec.cn/v1/chat/completions", Bearer, &[]),
    preset("helixmind", "HelixMind", "https://helixmind.online/v1/chat/completions", Bearer, &[]),
    preset("helyxai", "HelyxAI", "https://helyxai.space/v1/chat/completions", Bearer, &[]),
    preset("heroku", "Heroku", "https://us.inference.heroku.com/v1/chat/completions", Bearer, &[]),
    preset("huggingface", "Hugging Face", "https://router.huggingface.co/v1/chat/completions", Bearer, &[]),
    preset("hyperbolic", "Hyperbolic", "https://api.hyperbolic.xyz/v1/chat/completions", Bearer, &[]),
    // `Api-Key` is the same story as `haiper`'s `HAIPER_KEY`: the reference
    // sends it from `handlers/imageGeneration/providers/ideogram.ts`, and
    // both of its chat-surface auth builders Bearer-fall-back on it. See the
    // `haiper` row.
    preset("ideogram", "Ideogram", "https://api.ideogram.ai", Bearer, &[]),
    preset("iflytek", "iFlytek", "https://spark-api-open.xf-yun.com/v1/chat/completions", Bearer, &[]),
    preset("inception", "Inception", "https://api.inceptionlabs.ai/v1/chat/completions", Bearer, &[]),
    preset("inference-net", "Inference Net", "https://api.inference.net/v1/chat/completions", Bearer, &[]),
    preset("internlm", "InternLM", "https://chat.intern-ai.org.cn/api/v1/chat/completions", Bearer, &[]),
    preset("kenari", "Kenari", "https://kenari.id/v1/chat/completions", Bearer, &[]),
    preset("kie", "Kie.ai", "https://api.kie.ai/v1/chat/completions", Bearer, &[]),
    preset("kilo-gateway", "Kilo Gateway", "https://api.kilo.ai/api/gateway/chat/completions", Bearer, &[]),
    preset("kimi", "Kimi (Moonshot)", "https://api.moonshot.ai/v1/chat/completions", Bearer, &[]),
    preset("lambda-ai", "Lambda AI", "https://api.lambda.ai/v1/chat/completions", Bearer, &[]),
    preset("leonardo", "Leonardo", "https://cloud.leonardo.ai/api/rest/v1", Bearer, &[]),
    preset("liquid", "Liquid AI", "https://inference.liquid.ai/v1/chat/completions", Bearer, &[]),
    preset("literouter", "LiteRouter", "https://api.literouter.com/v1/chat/completions", Bearer, &[]),
    preset("llamagate", "LlamaGate", "https://llamagate.ai/v1/chat/completions", Bearer, &[]),
    preset("llm-kiwi", "LLM Kiwi", "https://api.llm.kiwi/v1/chat/completions", Bearer, &[]),
    preset("llm7", "LLM7", "https://api.llm7.io/v1/chat/completions", Bearer, &[]),
    preset("llmgateway", "LLM Gateway", "https://api.llmgateway.io/v1/chat/completions", Bearer, &[]),
    preset("logfare", "Logfare", "https://logfare.ai/v1/chat/completions", Bearer, &[]),
    preset("longcat", "LongCat", "https://api.longcat.chat/openai/v1/chat/completions", Bearer, &[]),
    preset("lyceum", "Lyceum", "https://api.lyceum.technology/openai/v1/chat/completions", Bearer, &[]),
    preset("maritalk", "Maritalk", "https://chat.maritaca.ai/api", AuthorizationScheme("Key"), &[]),
    preset("meganova-ai", "MegaNova AI", "https://api.meganova.ai/v1/chat/completions", Bearer, &[]),
    preset("meta-llama", "Meta Llama", "https://api.llama.com/compat/v1/chat/completions", Bearer, &[]),
    preset("minimax", "MiniMax", "https://api.minimax.io/v1/chat/completions", Bearer, &[]),
    preset("mistral", "Mistral", "https://api.mistral.ai/v1/chat/completions", Bearer, &[]),
    preset("mixlayer", "Mixlayer", "https://models.mixlayer.ai/v1/chat/completions", Bearer, &[]),
    preset("mlx-gemma", "MLX Gemma (local)", "http://localhost:11435/v1", Bearer, &[]),
    preset("mlx-qwen", "MLX Qwen (local)", "http://localhost:11436/v1", Bearer, &[]),
    preset("mnn-ai", "MNN AI", "https://api.mnnai.ru/v1/chat/completions", Bearer, &[]),
    preset("modal", "Modal", "https://api.modal.ai/v1/chat/completions", Bearer, &[]),
    preset("modelscope", "ModelScope", "https://api-inference.modelscope.cn/v1/chat/completions", Bearer, &[]),
    preset("monsterapi", "MonsterAPI", "https://api.monsterapi.ai/v1/chat/completions", Bearer, &[]),
    preset("moonshot", "Moonshot AI", "https://api.moonshot.ai/v1/chat/completions", Bearer, &[]),
    preset("morph", "Morph", "https://api.morphllm.com/v1/chat/completions", Bearer, &[]),
    preset("naga-ac", "NAGA AC", "https://api.naga.ac/v1/chat/completions", Bearer, &[]),
    preset("naga-ai", "NAGA AI", "https://api.naga.ac/v1/chat/completions", Bearer, &[]),
    preset("nanogpt", "NanoGPT", "https://nano-gpt.com/api/v1/chat/completions", Bearer, &[]),
    preset("nara", "Nara", "https://router.bynara.id/v1/chat/completions", Bearer, &[]),
    preset("navy", "Navy", "https://api.navy/v1/chat/completions", Bearer, &[("User-Agent", "OmniRoute/1.0")]),
    preset("nebius", "Nebius", "https://api.tokenfactory.nebius.com/v1/chat/completions", Bearer, &[]),
    preset("nous-research", "Nous Research", "https://inference-api.nousresearch.com/v1/chat/completions", Bearer, &[]),
    preset("novita", "Novita", "https://api.novita.ai/openai/v1/chat/completions", Bearer, &[]),
    preset("nscale", "Nscale", "https://inference.api.nscale.com/v1/chat/completions", Bearer, &[]),
    preset("nube", "Nube", "https://ai.nube.sh/api/v1/chat/completions", Bearer, &[]),
    preset("nvidia", "NVIDIA", "https://integrate.api.nvidia.com/v1/chat/completions", Bearer, &[]),
    preset("ofoxai", "OFOX AI", "https://api.ofox.ai/v1/chat/completions", Bearer, &[]),
    preset("ollama-cloud", "Ollama Cloud", "https://ollama.com/v1/chat/completions", Bearer, &[]),
    preset("openadapter", "OpenAdapter", "https://api.openadapter.in/v1/chat/completions", Bearer, &[]),
    preset("openai", "OpenAI", "https://api.openai.com/v1/chat/completions", Bearer, &[]),
    preset("opencode", "OpenCode Zen", "https://opencode.ai/zen/v1", Bearer, &[]),
    preset("openference-api", "Openference API", "https://api.openference.com/v1/chat/completions", Bearer, &[]),
    preset("openrouter", "OpenRouter", "https://openrouter.ai/api/v1/chat/completions", Bearer, &[("HTTP-Referer", "https://endpoint-proxy.local"), ("X-Title", "Endpoint Proxy")]),
    preset("openvecta", "OpenVecta", "https://api.openvecta.com/v1/chat/completions", Bearer, &[]),
    preset("opper", "Opper", "https://api.opper.ai/v3/compat/chat/completions", Bearer, &[]),
    preset("orcarouter", "OrcaRouter", "https://api.orcarouter.ai/v1/chat/completions", Bearer, &[("HTTP-Referer", "https://endpoint-proxy.local"), ("X-Title", "Endpoint Proxy")]),
    preset("ovhcloud", "OVHcloud", "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1/chat/completions", Bearer, &[]),
    preset("perplexity", "Perplexity", "https://api.perplexity.ai/chat/completions", Bearer, &[]),
    preset("pioneer", "Pioneer AI", "https://api.pioneer.ai/v1/chat/completions", ApiKeyHeader("x-api-key"), &[]),
    preset("plamo", "Plamo", "https://api.platform.preferredai.jp/v1/chat/completions", Bearer, &[]),
    preset("poe", "Poe", "https://api.poe.com/v1/chat/completions", Bearer, &[]),
    preset("poixe-ai", "Poixe AI", "https://api.poixe.com/v1/chat/completions", Bearer, &[]),
    preset("pollinations", "Pollinations", "https://gen.pollinations.ai/v1/chat/completions", Bearer, &[]),
    preset("poolside", "Poolside", "https://inference.poolside.ai/v1/chat/completions", Bearer, &[]),
    preset("predibase", "Predibase", "https://serving.app.predibase.com/v1/chat/completions", Bearer, &[]),
    preset("publicai", "PublicAI", "https://api.publicai.co/v1/chat/completions", Bearer, &[]),
    preset("qianfan", "Baidu Qianfan (v2)", "https://qianfan.baidubce.com/v2/chat/completions", Bearer, &[]),
    preset("qiniu", "Qiniu", "https://api.qnaigc.com/v1/chat/completions", Bearer, &[]),
    preset("qwen-cloud", "Qwen Cloud (Intl)", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions", Bearer, &[]),
    preset("qwen-cloud-token-plan", "Qwen Cloud Token Plan", "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1/chat/completions", Bearer, &[]),
    preset("regolo", "Regolo", "https://api.regolo.ai", Bearer, &[]),
    preset("reka", "Reka", "https://api.reka.ai/v1/chat/completions", Bearer, &[]),
    preset("requesty", "Requesty", "https://router.requesty.ai/v1/chat/completions", Bearer, &[]),
    preset("routeway", "Routeway", "https://api.routeway.ai/v1/chat/completions", Bearer, &[("User-Agent", "Mozilla/5.0 OmniRoute/1.0")]),
    preset("sambanova", "SambaNova", "https://api.sambanova.ai/v1/chat/completions", Bearer, &[]),
    preset("sarvam", "Sarvam AI", "https://api.sarvam.ai/v1/chat/completions", Bearer, &[]),
    preset("scaleway", "Scaleway", "https://api.scaleway.ai/v1/chat/completions", Bearer, &[]),
    preset("sealion", "Sea Lion", "https://api.sea-lion.ai/v1/chat/completions", Bearer, &[]),
    preset("seekai", "Seekai", "https://seekai.cc/v1/chat/completions", Bearer, &[]),
    preset("sensenova", "Sensenova", "https://token.sensenova.cn/v1/chat/completions", Bearer, &[]),
    preset("siliconflow", "SiliconFlow", "https://api.siliconflow.com/v1/chat/completions", Bearer, &[]),
    preset("sparkdesk", "SparkDesk", "https://spark-api-open.xf-yun.com/v1/chat/completions", Bearer, &[]),
    preset("speka", "Speka", "https://speka.me/v1/chat/completions", Bearer, &[]),
    preset("stepfun", "StepFun", "https://api.stepfun.com/v1/chat/completions", Bearer, &[]),
    preset("sumopod", "SumoPod", "https://ai.sumopod.com/v1/chat/completions", Bearer, &[]),
    preset("synthetic", "Synthetic", "https://api.synthetic.new/openai/v1/chat/completions", Bearer, &[]),
    preset("tencent", "Tencent", "https://api.hunyuan.cloud.tencent.com/v1/chat/completions", Bearer, &[]),
    preset("together", "Together", "https://api.together.xyz/v1/chat/completions", Bearer, &[]),
    preset("token-kiosk", "Token Kiosk", "https://agent-router.gaib.ai/v1/chat/completions", Bearer, &[]),
    preset("tokenreply", "TokenReply", "https://api.tokenreply.com/v1/chat/completions", Bearer, &[]),
    preset("tokenrouter", "TokenRouter", "https://api.tokenrouter.com/v1/chat/completions", Bearer, &[]),
    preset("typhoon", "Typhoon", "https://api.opentyphoon.ai/v1/chat/completions", Bearer, &[]),
    preset("uc-direct", "Uncensored.com (API)", "https://api.uncensored.com/api/v1", ApiKeyHeader("x-api-key"), &[]),
    preset("uncloseai", "UncloseAI", "https://hermes.ai.unturf.com/v1/chat/completions", Bearer, &[]),
    preset("unorouter", "UnoRouter", "https://api.unorouter.com/v1/chat/completions", Bearer, &[]),
    preset("upstage", "Upstage", "https://api.upstage.ai/v1/chat/completions", Bearer, &[]),
    preset("v0-vercel", "Vercel v0", "https://api.v0.dev/v1/chat/completions", Bearer, &[]),
    preset("venice", "Venice AI", "https://api.venice.ai/api/v1/chat/completions", Bearer, &[]),
    preset("vercel-ai-gateway", "Vercel AI Gateway", "https://ai-gateway.vercel.sh/v1/chat/completions", Bearer, &[]),
    preset("void-ai", "Void AI", "https://api.voidai.app/v1/chat/completions", Bearer, &[]),
    preset("volcengine", "Volcengine", "https://ark.cn-beijing.volces.com/api/v3/chat/completions", Bearer, &[]),
    preset("wandb", "Weights & Biases", "https://api.inference.wandb.ai/v1/chat/completions", Bearer, &[]),
    preset("writer", "Writer", "https://api.writer.com/v1/chat/completions", Bearer, &[]),
    preset("x5lab", "X5Lab", "https://api.x5lab.dev/v1/chat/completions", Bearer, &[]),
    preset("xai", "xAI", "https://api.x.ai/v1/chat/completions", Bearer, &[]),
    preset("xiaomi-mimo", "Xiaomi MiMo", "https://api.xiaomimimo.com/v1", Bearer, &[]),
    preset("xiaomi-mimo-token-plan", "Xiaomi MiMo Token Plan", "https://token-plan-sgp.xiaomimimo.com/v1", Bearer, &[]),
    preset("xkiro", "xKiro", "https://api.xkiro.com/v1/chat/completions", Bearer, &[]),
    preset("yi", "Yi", "https://api.lingyiwanwu.com/v1/chat/completions", Bearer, &[]),
    preset("yolo-auto", "YOLO Auto", "https://yolo-auto.com/v1/chat/completions", Bearer, &[]),
    preset("zenmux", "Zenmux", "https://zenmux.ai/api/v1/chat/completions", Bearer, &[]),
    preset("zerolimitai", "Zerolimitai", "https://www.zerolimitai.com/api/v1/chat/completions", Bearer, &[]),
    preset("zylo-api", "Zylo API", "https://api.zyloai.net/v1/chat/completions", Bearer, &[]),
];

/// Number of vendors in [`PRESET_PROVIDERS`]. Exposed so the admin
/// serializer and the crate's own tests agree on the table size without
/// either hard-coding a literal that can drift.
pub const PRESET_PROVIDER_COUNT: usize = PRESET_PROVIDERS.len();

/// Legacy short id -> canonical [`PRESET_PROVIDERS`] id, as the source
/// registry spells them. `find_preset` consults this after the id scan, so a
/// config still carrying `ds`, `pplx` or `oc` keeps resolving to
/// `deepseek`, `perplexity` and `opencode`.
#[rustfmt::skip]
pub const PRESET_ALIASES: &[(&str, &str)] = &[
    ("aiml", "aimlapi"),
    ("ali", "alibaba"),
    ("ling", "ant-ling"),
    ("af", "api-airforce"),
    ("arcee", "arcee-ai"),
    ("bzl", "bazaarlink"),
    ("bb", "blackbox"),
    ("bm", "bluesminds"),
    ("bpm", "byteplus"),
    ("cinf", "cheaperinference"),
    ("ds", "deepseek"),
    ("dai", "dit"),
    ("featherless", "featherless-ai"),
    ("faik", "freeaiapikey"),
    ("fb", "freebuff"),
    ("fmd", "freemodel-dev"),
    ("fta", "freetheai"),
    ("friendli", "friendliai"),
    ("g4fgem", "g4f-gemini"),
    ("g4fgroq", "g4f-groq"),
    ("g4fnv", "g4f-nvidia"),
    ("g4foll", "g4f-ollama"),
    ("g4fpol", "g4f-pollinations"),
    ("glb", "gitlawb"),
    ("hp", "haiper"),
    ("hf", "huggingface"),
    ("hyp", "hyperbolic"),
    ("ideo", "ideogram"),
    ("inet", "inference-net"),
    ("kg", "kilo-gateway"),
    ("lambda", "lambda-ai"),
    ("leo", "leonardo"),
    ("llmkiwi", "llm-kiwi"),
    ("lc", "longcat"),
    ("meta", "meta-llama"),
    ("ms", "modelscope"),
    ("monster", "monsterapi"),
    ("naga", "naga-ac"),
    ("nous", "nous-research"),
    ("ollamacloud", "ollama-cloud"),
    ("oad", "openadapter"),
    ("oc", "opencode"),
    ("ofa", "openference-api"),
    ("ovh", "ovhcloud"),
    ("pplx", "perplexity"),
    ("pn", "pioneer"),
    ("pol", "pollinations"),
    ("qwc", "qwen-cloud"),
    ("qct", "qwen-cloud-token-plan"),
    ("samba", "sambanova"),
    ("scw", "scaleway"),
    ("ska", "seekai"),
    ("tk", "token-kiosk"),
    ("trk", "tokenrouter"),
    ("ucd", "uc-direct"),
    ("unc", "uncloseai"),
    ("v0", "v0-vercel"),
    ("vag", "vercel-ai-gateway"),
    ("mimo", "xiaomi-mimo"),
    ("mimotp", "xiaomi-mimo-token-plan"),
    ("zm", "zenmux"),
    ("zylo", "zylo-api"),
];

/// Resolve a vendor id to its preset, case-insensitively, honouring
/// [`PRESET_ALIASES`].
///
/// `None` means "not a zero-custom-code vendor" — either an unknown id, or
/// one of the excluded classes in the module docs, in which case the caller
/// wants a dedicated bridge rather than a preset.
pub fn find_preset(id: &str) -> Option<&'static PresetProvider> {
    PRESET_PROVIDERS
        .iter()
        .find(|p| p.id.eq_ignore_ascii_case(id))
        .or_else(|| {
            PRESET_ALIASES
                .iter()
                .find(|(alias, _)| alias.eq_ignore_ascii_case(id))
                .and_then(|(_, canonical)| PRESET_PROVIDERS.iter().find(|p| p.id == *canonical))
        })
}
