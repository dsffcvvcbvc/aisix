//! Embedded catalog of standard OpenAI-compatible REST provider presets.
//!
//! Implements the AGENT.md §4.1 intent: vendors whose upstream is a plain
//! OpenAI-shaped REST endpoint need **zero custom code** — no bridge, no
//! executor. This table carries the three facts a dashboard needs to onboard
//! such a vendor, and nothing else:
//!
//! 1. the canonical `base_url`,
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
//! OpenAI chat request over HTTP(S). That excludes four classes, each for a
//! concrete reason rather than by taste:
//!
//! * **Web scrapers** — `chatgpt-web`, `grok-web`, `tinycms-web`, the
//!   cookie-auth entries, and the `wss://` / headless-Chromium ports. These
//!   drive a browser session, not an API; a bearer-shaped preset would be a
//!   lie about what the caller must do.
//! * **Already-bridged vendors** — the yellow zone (`cline`,
//! `clinepass`, `qoder`, `grok-cli`, `codex`, `agy`,
//!   `antigravity`) plus their registry twins (`xai-oauth`,
//!   `devin-cli`, `devin-desktop`, `codebuddy-cn`). They already have
//!   `Bridge` impls in this workspace; a second, weaker description of the
//!   same vendor is a second thing to keep in sync.
//! * **OAuth-only upstreams** — `github`, `gitlab-duo`, `kilocode`,
//!   `trae`, `openference`. `PresetAuth` models "where does the key go",
//!   and OAuth needs a token-exchange lifecycle no variant can express.
//! * **Non-REST / non-callable `base_url`** — `cloudflare-ai` (the executor
//!   splices an account id into the path), `snowflake` and `databricks`
//!   (`{account}` / all-zeros placeholder hosts), `bedrock` (no URL at
//!   all — a native AWS SDK client), plus ports that need something other
//!   than a plain HTTPS request: `cloudflare-playground` (headless
//!   Chromium driving a `cf_agent` WebSocket), `uc` (a Clerk-JWT socket
//!   minted from a browser login) and `promptql` (a reverse-engineered
//!   GraphQL playground endpoint).
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
//! aliases vendors were registered under (67 of them, in
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
    /// and what 184 of the 190 `PRESET_PROVIDERS` entries use.
    Bearer,
    /// The key does not go out as `Authorization: Bearer`. The payload is the
    /// source registry's `authHeader` recorded verbatim, which is one of
    /// two things:
    ///
    /// * a **header name** — `x-api-key`, `Api-Key`, `api-key`, or a
    ///   vendor-unique one like `HAIPER_KEY`; the key replaces the
    ///   credential in that header.
    /// * an **`Authorization` scheme name** for a vendor that authenticates
    ///   with something other than Bearer. There is exactly one such entry,
    ///   `maritalk`, whose registry value is `key` — the upstream expects
    ///   `Authorization: Key <key>`, so render the payload into
    ///   `Authorization` rather than into a header of that name.
    ///
    /// Six of the 190 entries need this; the other 184 are `Bearer`.
    ApiKeyHeader(&'static str),
    /// No credential is sent. Unused by the current table — see the module
    /// docs — but part of the contract so keyless local servers can be
    /// onboarded without another breaking change.
    None,
}

// The table below is 190 rows; spelling the common shapes in short keeps it
// scannable and diffable.
use PresetAuth::{ApiKeyHeader, Bearer};

/// A vendor whose upstream is a plain OpenAI-shaped REST endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresetProvider {
    /// Canonical vendor id, as the dashboard and `config.example.yaml`
    /// spell it. Lowercase; the lookup key.
    pub id: &'static str,
    /// Human label for provider pickers.
    pub display_name: &'static str,
    /// Canonical upstream base URL, byte-identical to the source registry
    /// entry. Point the connection's `api_base` at this.
    pub base_url: &'static str,
    /// Which header carries the credential.
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
    preset("command-code", "Command Code", "https://api.commandcode.ai", Bearer, &[]),
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
    preset("free-ai", "Free.ai", "https://api.free.ai/v1/chat/", Bearer, &[]),
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
    preset("haiper", "Haiper", "https://api.haiper.ai/v1", ApiKeyHeader("HAIPER_KEY"), &[]),
    preset("hcnsec", "HCNSEC", "https://api.hcnsec.cn/v1/chat/completions", Bearer, &[]),
    preset("helixmind", "HelixMind", "https://helixmind.online/v1/chat/completions", Bearer, &[]),
    preset("helyxai", "HelyxAI", "https://helyxai.space/v1/chat/completions", Bearer, &[]),
    preset("heroku", "Heroku", "https://us.inference.heroku.com/v1/chat/completions", Bearer, &[]),
    preset("huggingface", "Hugging Face", "https://router.huggingface.co/v1/chat/completions", Bearer, &[]),
    preset("hyperbolic", "Hyperbolic", "https://api.hyperbolic.xyz/v1/chat/completions", Bearer, &[]),
    preset("ideogram", "Ideogram", "https://api.ideogram.ai", ApiKeyHeader("Api-Key"), &[]),
    preset("iflytek", "iFlytek", "https://spark-api-open.xf-yun.com/v1/chat/completions", Bearer, &[]),
    preset("inception", "Inception", "https://api.inceptionlabs.ai/v1/chat/completions", Bearer, &[]),
    preset("inference-net", "Inference Net", "https://api.inference.net/v1/chat/completions", Bearer, &[]),
    preset("inner-ai", "Inner AI", "https://chatapi.innerai.com/chat", Bearer, &[]),
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
    preset("maritalk", "Maritalk", "https://chat.maritaca.ai/api", ApiKeyHeader("key"), &[]),
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
    preset("muse-code", "Meta Muse Code", "https://api.meta.ai/v1/responses", Bearer, &[("User-Agent", "muse-build/1.3.0 (interactive; macos-aarch64; build ac7280f2aca67769d1455a8847bb502b617d50f6)")]),
    preset("naga-ac", "NAGA AC", "https://api.naga.ac/v1/chat/completions", Bearer, &[]),
    preset("naga-ai", "NAGA AI", "https://api.naga.ac/v1/chat/completions", Bearer, &[]),
    preset("nanogpt", "NanoGPT", "https://nano-gpt.com/api/v1/chat/completions", Bearer, &[]),
    preset("nara", "Nara", "https://router.bynara.id/v1/chat/completions", Bearer, &[]),
    preset("navy", "Navy", "https://api.navy/v1/chat/completions", Bearer, &[("User-Agent", "OmniRoute/1.0")]),
    preset("nebius", "Nebius", "https://api.tokenfactory.nebius.com/v1/chat/completions", Bearer, &[]),
    preset("nlpcloud", "NLP Cloud", "https://api.nlpcloud.io/v1/gpu", Bearer, &[]),
    preset("nous-research", "Nous Research", "https://inference-api.nousresearch.com/v1/chat/completions", Bearer, &[]),
    preset("novita", "Novita", "https://api.novita.ai/openai/v1/chat/completions", Bearer, &[]),
    preset("nscale", "Nscale", "https://inference.api.nscale.com/v1/chat/completions", Bearer, &[]),
    preset("nube", "Nube", "https://ai.nube.sh/api/v1/chat/completions", Bearer, &[]),
    preset("nvidia", "NVIDIA", "https://integrate.api.nvidia.com/v1/chat/completions", Bearer, &[]),
    preset("ofoxai", "OFOX AI", "https://api.ofox.ai/v1/chat/completions", Bearer, &[]),
    preset("ollama-cloud", "Ollama Cloud", "https://ollama.com/v1/chat/completions", Bearer, &[]),
    preset("oneminai", "OneMin AI", "https://api.1min.ai/api/chat-with-ai", ApiKeyHeader("api-key"), &[]),
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
    ("cmd", "command-code"),
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
    ("in-ai", "inner-ai"),
    ("kg", "kilo-gateway"),
    ("lambda", "lambda-ai"),
    ("leo", "leonardo"),
    ("llmkiwi", "llm-kiwi"),
    ("lc", "longcat"),
    ("meta", "meta-llama"),
    ("ms", "modelscope"),
    ("monster", "monsterapi"),
    ("mc", "muse-code"),
    ("naga", "naga-ac"),
    ("nlpc", "nlpcloud"),
    ("nous", "nous-research"),
    ("ollamacloud", "ollama-cloud"),
    ("1min", "oneminai"),
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
