# PRESET catalog: reconciling 190 against the spec's 216

> Verdict: **the table is correct at 190. The spec's 216 is stale, and the
> table must not be padded to reach it.** This document records the
> derivation so the number is not re-litigated, plus the exact edit
> `AGENT.md` needs — a file that lives **outside this repository**
> (`/home/ernur/omniroute-aisix/AGENT.md`, untracked by `aisix`), so the
> spec patch below could not be committed here and has to be applied there.

## 1. The claim

`AGENT.md` §4 is titled "Topology of **274** Providers in a Single Binary";
§4.1 is "Embedded Registry for **216** Standard REST Providers (**78**%)",
repeated in the §4 diagram ("Direct zero-overhead proxy for **216** REST
vendors"). 216 / 274 = 78.8%, so the two figures are internally consistent —
they are one snapshot of one moment, not two independent claims.

The same section's implementation-status note is stale in a second way: it
records "**PRESET-каталог — НЕ найден в коде**" (`PRESET_PROVIDERS` not found
in code). The catalog exists
(`crates/aisix-provider-openai/src/presets.rs`, exported from the crate's
`lib.rs` and served at `GET /admin/v1/preset_providers`).

## 2. The derivation

Counted against the source registry,
`omniroute/open-sse/config/providers/registry/*/index.ts`, at the time of
writing. The unit is the **registry entry**, not the directory: 256
directories hold 257 entries (`mlx/` declares `mlx-gemma` and `mlx-qwen`;
`tinycms/` declares `tinycms-web`; `devin/`, `segmind/` and
`stability-ai/` have no `index.ts`).

| Step | Count | Running |
| --- | ---: | ---: |
| registry entries | 257 | 257 |
| less already-bridged vendors and registry twins | −18 | 239 |
| less web scrapers / cookie-auth entries / browser-driven ports | −24 | 215 |
| less non-OpenAI wire formats | −11 | 204 |
| less oauth-only upstreams | −6 | 198 |
| less non-REST or non-callable `base_url` | −7 | 191 |
| less a second id for an endpoint already listed | −1 | **190** |

`190 = 257 − 67`, exactly. The per-class ids are enumerated in
`presets_tests::EXCLUDED_IDS`, and a test asserts they sum to 67 — so the
table above and the guarded set cannot drift apart.

### Per-class membership

**Already-bridged (18).** The yellow zone plus its registry twins and
siblings: `agy`, `antigravity`, `cline`, `clinepass`, `codebuddy-cn`,
`codex`, `codex-app-server`, `cursor`, `cursor-api`, `devin-cli`,
`devin-cli-agentic`, `devin-desktop`, `ghe-copilot`, `grok-cli`, `kiro`,
`qoder`, `xai-oauth`, `zed-hosted`. Each already has a `Bridge` impl in this
workspace; a preset would be a second, weaker description of the same
vendor to keep in sync.

**Web scrapers / cookie-auth / browser ports (24).** `adapta-web`, `auggie`,
`chatgpt-web`, `chatgpt-web-codex`, `conol-web`, `copilot-m365-web`,
`copilot-web`, `duckduckgo-web`, `grok-web`, `huggingchat`, `hyperagent`,
`lmarena`, `maxai`, `muse-spark-web`, `notion-web`, `t3-web`,
`tencent-aistudio-web`, `tinycms-web`, `udio`, `veoaifree-web`,
`yuanbao-web`, `zai-web`, `zcode`, `zenmux-free`. These drive a browser
session rather than an API.

`maxai` is the case worth writing down, because the registry records it
with a plain `baseUrl` and `apikey`/`bearer` and so looks like a textbook
preset. Its executor's own doc says otherwise: MaxAI "is a consumer web app
with **no public API**", the executor reproduces the web app's *signed*
request with a per-request signature, Firefox-150 identity headers and an
OAuth token minted by a browser-login flow, and "the request **MUST** exit
a residential IP" because MaxAI bot-bans datacentre addresses. The
registry's `baseUrl` is a constant the executor ignores, not an endpoint it
serves. This entry was previously undocumented in the module's exclusion
bullets — that was a documentation gap, not a catalog gap.

**Non-OpenAI wire formats (11).** Registry `format` is not `openai`:
`anthropic`, `agentrouter`, `bailian-coding-plan`, `tabitoken`, `wafer`,
`zai` (`claude`); `gemini`, `vertex` (`gemini`); `clova-studio` (`clova`);
`deepai` (`custom`); `magnific` (`magnific-image`). A `base_url` that
rejects an OpenAI-shaped request 400s on the first real call, which is
worse than no row.

**OAuth-only (6).** `claude`, `github`, `gitlab-duo`, `kilocode`,
`openference`, `trae`. `PresetAuth` models "where does the key go"; OAuth
needs a token-exchange lifecycle no variant expresses.

**Non-REST / non-callable `base_url` (7).** `bedrock` (no URL — a native
AWS SDK client), `cloudflare-ai` (the executor splices an account id into
the path), `snowflake` and `databricks` (placeholder hosts), plus ports
needing more than a plain HTTPS request: `cloudflare-playground`
(headless Chromium over a `cf_agent` WebSocket), `uc` (a Clerk-JWT socket
minted from a browser login), `promptql` (a reverse-engineered GraphQL
playground endpoint).

**A second id for an endpoint already listed (1).** `kimi-k3` — see §3.

## 3. Why the 216 is not reachable

Three independent facts, each enough on its own:

1. **The set is closed.** All 190 ids are registry entry ids, and all 67
   registry entries not in the table are accounted for in the table above.
   There is no pool of 26 un-added vendors. **A count larger than its
   source is not a count of a subset** — the 216 could not have been
   produced from this registry by any rule, correct or not.
2. **The source has moved.** The registry the 216 was measured against
   predates the current one, and the same spec's total-provider figure is
   stale in the same way (the source's own generated reference now reports
   358 providers, against the spec's 274).
3. **The registry counts aliases separately, and 216 is consistent with
   doing so.** `kimi-k3` is a second registry entry whose `base_url` and
   auth are byte-identical to rows the table already carries under `kimi`
   and `moonshot` — a model tier, not a vendor. The table drops it. The
   same shape appears six times inside the table itself as a declared
   family (`alibaba`/`qwen-cloud`, `baidu`/`qianfan`, `doubao`/`volcengine`,
   `iflytek`/`sparkdesk`, `kimi`/`moonshot`, `naga-ac`/`naga-ai`), each
   pair a distinct id over one endpoint. Any count taken over registry ids
   rather than endpoints moves every time the registry re-spells a vendor.

## 4. What was changed

- **The table: unchanged.** No vendor was added or removed; 190 stands.
- **The module docs** (`presets.rs`) now record the derivation, name the
  two previously unnamed exclusions (`maxai` as a web scraper, `kimi-k3`
  as a duplicate endpoint), and add the non-OpenAI-format class as a
  bullet in its own right.
- **The test suite now pins the decision, not a range.** The previous
  `150..=220` band could not tell 190 from a padded 216, and its ceiling
  actively permitted one. In its place:
  - `the_catalog_is_the_reconciled_size` — exact 190, with a message that
    says to update the derivation in the same commit.
  - `the_excluded_classes_are_still_excluded` — every id of every class is
    asserted absent, the classes are asserted to sum to 67, and the
    duplicate-endpoint class is asserted to shadow ids that really do
    share one endpoint.
  - `every_row_is_a_plain_rest_endpoint` — mechanical restatement of the
    non-callable exclusion: `https://` or `http://localhost` only, no
    `{`/`<`/all-zeros placeholder, no `PresetAuth::None`.
  - `every_repeated_endpoint_is_a_known_vendor_family` — every repeated
    `base_url` must be a declared family, and every declared family must
    really share one endpoint.

  Mutation-checked: adding three rows to close the gap (an excluded id, a
  `wss://` row, and a second id over an existing endpoint) turns **six**
  tests red — the three new ones plus three pre-existing.

## 5. The spec patch, to be applied in `AGENT.md` (outside this repo)

```diff
-4. [Topology of 274 Providers in a Single Binary](#4-topology-of-274-providers-in-a-single-binary)
-   - 4.1. Embedded Registry for 216 Standard REST Providers (78%)
+4. [Topology of the Provider Catalog in a Single Binary](#4-topology-of-the-provider-catalog-in-a-single-binary)
+   - 4.1. Embedded Registry of 190 Standard REST Providers
```

```diff
-│                     • Direct zero-overhead proxy for 216 REST vendors  │
+│                     • Direct zero-overhead proxy for 190 REST vendors  │
```

```diff
-Vendors implementing standard OpenAI/Anthropic formats (Mistral, DeepSeek, Groq, Cerebras, OpenRouter, Together, MiniMax, etc.) require zero custom code.
+Vendors implementing a standard OpenAI-shaped REST format (Mistral, DeepSeek, Groq, Cerebras, OpenRouter, Together, MiniMax, etc.) require zero custom code. The catalog holds 190 of them: the source registry's 257 entries less the vendors that need a bridge (18), a browser session or a cookie (24), a non-OpenAI wire format (11), an OAuth token exchange (6), a non-REST or non-callable endpoint (7), and one second id for an endpoint already listed (1). The per-class membership and the derivation are in `aisix/PRESET_CATALOG_RECONCILIATION.md`.
```

And in §4.1's implementation-status note, delete the stale first bullet
(`PRESET-каталог — НЕ найден в коде`) and replace it with a pointer to
`crates/aisix-provider-openai/src/presets.rs` and the
`GET /admin/v1/preset_providers` route. The other bullets in that note
(bridge env tables, `pt-*` limits, telemetry surfaces, the CP proposal)
are outside this reconciliation and should be left alone.

The §4.2/§4.3/§5 headings and the rest of the topology diagram are
unaffected: the yellow-zone bridges and native cloud providers they
describe are all still exactly as written.
