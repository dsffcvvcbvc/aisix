# PRESET catalog: reconciling 184 against the spec's 216

> Verdict: **the table is correct at 184. The spec's 216 is stale, and the
> table must not be padded to reach it.** This document records the
> derivation so the number is not re-litigated, plus the exact edit
> `AGENT.md` needs — a file that lives **outside this repository**
> (`/home/ernur/omniroute-aisix/AGENT.md`, untracked by `aisix`), so the
> spec patch below could not be committed here and has to be applied there.
>
> **Amended.** The table was 190 until six rows were removed as
> *endpoints the OpenAI family bridge cannot reach*, for two provable
> reasons. (1) The row's `base_url` already ends in a path segment outside
> the seven OpenAI operations `strip_known_endpoint` knows, so the family
> bridge extended it into a URL no one serves: `muse-code` (`…/v1/responses`,
> a Responses-API endpoint), `oneminai` (`…/api/chat-with-ai`, which the
> source registry itself documents as a non-OpenAI wire format behind a
> translating executor), `inner-ai` (`…/chat`, and a dedicated
> `InnerAiExecutor` in the reference) and `free-ai` (`…/v1/chat/`) — the
> bridge reached `…/chat/chat/completions`, `…/responses/chat/completions`
> and `…/chat-with-ai/chat/completions`. (2) The reference reaches the
> vendor on a path the bridge cannot produce at all: `command-code`
> (registry `chatPath: "/provider/v1/chat/completions"`, appended by
> `executors/commandCode.ts`) and `nlpcloud` (`executors/nlpcloud.ts` builds
> `<base>/<model>/chatbot`). A row the gateway cannot dispatch to the URL it
> publishes is a worse promise than no row.
> `presets_tests::every_row_dispatches_to_its_own_base_url` holds the
> catalog to the first reason, and `EXCLUDED_IDS` to both.

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
| less endpoints the OpenAI family bridge cannot reach | −6 | 185 |
| less a second id for an endpoint already listed | −1 | **184** |

`184 = 257 − 73`, exactly. The per-class ids are enumerated in
`presets_tests::EXCLUDED_IDS`, and a test asserts they sum to 73 — so the
table above and the guarded set cannot drift apart.

### Per-class membership

**Already-bridged (18).** The yellow zone plus its registry twins and
siblings: `agy`, `antigravity`, `cline`, `clinepass`, `codebuddy-cn`,
`codex`, `codex-app-server`, `cursor`, `cursor-api`, `devin-cli`,
`devin-cli-agentic`, `devin-desktop`, `ghe-copilot`, `grok-cli`, `kiro`,
`qoder`, `xai-oauth`, `zed-hosted`. Each already has a `Bridge` impl in this
workspace; a preset would be a second, weaker description of the same
vendor to keep in sync. The class is defined by *aisix* having a bridge, not
by the reference having an executor: `inner-ai` has a dedicated
`InnerAiExecutor` in the reference but no bridge here, so it belongs to the
class below.

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

**Endpoints the OpenAI family bridge cannot reach (6).** `command-code`,
`free-ai`, `inner-ai`, `muse-code`, `nlpcloud`, `oneminai` — see the
amendment at the top for the two provable reasons. This is a
*bridge-capability* limit, not a judgement about the vendors: `cohere`
shows the shape that IS expressible (a base the bridge rewrites before
extending it, `cohere.rs`), and each of these six becomes onboardable again
the day the bridge learns that vendor's operation. The criterion is always
something readable in the reference source — a `chatPath`, a `buildUrl`, a
dedicated executor — never a guess about a live vendor.

**A second id for an endpoint already listed (1).** `kimi-k3` — see §3.

## 3. Why the 216 is not reachable

Three independent facts, each enough on its own:

1. **The set is closed.** All 184 ids are registry entry ids, and all 73
   registry entries not in the table are accounted for in the table above.
   There is no pool of 32 un-added vendors. **A count larger than its
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

- **The table lost six rows** (see the amendment) and no vendor was added;
  184 stands.
- **The module docs** (`presets.rs`) now record the derivation, name the
  two previously unnamed exclusions (`maxai` as a web scraper, `kimi-k3`
  as a duplicate endpoint), and add the non-OpenAI-format class as a
  bullet in its own right.
- **The test suite now pins the decision, not a range.** The previous
  `150..=220` band could not tell 184 from a padded 216, and its ceiling
  actively permitted one. In its place:
  - `the_catalog_is_the_reconciled_size` — exact 184, with a message that
    says to update the derivation in the same commit.
  - `the_excluded_classes_are_still_excluded` — every id of every class is
    asserted absent, the classes are asserted to sum to 73, and the
    duplicate-endpoint class is asserted to shadow ids that really do
    share one endpoint.
  - `no_alias_points_at_an_excluded_vendor` — the complement of
    `aliases_are_unique_and_all_point_at_a_real_vendor`: an alias whose
    target still EXISTS is exactly the case that test cannot catch, and
    `cmd`, `nlpc`, `in-ai` and `1min` are the four it caught.
  - `every_row_is_a_plain_rest_endpoint` — mechanical restatement of the
    non-callable exclusion: `https://` or `http://localhost` only, no
    `{`/`<`/all-zeros placeholder, no `PresetAuth::None`.
  - `every_repeated_endpoint_is_a_known_vendor_family` — every repeated
    `base_url` must be a declared family, and every declared family must
    really share one endpoint.
  - `every_row_dispatches_to_its_own_base_url` — the catalog's central
    promise, held against `bridge::resolve_base_for` itself: a full-endpoint
    row must round-trip byte-identically, and a base row must be one the
    bridge may extend — not one already ending in an operation segment,
    which is the `…/chat/chat/completions` doubling.
  - `a_non_bearer_auth_shape_is_a_valid_header_name` — every non-Bearer row
    names something a header can actually be built from, and the
    `Authorization`-scheme variant is distinct from the header-name one.
  - `no_alias_points_at_an_excluded_vendor` (above) and, on the bridge side,
    `a_registry_auth_header_the_reference_ignores_on_chat_stays_bearer` —
    the regression guard for `haiper` / `ideogram`, whose registry
    `authHeader` names an image/video credential that no chat path in
    either implementation ever sends.

  Mutation-checked: adding three rows to close the gap (an excluded id, a
  `wss://` row, and a second id over an existing endpoint) turns **six**
  tests red — the three new ones plus three pre-existing.

## 5. The spec patch, to be applied in `AGENT.md` (outside this repo)

```diff
-4. [Topology of 274 Providers in a Single Binary](#4-topology-of-274-providers-in-a-single-binary)
-   - 4.1. Embedded Registry for 216 Standard REST Providers (78%)
+4. [Topology of the Provider Catalog in a Single Binary](#4-topology-of-the-provider-catalog-in-a-single-binary)
+   - 4.1. Embedded Registry of 184 Standard REST Providers
```

```diff
-│                     • Direct zero-overhead proxy for 216 REST vendors  │
+│                     • Direct zero-overhead proxy for 184 REST vendors  │
```

```diff
-Vendors implementing standard OpenAI/Anthropic formats (Mistral, DeepSeek, Groq, Cerebras, OpenRouter, Together, MiniMax, etc.) require zero custom code.
+Vendors implementing a standard OpenAI-shaped REST format (Mistral, DeepSeek, Groq, Cerebras, OpenRouter, Together, MiniMax, etc.) require zero custom code. The catalog holds 184 of them: the source registry's 257 entries less the vendors that need a bridge (18), a browser session or a cookie (24), a non-OpenAI wire format (11), an OAuth token exchange (6), a non-REST or non-callable endpoint (7), an endpoint the OpenAI family bridge cannot reach (6), and one second id for an endpoint already listed (1). The per-class membership and the derivation are in `aisix/PRESET_CATALOG_RECONCILIATION.md`.
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

## 6. Operator impact of the auth-shape change

The catalog is a published contract (`GET /admin/v1/preset_providers`), so
every change to an id, a `base_url` or an auth shape is listed here with what
an operator has to do about it. **No existing `resources.yaml` breaks** —
nothing in this change makes a previously-routable request unroutable — but
two classes of existing config change behaviour, and one gains a field the
dashboard does not yet know about.

### 6.1 `auth` shape — behaviour change, no action required for a working config

`bridge.rs::build_request_headers` now reads the declared shape off the
catalog row instead of always writing `Authorization: Bearer`. Three vendors
are affected:

| vendor | before (on the wire) | after | why |
| --- | --- | --- | --- |
| `maritalk` | `Authorization: Bearer <key>` | `Authorization: Key <key>` | its registry `authHeader` is `key`, an **Authorization scheme**, not a header name. Both of the reference's chat-surface auth builders render it that way (`open-sse/executors/default.ts` hard-codes `case "maritalk"`, `open-sse/services/provider.ts` does it generically for `authHeader === "key"`). The old Bearer was a guaranteed 401. |
| `pioneer` | `Authorization: Bearer <key>` | `x-api-key: <key>` | the registry value is `x-api-key`, one of the two names the reference's generic arm honours; the vendor's own registry comment says "X-API-Key header … (Bearer also accepted upstream)", so **an existing config that works today keeps working**. |
| `uc-direct` | `Authorization: Bearer <key>` | `x-api-key: <key>` | the registry value is `x-api-key`; the vendor's own comment says the `uai_sk_live_` key is "NOT Bearer", so the old Bearer was a guaranteed 401. |

No key, `api_base` or Model reference has to change. `maritalk` and
`uc-direct` were broken before this change and are fixed by it; `pioneer`
keeps working because the vendor accepts both.

### 6.2 `haiper` and `ideogram` — catalogue corrected, wire unchanged

Both had `ApiKeyHeader("HAIPER_KEY")` / `ApiKeyHeader("Api-Key")` published
to the dashboard while the bridge sent `Authorization: Bearer`. The header
names are real, but they name those vendors' **image and video** APIs: the
reference sends them from `handlers/imageGeneration/providers/haiper.ts`,
`handlers/videoGeneration/providers/ideogram.ts` and
`handlers/videoGeneration.ts`, never from a chat path, and both of its
chat-surface auth builders Bearer-fall-back on any other spelling. The rows
are now `bearer`, which is what actually goes out — so **the wire does not
change**; only the (wrong) hint the dashboard showed does. The onboarding
wizard stops telling operators "This vendor expects the key in the
HAIPER_KEY header", which it should never have said for a chat connection.

### 6.3 Six rows removed — an operator who onboarded one of them

`command-code`, `free-ai`, `inner-ai`, `muse-code`, `nlpcloud`, `oneminai`
(and the aliases `cmd`, `in-ai`, `1min`, `nlpc`) are no longer offered. An
existing ProviderKey whose `provider` is one of them still loads and still
holds its `api_base`; `find_preset` returns `None`, so `resolve_bridge`
falls through to the family bridge exactly as it did before this change —
the row was never load-bearing for dispatch, it was onboarding metadata. If
such a key is pointed at a `chat/completions` URL it was already failing
(`…/chat/chat/completions`, `…/responses/chat/completions`,
`…/chat-with-ai/chat/completions` are not served); for `command-code` and
`nlpcloud` the operator must additionally set `api_base` to the path the
vendor actually serves, or onboard the vendor through a bridge that knows it.

### 6.4 New wire `type` the dashboard does not model yet

`maritalk` is published as `{"type":"authorization_scheme","scheme":"Key"}`
rather than `{"type":"api_key_header","header":"key"}`. This is deliberate:
publishing a header name there is the one instruction a client cannot act on
correctly. **A client that only knows `bearer` / `api_key_header` / `none`
must be taught `authorization_scheme` before the hint is correct** — today
`omniroute/src/shared/utils/aisixPresets.ts` `readAuthShape` returns
`authHeader: null` for it, so the wizard shows no header hint for
`maritalk` instead of showing a wrong one. That is a cosmetic gap, not a
routing one: the key is pasted into the same standard field either way and
the gateway now sends it correctly regardless of what the wizard says.
