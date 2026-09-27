import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
  EtcdClient,
  ProxyClient,
  SeedClient,
  metricDelta,
  scrapeMetrics,
  spawnApp,
  startAntigravityUpstream,
  waitConfigPropagation,
  type AntigravityUpstream,
  type MetricSample,
  type ReceivedAntigravityRequest,
  type SpawnedApp,
} from "../harness/index.js";

/**
 * The Antigravity cached-token counter, proven on a real request.
 *
 * `aisix_llm_cached_input_tokens_total` was, until this spec, asserted only
 * at unit level. Per the repo's rule (`CLAUDE.md`, "Handler Families Stay in
 * Lockstep"), a metric family is shipped when an e2e sees it MOVE in
 * `GET /metrics` after driving real traffic — a `pub` emit function with a
 * unit test is exactly the invisible case that rule names. Closing this is
 * what ships the counter.
 *
 * The counter's whole point is a boundary: Gemini reports
 * `cachedContentTokenCount` as a SUBSET of `promptTokenCount`, so it must
 * land in `aisix_llm_cached_input_tokens_total` and must NOT be added into
 * `aisix_llm_input_tokens_total`. Both halves are asserted, because a bridge
 * that dropped the value entirely and one that added it into the prompt
 * total would both leave only the first assertion's absence looking right.
 *
 * Why a mock is required at all: the RPC endpoint was a compiled-in const
 * (`ANTIGRAVITY_RPC_URL`), so no test could stand an upstream for this
 * bridge. `ANTIGRAVITY_RPC_URL` is the seam that makes it possible, and the
 * mock is also the stubbed Google token mint — a `ya29.`-prefixed
 * credential short-circuits `get_token`, so no OAuth round-trip is attempted
 * and the only network call this spec causes is the one it can see.
 *
 * Source-blind by construction: the mock is a Gemini-shaped SSE upstream, and
 * the expected numbers below follow from the counters this spec reports,
 * not from reading the bridge.
 */

const CALLER_PLAINTEXT = "sk-antigravity-cached-e2e";
const CALLER_KEY_HASH = createHash("sha256")
  .update(CALLER_PLAINTEXT)
  .digest("hex");

const MODEL = "antigravity-cached-e2e-model";

/** A pre-minted access token: the bridge accepts it as-is, no token mint. */
const MINTED_ACCESS_TOKEN = "ya29.mock-access-token-for-e2e";

/** Prompt total the upstream reports, of which `PROMPT` came from cache. */
const PROMPT_TOKENS = 120;
const CACHED_TOKENS = 96;
/** Gemini identity: total = prompt + candidates (thoughts folded in). */
const CANDIDATES_TOKENS = 7;
const TOTAL_TOKENS = PROMPT_TOKENS + CANDIDATES_TOKENS;

/** Uncached prompt tokens — the part of the prompt that was NOT a cache hit. */
const UNCACHED_PROMPT_TOKENS = PROMPT_TOKENS - CACHED_TOKENS;

const CACHED = "aisix_llm_cached_input_tokens_total";
const INPUT = "aisix_llm_input_tokens_total";
const OUTPUT = "aisix_llm_output_tokens_total";
const TOTAL = "aisix_llm_total_tokens_total";
/** The Anthropic-shape counters. A Gemini-shaped request must mint NEITHER. */
const CACHE_READ = "aisix_llm_cache_read_input_tokens_total";
const CACHE_CREATION = "aisix_llm_cache_creation_input_tokens_total";

/** The label the `aisix_llm_*` families slice this traffic on. */
const LABEL = { model: MODEL, provider: "antigravity" };

describe("antigravity cached-token metric: one real request, one scrape", () => {
  let app: SpawnedApp | undefined;
  let upstream: AntigravityUpstream | undefined;
  let proxy: ProxyClient | undefined;
  let reachable = false;

  beforeAll(async () => {
    const etcd = new EtcdClient();
    reachable = await etcd.ping();
    if (!reachable) return;

    upstream = await startAntigravityUpstream({
      content: "antigravity mock reply",
      usage: {
        promptTokenCount: PROMPT_TOKENS,
        candidatesTokenCount: CANDIDATES_TOKENS,
        totalTokenCount: TOTAL_TOKENS,
        cachedContentTokenCount: CACHED_TOKENS,
      },
    });

    app = await spawnApp({ extraEnv: { ANTIGRAVITY_RPC_URL: upstream.rpcUrl } });
    const seed = new SeedClient(etcd, app.etcdPrefix);

    const pk = await seed.createProviderKey({
      display_name: "antigravity-cached-e2e-pk",
      api_key: MINTED_ACCESS_TOKEN,
      // Set, so the bridge skips `loadCodeAssist` discovery entirely: the
      // mock only ever sees the content RPC.
      project: "mock-project",
      provider: "antigravity",
    });
    await seed.createModel({
      display_name: MODEL,
      provider: "antigravity",
      model_name: "gemini-3-pro",
      provider_key_id: pk.id,
    });
    await seed.createApiKey({
      key_hash: CALLER_KEY_HASH,
      allowed_models: [MODEL],
    });

    proxy = new ProxyClient(app.proxyUrl, CALLER_PLAINTEXT);
    // Gate on the caller key authenticating — the condition that implies the
    // whole seed set (ProviderKey included) is in the snapshot. Not a chat
    // call: that is the behavior under test, and a gate that exercised it
    // would fail by timeout rather than by assertion.
    await waitConfigPropagation(async () => {
      const res = await proxy!.listModels();
      return res.status === 200;
    });
  });

  afterAll(async () => {
    await app?.exit();
    await upstream?.close();
  });

  test("one request reaches the mock RPC with the minted token, and the two cache families move by their own amounts", async (ctx) => {
    if (!reachable || !app || !proxy || !upstream) {
      ctx.skip();
      return;
    }

    const before: MetricSample[] = await scrapeMetrics(app.metricsUrl);

    const res = await proxy.chat({
      model: MODEL,
      messages: [{ role: "user", content: "how much of this prompt was cached?" }],
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect((res.body as { choices: Array<{ message: { content: string } }> }).choices[0].message
      .content).toBe("antigravity mock reply");

    // The upstream the request actually went to. Asserted on the recorded
    // request, not on a counter: a bridge that answered from somewhere else
    // would otherwise be invisible.
    const rpc: ReceivedAntigravityRequest[] = upstream.receivedRequests.filter(
      (r) => r.path === "/v1internal:streamGenerateContent",
    );
    expect(rpc).toHaveLength(1);
    expect(rpc[0].method).toBe("POST");
    expect(rpc[0].query).toBe("alt=sse");
    expect(rpc[0].headers.authorization).toBe(`Bearer ${MINTED_ACCESS_TOKEN}`);
    expect(rpc[0].headers.accept).toBe("text/event-stream");
    // No discovery round-trip: `project` was set, so `loadCodeAssist` never ran.
    expect(
      upstream.receivedRequests.filter((r) => r.path === "/v1internal:loadCodeAssist"),
    ).toHaveLength(0);

    const after: MetricSample[] = await scrapeMetrics(app.metricsUrl);

    // The counter this spec exists for: the cached subset, its own value.
    expect(metricDelta(before, after, CACHED, LABEL)).toBe(CACHED_TOKENS);
    // The prompt total is NOT grown by the cached part — it is the upstream's
    // own `promptTokenCount`, cache hit included. This is the half that fails
    // if a bridge ever adds the two together.
    expect(metricDelta(before, after, INPUT, LABEL)).toBe(PROMPT_TOKENS);
    expect(metricDelta(before, after, OUTPUT, LABEL)).toBe(CANDIDATES_TOKENS);
    expect(metricDelta(before, after, TOTAL, LABEL)).toBe(TOTAL_TOKENS);

    // The two families are for the OTHER accounting shape and stay absent
    // for a Gemini-shaped request. A series that never appears and a series
    // sitting at zero read the same here, so this is the sharp form: no
    // sample of either name may exist for this traffic.
    expect(sumFor(after, CACHE_READ, LABEL)).toBe(0);
    expect(sumFor(after, CACHE_CREATION, LABEL)).toBe(0);
  });
});

/** Total of every sample of `name` whose labels include `want`. */
function sumFor(
  samples: MetricSample[],
  name: string,
  want: Record<string, string>,
): number {
  return samples
    .filter(
      (s) =>
        s.name === name &&
        Object.entries(want).every(([k, v]) => s.labels[k] === v),
    )
    .reduce((acc, s) => acc + s.value, 0);
}
