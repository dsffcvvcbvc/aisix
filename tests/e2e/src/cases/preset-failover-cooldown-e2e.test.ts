import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import {
  AdminClient,
  EtcdClient,
  ProxyClient,
  SeedClient,
  metricDelta,
  scrapeMetrics,
  spawnApp,
  startOpenAiUpstream,
  waitConfigPropagation,
  type MetricSample,
  type OpenAiUpstream,
  type SpawnedApp,
} from "../harness/index.js";

/**
 * Failover and cooldown, driven through CATALOGUED preset vendors.
 *
 * Both mechanisms have their own specs already (`fallback-e2e`,
 * `cooldown-contract-e2e`, `runtime-status-e2e`) — and every Model in those
 * is a hand-written `provider: "openai"` row. What they cannot say is
 * whether a vendor that reaches the OpenAI family bridge through
 * `resolve_bridge`'s preset fallback behaves the same under a routing group
 * and a 429. The catalog lookup is the only thing that differs on the way
 * to dispatch, so that is what this spec varies: the targets are real
 * catalog ids, and everything downstream of the bridge is held constant.
 *
 * The cooldown half also pins the DOCUMENTED default TTL against the shipped
 * one. `CooldownConfig::default_seconds_or_default()` is **30** seconds
 * (`crates/aisix-core/src/models/model.rs`, `DEFAULT_COOLDOWN_SECONDS = 30`)
 * — not 60 — so `cooldown_until` is asserted to land about 30s out. A TTL
 * assertion at 60 would pass on a 30s default only if it were loose enough
 * to accept both, which is the same no-op assertion in a different coat.
 */

const CALLER_PLAINTEXT = "sk-preset-failover-cooldown-e2e";
const CALLER_KEY_HASH = createHash("sha256")
  .update(CALLER_PLAINTEXT)
  .digest("hex");

const UPSTREAM_SECRET = "sk-preset-failover-upstream";

/** `DEFAULT_COOLDOWN_SECONDS` — see the module comment. */
const DOCUMENTED_COOLDOWN_SECONDS = 30;
/** Slack for clock skew and request time, not for a wrong default. */
const COOLDOWN_TOLERANCE_SECONDS = 8;

const REQUESTS = "aisix_llm_requests_total";
const DEPLOYMENT_REQUESTS = "aisix_deployment_requests_total";
const DEPLOYMENT_FAILURES = "aisix_deployment_failure_responses_total";
const DEPLOYMENT_SUCCESSES = "aisix_deployment_success_responses_total";
const SUCCESSFUL_FALLBACKS = "aisix_routing_successful_fallbacks_total";
const INPUT = "aisix_llm_input_tokens_total";
const CACHED = "aisix_llm_cached_input_tokens_total";

/** Prompt total the mocks report; `CACHED_PROMPT_TOKENS` of it is a cache hit. */
const USAGE = { prompt_tokens: 21, completion_tokens: 6, total_tokens: 27 };
const CACHED_PROMPT_TOKENS = 13;

/**
 * The chat requests that reached one mock, ignoring everything else.
 *
 * `GET /v1/models` — the readiness gate every spec uses — makes the gateway
 * ask each Provider Key's `api_base` for its catalog, so a mock's
 * `receivedRequests` is never only this spec's chat traffic. Counting the
 * whole array asserts a coincidence of how often the gate polled (the full
 * suite left 22 recorded requests where a standalone run left 1). Counting
 * the chat path asserts the subject.
 */
function chatsTo(mock: OpenAiUpstream, path: string) {
  return mock.receivedRequests.filter((r) => r.path === path);
}

/**
 * The chat path a vendor's `api_base` produces, from the same expression
 * the seed uses. Derived rather than written out twice: the two copies
 * drifted once, and a filter on a path nothing ever requests silently
 * counts zero — which reads as "the upstream was never called" and inverts
 * the meaning of every assertion built on it.
 */
const chatPath = (vendor: string) => `/v-${vendor}/chat/completions`;

/** The 429 mock's chat traffic — the counts the cooldown test reasons about. */
function rateLimitedChats(mock: OpenAiUpstream) {
  return chatsTo(mock, chatPath(VENDOR_COOLDOWN));
}

/** Two real catalog ids, chosen because neither is Cohere. */
const VENDOR_PRIMARY = "groq";
const VENDOR_SECONDARY = "deepseek";
/** A third, on its own, for the cooldown half. */
const VENDOR_COOLDOWN = "together";

const MODEL_FAILOVER_GROUP = "preset-failover-group";
const MODEL_PRIMARY = "preset-failover-primary";
const MODEL_SECONDARY = "preset-failover-secondary";
const MODEL_COOLDOWN = "preset-cooldown-target";
const MODEL_COOLDOWN_FALLBACK = "preset-cooldown-fallback";
const MODEL_COOLDOWN_GROUP = "preset-cooldown-group";

function chatBody(content: string) {
  return {
    id: "chatcmpl-preset-failover",
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: "mock-model",
    choices: [
      { index: 0, message: { role: "assistant", content }, finish_reason: "stop" },
    ],
    usage: {
      prompt_tokens: USAGE.prompt_tokens,
      completion_tokens: USAGE.completion_tokens,
      total_tokens: USAGE.total_tokens,
      prompt_tokens_details: { cached_tokens: CACHED_PROMPT_TOKENS },
    },
  };
}

describe("preset-catalog vendors under routing: failover on 5xx, cooldown on 429", () => {
  let app: SpawnedApp | undefined;
  let admin: AdminClient | undefined;
  let proxy: ProxyClient | undefined;
  let failing: OpenAiUpstream | undefined;
  let healthy: OpenAiUpstream | undefined;
  let rateLimited: OpenAiUpstream | undefined;
  let reachable = false;

  beforeAll(async () => {
    const etcd = new EtcdClient();
    reachable = await etcd.ping();
    if (!reachable) return;

    failing = await startOpenAiUpstream({
      status: 503,
      errorBody: { error: { message: "upstream unavailable", type: "server_error" } },
    });
    healthy = await startOpenAiUpstream({ nonStreamBody: chatBody("served by secondary") });
    // 429 with no `Retry-After`, so the TTL is the documented default rather
    // than whatever the upstream asked for — otherwise the default is not
    // what is under test.
    rateLimited = await startOpenAiUpstream({
      status: 429,
      errorBody: { error: { message: "rate limit exceeded", type: "rate_limit_error" } },
    });

    app = await spawnApp();
    admin = new AdminClient(app.adminUrl, app.adminKey, app.metricsUrl);
    proxy = new ProxyClient(app.proxyUrl, CALLER_PLAINTEXT);
    const seed = new SeedClient(etcd, app.etcdPrefix);

    const primaryPk = await seed.createProviderKey({
      display_name: "preset-failover-primary-pk",
      api_key: UPSTREAM_SECRET,
      api_base: `${failing.baseUrl}/v-${VENDOR_PRIMARY}`,
      provider: VENDOR_PRIMARY,
      adapter: "openai",
    });
    const secondaryPk = await seed.createProviderKey({
      display_name: "preset-failover-secondary-pk",
      api_key: UPSTREAM_SECRET,
      api_base: `${healthy.baseUrl}/v-${VENDOR_SECONDARY}`,
      provider: VENDOR_SECONDARY,
      adapter: "openai",
    });
    await seed.createModel({
      display_name: MODEL_PRIMARY,
      provider: VENDOR_PRIMARY,
      model_name: "mock-model",
      provider_key_id: primaryPk.id,
      // Off: a 5xx would cool this target down after the first request, and
      // the next request would then skip it — which would stop testing
      // within-request failover.
      cooldown: { enabled: false },
    });
    await seed.createModel({
      display_name: MODEL_SECONDARY,
      provider: VENDOR_SECONDARY,
      model_name: "mock-model",
      provider_key_id: secondaryPk.id,
    });
    await seed.createModel({
      display_name: MODEL_FAILOVER_GROUP,
      routing: {
        strategy: "failover",
        targets: [{ model: MODEL_PRIMARY }, { model: MODEL_SECONDARY }],
        max_fallbacks: 1,
      },
    });

    const cooldownPk = await seed.createProviderKey({
      display_name: "preset-cooldown-pk",
      api_key: UPSTREAM_SECRET,
      api_base: `${rateLimited.baseUrl}/v-${VENDOR_COOLDOWN}`,
      provider: VENDOR_COOLDOWN,
      adapter: "openai",
    });
    const cooldownFallbackPk = await seed.createProviderKey({
      display_name: "preset-cooldown-fallback-pk",
      api_key: UPSTREAM_SECRET,
      api_base: `${healthy.baseUrl}/v-cooldown-fallback`,
      provider: VENDOR_SECONDARY,
      adapter: "openai",
    });
    await seed.createModel({
      display_name: MODEL_COOLDOWN,
      provider: VENDOR_COOLDOWN,
      model_name: "mock-model",
      provider_key_id: cooldownPk.id,
      // Opt-in: cooldown runs only when the operator asks for it.
      cooldown: { enabled: true },
    });
    await seed.createModel({
      display_name: MODEL_COOLDOWN_FALLBACK,
      provider: VENDOR_SECONDARY,
      model_name: "mock-model",
      provider_key_id: cooldownFallbackPk.id,
    });
    // The cooldown target is reached through a GROUP, not addressed
    // directly: cooldown is a candidate FILTER
    // (`ModelRuntimeStatusTracker::should_skip_for_routing`), so a caller
    // naming the cooled model directly still gets a dispatch — there is no
    // candidate list to filter. Exercising it behind a group is what makes
    // "the next request skipped the cooled target" observable at all.
    await seed.createModel({
      display_name: MODEL_COOLDOWN_GROUP,
      routing: {
        strategy: "failover",
        targets: [{ model: MODEL_COOLDOWN }, { model: MODEL_COOLDOWN_FALLBACK }],
        max_fallbacks: 1,
      },
    });

    await seed.createApiKey({
      key_hash: CALLER_KEY_HASH,
      allowed_models: [
        MODEL_FAILOVER_GROUP,
        MODEL_SECONDARY,
        MODEL_COOLDOWN,
        MODEL_COOLDOWN_GROUP,
      ],
    });

    await waitConfigPropagation(async () => {
      const res = await proxy!.listModels();
      return res.status === 200;
    });
  });

  afterAll(async () => {
    await app?.exit();
    await failing?.close();
    await healthy?.close();
    await rateLimited?.close();
  });

  test("a 5xx on the first catalogued target fails over to the second, and the caller sees 200", async (ctx) => {
    if (!reachable || !proxy || !failing || !healthy) {
      ctx.skip();
      return;
    }

    const before: MetricSample[] = await scrapeMetrics(app!.metricsUrl);
    const res = await proxy.chat({
      model: MODEL_FAILOVER_GROUP,
      messages: [{ role: "user", content: "fail over please" }],
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(
      (res.body as { choices: Array<{ message: { content: string } }> }).choices[0].message
        .content,
    ).toBe("served by secondary");
    const after: MetricSample[] = await scrapeMetrics(app!.metricsUrl);

    // Both upstreams were actually hit — the second mock's reply is the
    // evidence, and the first mock's recorded request is the other half.
    // Asserting only the 200 would pass against a gateway that answered
    // from nowhere.
    expect(
      chatsTo(failing!, chatPath(VENDOR_PRIMARY)),
    ).toHaveLength(1);
    expect(
      chatsTo(healthy!, chatPath(VENDOR_SECONDARY)),
    ).toHaveLength(1);

    // Per-ATTEMPT counters, filed under the target each attempt hit. The
    // failed 5xx appears in no request-level series — that is by design, and
    // the contrast is asserted so it cannot be mistaken for a gap.
    expect(metricDelta(before, after, DEPLOYMENT_REQUESTS, { model: MODEL_PRIMARY })).toBe(1);
    expect(metricDelta(before, after, DEPLOYMENT_FAILURES, { model: MODEL_PRIMARY })).toBe(1);
    expect(metricDelta(before, after, DEPLOYMENT_REQUESTS, { model: MODEL_SECONDARY })).toBe(1);
    expect(metricDelta(before, after, DEPLOYMENT_SUCCESSES, { model: MODEL_SECONDARY })).toBe(1);
    expect(
      metricDelta(before, after, SUCCESSFUL_FALLBACKS, {
        model: MODEL_FAILOVER_GROUP,
        fallback_model: MODEL_SECONDARY,
      }),
    ).toBe(1);
    // The request-level family carries BOTH identities, and pinning the
    // split is the point: `model` is the caller-addressed ENTRY (the group
    // the caller named), while `provider` / `provider_key_id` name the
    // DISPATCHED TARGET that actually served it. Asserting the group alone
    // would pass against a gateway that recorded the primary's 5xx; the
    // `is_fallback` label is what says the rescue happened.
    expect(
      metricDelta(before, after, REQUESTS, {
        model: MODEL_FAILOVER_GROUP,
        provider: VENDOR_SECONDARY,
        is_fallback: "true",
        status: "200",
      }),
    ).toBe(1);
    // No request-level sample names the group AND the failed target: the
    // 5xx is an attempt, and attempts live in the deployment family.
    expect(
      metricDelta(before, after, REQUESTS, { model: MODEL_FAILOVER_GROUP, provider: VENDOR_PRIMARY }),
    ).toBe(0);
    // …and the group's total is one request, not two.
    expect(metricDelta(before, after, REQUESTS, { model: MODEL_FAILOVER_GROUP })).toBe(1);

    // The rescued request's token accounting, filed under the entry the
    // caller addressed and the target that served it: the cached subset
    // beside the prompt total, never added into it.
    const served = { model: MODEL_FAILOVER_GROUP, provider: VENDOR_SECONDARY };
    expect(metricDelta(before, after, INPUT, served)).toBe(USAGE.prompt_tokens);
    expect(metricDelta(before, after, CACHED, served)).toBe(CACHED_PROMPT_TOKENS);
  });

  test("a 429 cools a catalogued target for the documented default TTL, and GET /status/models shows it", async (ctx) => {
    if (!reachable || !app || !proxy || !admin || !rateLimited || !healthy) {
      ctx.skip();
      return;
    }

    // Before: the target is healthy and no CHAT request has reached it.
    //
    // "No request at all" would be the wrong assertion and was the first
    // version of it: the readiness gate is `GET /v1/models`, which the
    // gateway answers by asking every Provider Key's `api_base` for its
    // catalog, so this mock legitimately records those probes. Filtering to
    // the chat path is what makes the counts mean what they claim — the
    // whole-subject assertion that caught it was the full-suite run, where
    // the gate polled often enough to leave 22 recorded requests.
    const before = await admin.listModelStatuses();
    const beforeRow = before.find((r) => r.display_name === MODEL_COOLDOWN);
    expect(beforeRow, `${MODEL_COOLDOWN} missing from /status/models`).toBeDefined();
    expect(beforeRow!.status).toBe("healthy");
    expect(beforeRow!.cooldown_until).toBeUndefined();
    expect(rateLimitedChats(rateLimited!)).toHaveLength(0);

    // One 429, through the group. 429 is not retried by default
    // (`retry_on_429` defaults false and `fallback_on_statuses` is empty),
    // so it surfaces to the caller unchanged — cooldown is an independent
    // layer, not a retry.
    const requestedAt = Date.now();
    const res = await proxy.chat({
      model: MODEL_COOLDOWN_GROUP,
      messages: [{ role: "user", content: "get me cooled down" }],
    });
    expect(res.status, JSON.stringify(res.body)).toBe(429);
    expect(rateLimitedChats(rateLimited!)).toHaveLength(1);

    // The state shows on the status listener, unauthenticated, as
    // `cooldown` plus the instant the target returns to rotation.
    const after = await admin.listModelStatuses();
    const row = after.find((r) => r.display_name === MODEL_COOLDOWN)!;
    expect(row.status).toBe("cooldown");
    // `cooldown_until` is a `SystemTime`, so serde renders it as the pair
    // `{"secs_since_epoch":…, "nanos_since_epoch":…}` — NOT an RFC3339
    // string. `new Date(...)` on that is `Invalid Date`, and the arithmetic
    // below would silently be `NaN`; the shape is therefore pinned before
    // the TTL is read off it, so a change to the encoding is a failure
    // rather than a NaN that happens to compare false.
    expect(
      row.cooldown_until,
      "cooldown_until must be present while the target is cooling down",
    ).toBeTruthy();
    const until = row.cooldown_until as { secs_since_epoch: number; nanos_since_epoch: number };
    expect(
      typeof until.secs_since_epoch,
      `cooldown_until shape was ${JSON.stringify(row.cooldown_until)}`,
    ).toBe("number");
    const untilMs = until.secs_since_epoch * 1000 + until.nanos_since_epoch / 1e6;
    const ttlSeconds = (untilMs - requestedAt) / 1000;
    expect(
      ttlSeconds,
      `cooldown TTL was ${ttlSeconds.toFixed(1)}s, expected ~${DOCUMENTED_COOLDOWN_SECONDS}s`,
    ).toBeGreaterThan(DOCUMENTED_COOLDOWN_SECONDS - COOLDOWN_TOLERANCE_SECONDS);
    expect(ttlSeconds).toBeLessThan(DOCUMENTED_COOLDOWN_SECONDS + COOLDOWN_TOLERANCE_SECONDS);

    // The routing model itself is virtual, so it carries no runtime health
    // of its own — the state lives on the direct target the group reached.
    const groupRow = after.find((r) => r.display_name === MODEL_COOLDOWN_GROUP)!;
    expect(groupRow.kind).toBe("routing");
    expect(groupRow.status).toBe("not_applicable");
    expect(groupRow.cooldown_until).toBeUndefined();

    // The cooldown is REAL, not just rendered: the next request through the
    // group never reaches the 429 mock and is served by the second target.
    // A status view that says "cooldown" while dispatch still walks
    // straight into it is exactly the lie this assertion exists to catch.
    const second = await proxy.chat({
      model: MODEL_COOLDOWN_GROUP,
      messages: [{ role: "user", content: "am I still cooled down?" }],
    });
    expect(second.status, JSON.stringify(second.body)).toBe(200);
    expect(
      (second.body as { choices: Array<{ message: { content: string } }> }).choices[0].message
        .content,
    ).toBe("served by secondary");
    // The decisive count: the cooled upstream was NOT called a second time.
    expect(
      rateLimitedChats(rateLimited!),
      "the cooled target must be out of the candidate list",
    ).toHaveLength(1);
    expect(
      chatsTo(healthy!, "/v-cooldown-fallback/chat/completions"),
    ).toHaveLength(1);
  });
});
