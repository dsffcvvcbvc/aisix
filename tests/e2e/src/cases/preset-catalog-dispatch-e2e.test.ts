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
  type ReceivedRequest,
  type SpawnedApp,
} from "../harness/index.js";

/**
 * The WHOLE preset catalog dispatches, driven through a local mock upstream.
 *
 * `crates/aisix-provider-openai/src/presets.rs` catalogs 190 vendors whose
 * upstream is a plain OpenAI-shaped REST endpoint, and
 * `crates/aisix-proxy/src/dispatch.rs::resolve_bridge` falls back to the
 * OpenAI family bridge for any catalogued provider. That fallback is a
 * `find_preset` membership test, so a catalog entry is a claim that a vendor
 * will dispatch — and until now only 18 of the 190 had been spot-checked.
 * This spec drives all of them.
 *
 * The catalog is read from the product's own surface
 * (`GET /admin/v1/preset_providers`) rather than parsed out of the Rust
 * source, so what is driven is what an onboarding dashboard is offered, and
 * the "190" is the product's count rather than a literal this file repeats.
 *
 * Each vendor gets its own `api_base` path (`/v-<id>`) on one shared mock, so
 * a request that reached the wrong vendor's base is visible in the recorded
 * path instead of being indistinguishable from a correct one.
 *
 * WHAT THIS SPEC DOES NOT CLAIM: the real upstream URLs in the catalog are
 * unreachable from here, so `base_url` is proven as "the request went to the
 * base the resource names", never as "the vendor answered". Only
 * `maritalk`'s path shape is not derivable from `api_base` — the bridge
 * rewrites Cohere's base (see `cohere::is_cohere`), and the rewrite is
 * asserted below.
 */

const CALLER_PLAINTEXT = "sk-preset-catalog-dispatch-e2e";
const CALLER_KEY_HASH = createHash("sha256")
  .update(CALLER_PLAINTEXT)
  .digest("hex");

/** Credential the mock expects, one per spec run. */
const UPSTREAM_SECRET = "sk-preset-catalog-upstream";

/** The catalog size the crate pins (`PRESET_PROVIDER_COUNT`). */
const EXPECTED_CATALOG_SIZE = 190;

const REQUESTS = "aisix_llm_requests_total";
const INPUT = "aisix_llm_input_tokens_total";
const OUTPUT = "aisix_llm_output_tokens_total";
const CACHED = "aisix_llm_cached_input_tokens_total";
const DURATION = "aisix_llm_request_duration_seconds_count";

/** The OpenAI-shaped usage every mock reply reports. */
const USAGE = { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 };
/** ...of which this many came out of the upstream's prompt cache. */
const CACHED_TOKENS = 8;

/** One catalog row, as `GET /admin/v1/preset_providers` projects it. */
interface PresetRow {
  id: string;
  display_name: string;
  base_url: string;
  auth: { type: string; header?: string };
  headers: Array<{ name: string; value: string }>;
}

/**
 * The 184 `Bearer` rows, i.e. the ones whose declared auth shape IS what the
 * OpenAI family bridge does. The six exceptions are the subject of their own
 * test below, and must not be silently folded into this count.
 */
function bearerRows(rows: PresetRow[]): PresetRow[] {
  return rows.filter((r) => r.auth.type === "bearer");
}

function apiKeyHeaderRows(rows: PresetRow[]): PresetRow[] {
  return rows.filter((r) => r.auth.type === "api_key_header");
}

/**
 * The upstream path a vendor's `api_base` produces. The family bridge
 * appends `/chat/completions` to the resolved base; Cohere is the one
 * vendor whose base is rewritten first, to `<root>/compatibility/v1`
 * (`crates/aisix-provider-openai/src/cohere.rs` — its `/v1` sibling answers
 * 405, so the rewrite is a correctness requirement, not a preference).
 */
function expectedPath(row: PresetRow): string {
  const base = `/v-${row.id}`;
  return row.id === "cohere"
    ? `${base}/compatibility/v1/chat/completions`
    : `${base}/chat/completions`;
}

describe("preset catalog: every vendor in the catalog dispatches to its own base", () => {
  let app: SpawnedApp | undefined;
  let admin: AdminClient | undefined;
  let proxy: ProxyClient | undefined;
  let upstream: OpenAiUpstream | undefined;
  let reachable = false;
  let catalog: PresetRow[] = [];
  /** `api_key_header` rows, kept for the auth-shape test. */
  let headerAuthRows: PresetRow[] = [];
  /** Bearer rows, kept for the per-vendor auth test. */
  let plainRows: PresetRow[] = [];
  /** Per-vendor outcome, filled in by the drive and asserted in bulk. */
  const outcomes = new Map<string, { status: number; body: unknown }>();

  beforeAll(async () => {
    const etcd = new EtcdClient();
    reachable = await etcd.ping();
    if (!reachable) return;

    upstream = await startOpenAiUpstream({
      nonStreamBody: {
        id: "chatcmpl-preset-catalog",
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: "mock-model",
        choices: [
          {
            index: 0,
            message: { role: "assistant", content: "mock reply" },
            finish_reason: "stop",
          },
        ],
        usage: {
          prompt_tokens: USAGE.prompt_tokens,
          completion_tokens: USAGE.completion_tokens,
          total_tokens: USAGE.total_tokens,
          // The OpenAI accounting shape: a SUBSET of `prompt_tokens`. Set
          // on every reply so the cached-token counter is proven moving
          // across this drive and not just the two plain counters.
          prompt_tokens_details: { cached_tokens: CACHED_TOKENS },
        },
      },
    });

    // The catalog is the product's own onboarding surface, so it is read
    // over the admin listener. `admin: true` is required for the read; the
    // unauthenticated-401 contract is asserted in its own test so enabling
    // it here can never quietly widen access.
    app = await spawnApp({ admin: true });
    admin = new AdminClient(app.adminUrl, app.adminKey, app.metricsUrl);
    proxy = new ProxyClient(app.proxyUrl, CALLER_PLAINTEXT);
    const seed = new SeedClient(etcd, app.etcdPrefix);

    catalog = await admin.json<PresetRow[]>("GET", "/admin/v1/preset_providers");
    headerAuthRows = apiKeyHeaderRows(catalog);
    plainRows = bearerRows(catalog);

    // One ProviderKey + one Model per catalogued vendor, each pointed at its
    // own path on the shared mock.
    for (const row of catalog) {
      const pk = await seed.createProviderKey({
        display_name: `preset-${row.id}-pk`,
        api_key: UPSTREAM_SECRET,
        api_base: `${upstream.baseUrl}/v-${row.id}`,
        // `openai` is the adapter every catalogued vendor speaks; `provider`
        // is the vendor id, which is what `resolve_bridge` looks up.
        provider: row.id,
        adapter: "openai",
      });
      await seed.createModel({
        display_name: `preset-${row.id}-model`,
        provider: row.id,
        model_name: "mock-model",
        provider_key_id: pk.id,
      });
    }
    // Seeded LAST so the gate below implies the whole set: an API key only
    // authenticates once every resource written before it has landed.
    await seed.createApiKey({
      key_hash: CALLER_KEY_HASH,
      allowed_models: catalog.map((r) => `preset-${r.id}-model`),
    });

    await waitConfigPropagation(async () => {
      const res = await proxy!.listModels();
      return res.status === 200;
    });
  }, 300_000);

  afterAll(async () => {
    await app?.exit();
    await upstream?.close();
  });

  test("the catalog read this spec drives is the full, well-formed 190", async (ctx) => {
    if (!reachable || !app || !admin) {
      ctx.skip();
      return;
    }
    expect(catalog).toHaveLength(EXPECTED_CATALOG_SIZE);
    // Unique ids: a duplicate would make one vendor's traffic
    // indistinguishable from another's and the per-vendor path assertion
    // below would silently cover the same vendor twice.
    expect(new Set(catalog.map((r) => r.id)).size).toBe(EXPECTED_CATALOG_SIZE);
    for (const row of catalog) {
      expect(row.id, "id must be lowercase and non-empty").toMatch(/^[a-z0-9-]+$/);
      expect(row.base_url, `${row.id} base_url`).toMatch(/^https?:\/\//);
      expect(
        row.auth.type,
        `${row.id} auth.type must be one this spec models`,
      ).toMatch(/^(bearer|api_key_header|none)$/);
      if (row.auth.type === "api_key_header") {
        expect(row.auth.header, `${row.id} must name its header`).toBeTruthy();
      }
    }
    // The split the auth-shape test below is built on.
    expect(plainRows).toHaveLength(184);
    expect(headerAuthRows).toHaveLength(6);
  });

  test("unauthenticated /admin/v1/preset_providers stays 401", async (ctx) => {
    if (!reachable || !app) {
      ctx.skip();
      return;
    }
    // Spelled with a raw request rather than AdminClient, which always
    // sends the key — the whole point is the request WITHOUT one.
    const res = await fetch(`${app.adminUrl}/admin/v1/preset_providers`);
    expect(res.status).toBe(401);
    await res.body?.cancel();
  });

  test("all 190 vendors dispatch: one request each, every one landing on its own base", async (ctx) => {
    if (!reachable || !proxy || !upstream) {
      ctx.skip();
      return;
    }

    // Sequential: one in-flight request at a time keeps the mock's recorded
    // order the drive's order, so a failure names the vendor unambiguously.
    for (const row of catalog) {
      const res = await proxy.chat({
        model: `preset-${row.id}-model`,
        messages: [{ role: "user", content: `ping ${row.id}` }],
      });
      outcomes.set(row.id, { status: res.status, body: res.body });
    }

    const failed = [...outcomes.entries()]
      .filter(([, o]) => o.status !== 200)
      .map(([id, o]) => `${id} → ${o.status} ${JSON.stringify(o.body).slice(0, 200)}`);
    expect(failed, "vendors that did not answer 200").toEqual([]);

    // Every catalogued vendor reached the mock, on its own base path.
    const seen = new Map<string, number>();
    for (const r of upstream.receivedRequests as ReceivedRequest[]) {
      const hit = catalog.find((row) => r.path === expectedPath(row));
      if (hit) seen.set(hit.id, (seen.get(hit.id) ?? 0) + 1);
    }
    const missing = catalog.filter((row) => !seen.has(row.id)).map((r) => r.id);
    expect(missing, "vendors whose request never reached the mock").toEqual([]);

    // Exactly one request per vendor: a doubled one means the gateway
    // retried, and a request the drive never made.
    const doubled = [...seen.entries()]
      .filter(([, n]) => n !== 1)
      .map(([id, n]) => `${id} x${n}`);
    expect(doubled, "vendors whose mock saw a count other than 1").toEqual([]);

    // No request landed anywhere other than a catalogued vendor's own base
    // — the mock served 190 requests and nothing else.
    const cataloguedPaths = new Set(catalog.map(expectedPath));
    const strays = upstream.receivedRequests
      .map((r) => r.path)
      .filter((p) => !cataloguedPaths.has(p));
    expect([...new Set(strays)], "requests to an unexpected mock path").toEqual([]);
  });

  test("every bearer vendor's credential is exactly one Authorization: Bearer, with no other credential slot", async (ctx) => {
    if (!reachable || !upstream) {
      ctx.skip();
      return;
    }
    for (const row of plainRows) {
      const req = upstream.receivedRequests.find(
        (r) => r.path === expectedPath(row),
      );
      expect(req, `${row.id} never reached the mock`).toBeDefined();
      // Exactly one occurrence, not just one value: node keeps only the
      // first of a repeated name, so `headerNames` is the only way to see a
      // doubled credential (see `ReceivedRequest.headerNames`).
      const authSlots = req!.headerNames.filter(
        (n) => n === "authorization" || n === "proxy-authorization",
      );
      expect(authSlots.length, `${row.id} credential slots`).toBe(1);
      expect(
        req!.headers.authorization,
        `${row.id} authorization`,
      ).toBe(`Bearer ${UPSTREAM_SECRET}`);
    }
  });

  test("the catalog's static headers are onboarding metadata the data plane never sent", async (ctx) => {
    if (!reachable || !upstream) {
      ctx.skip();
      return;
    }
    // The catalog carries static non-secret headers (OpenRouter's
    // `HTTP-Referer`/`X-Title`, …). Nothing on the dispatch path reads them:
    // the only two consumers of the catalog are this admin serializer and
    // `resolve_bridge`'s membership test, so the gateway never puts the
    // catalog's VALUE on the wire on its own.
    //
    // The assertion is on the VALUE, not on the header's absence. Several
    // catalog headers are `User-Agent`, and the outbound HTTP client sets
    // one of its own on every request — asserting the NAME were absent would
    // be asserting that the HTTP client does not identify itself, which is
    // both false and unrelated to the catalog.
    const withHeaders = catalog.filter((row) => row.headers.length > 0);
    expect(withHeaders.length, "vendors declaring static headers").toBeGreaterThan(0);
    for (const row of withHeaders) {
      const req = upstream.receivedRequests.find(
        (r) => r.path === expectedPath(row),
      );
      expect(req, `${row.id} never reached the mock`).toBeDefined();
      for (const header of row.headers) {
        expect(
          req!.headers[header.name.toLowerCase()],
          `${row.id} must not carry the catalog's ${header.name} unsolicited`,
        ).not.toBe(header.value);
      }
    }
  });

  test.fails("KNOWN GAP — the 6 api_key_header vendors still get a Bearer; the catalog's shape is not applied on the data path", async (ctx) => {
    if (!reachable || !upstream) {
      ctx.skip();
      return;
    }
    // `test.fails` is the point, not a workaround: the assertions below are
    // the CORRECT contract (the credential belongs in the header the
    // catalog names), they are expected to fail against the product as it
    // stands, and the day the product applies the declared shape they
    // START FAILING — which vitest reports, forcing this to be rewritten as
    // a plain `test`. Deleting or weakening the assertions instead is how a
    // gap like this rots.
    //
    // Why it is a gap: the OpenAI family bridge builds
    // `Authorization: Bearer <api_key>` unconditionally
    // (`crates/aisix-provider-openai/src/bridge.rs`, `build_request_headers`)
    // and merges `request.default_headers` skip-if-present, so an operator
    // cannot displace it — and the header-template vocabulary
    // (`crates/aisix-core/src/header_template.rs`) has no credential
    // variable, so the secret cannot be routed into another header either.
    // The etalon is no better: `open-sse/executors/default.ts` honours only
    // `x-api-key` / `x-goog-api-key` generically and renders `maritalk`'s
    // `key` via a hard-coded per-vendor switch case.
    expect(
      headerAuthRows.map((r) => r.id).sort(),
      "the six vendors whose declared auth shape is not Bearer",
    ).toEqual([
      "haiper",
      "ideogram",
      "maritalk",
      "oneminai",
      "pioneer",
      "uc-direct",
    ]);

    for (const row of headerAuthRows) {
      const req = upstream.receivedRequests.find(
        (r) => r.path === expectedPath(row),
      );
      expect(req, `${row.id} never reached the mock`).toBeDefined();
      const declared = row.auth.header!;
      // CORRECT behaviour, expected to fail today: the credential goes out
      // in the header the catalog names, not as a Bearer.
      expect(
        req!.headers[declared.toLowerCase()],
        `${row.id} should authenticate via ${declared}`,
      ).toBe(UPSTREAM_SECRET);
    }
  }, 60_000);

  test("the drive moves the llm metric families, including the cached-token counter", async (ctx) => {
    if (!reachable || !app) {
      ctx.skip();
      return;
    }
    // A second, isolated drive of one catalogued vendor, scraped either side,
    // so every family is a DELTA across exactly this request rather than an
    // absolute value the 190-vendor drive already moved.
    const row = plainRows.find((r) => r.id === "openai")!;
    const before: MetricSample[] = await scrapeMetrics(app.metricsUrl);
    const res = await new ProxyClient(app.proxyUrl, CALLER_PLAINTEXT).chat({
      model: `preset-${row.id}-model`,
      messages: [{ role: "user", content: "metrics delta" }],
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const after: MetricSample[] = await scrapeMetrics(app.metricsUrl);

    const label = { model: `preset-${row.id}-model` };
    expect(metricDelta(before, after, REQUESTS, label)).toBe(1);
    expect(metricDelta(before, after, INPUT, label)).toBe(USAGE.prompt_tokens);
    expect(metricDelta(before, after, OUTPUT, label)).toBe(USAGE.completion_tokens);
    // A SUBSET of the prompt total: recorded beside it, never added in.
    expect(metricDelta(before, after, CACHED, label)).toBe(CACHED_TOKENS);
    expect(metricDelta(before, after, DURATION, label)).toBe(1);
  });
});
