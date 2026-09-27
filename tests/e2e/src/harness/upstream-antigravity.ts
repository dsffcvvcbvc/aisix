import { createServer, type Server } from "node:http";
import { pickFreePort } from "./ports.js";

/**
 * The Cloud Code RPC path the Antigravity bridge posts to. Matches the
 * `ANTIGRAVITY_RPC_URL` / `ANTIGRAVITY_RPC_FALLBACK_URL` consts in
 * `crates/aisix-provider-vertex/src/antigravity.rs` — asserted rather than
 * merely documented, so a rename upstream reds here instead of turning every
 * Antigravity request into a silent 404.
 */
export const ANTIGRAVITY_RPC_PATH = "/v1internal:streamGenerateContent";

/**
 * The Gemini `usageMetadata` counters, in the field names the wire uses
 * (`AntigravityUsage` in the bridge renames each one). Defaults are a
 * mostly-cached prompt: the subject of the Antigravity metrics e2e is
 * `cachedContentTokenCount`, and a default that reported no cache detail
 * would let that counter go unpinned.
 */
export interface AntigravityUsage {
  promptTokenCount?: number;
  candidatesTokenCount?: number;
  totalTokenCount?: number;
  /** A SUBSET of `promptTokenCount` — the OpenAI accounting shape. */
  cachedContentTokenCount?: number;
  thoughtsTokenCount?: number;
  toolUsePromptTokenCount?: number;
}

export interface AntigravityUpstreamOptions {
  /** Assistant text carried in the first candidate's single text part. */
  content?: string;
  usage?: AntigravityUsage;
  /**
   * The `cloudaicompanionProject` discovery would return, for a spec that
   * deliberately leaves `ProviderKey.project` unset and lets the bridge
   * discover. Omitted leaves `loadCodeAssist` unhandled, which is what a
   * spec that sets `project` wants: discovery must never run.
   */
  discoveredProject?: string;
  /** Status code to answer the RPC with (default 200). */
  status?: number;
  /** Body to return when `status` >= 300. */
  errorBody?: unknown;
}

export interface AntigravityUpstream {
  baseUrl: string;
  /**
   * The URL to hand the gateway as `ANTIGRAVITY_RPC_URL`. Carries the path
   * and the `alt=sse` query the bridge sends, so a spec names one value in
   * one place and cannot get the seam half-right.
   */
  rpcUrl: string;
  receivedRequests: ReceivedAntigravityRequest[];
  close(): Promise<void>;
}

export interface ReceivedAntigravityRequest {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  body: string;
}

/**
 * A node http server standing in for Google Cloud Code, serving the two
 * endpoints the Antigravity bridge reaches for:
 *
 *   - `POST /v1internal:streamGenerateContent?alt=sse` — the content RPC,
 *     answered with Gemini-shaped SSE frames (`data: {"response": {…}}`).
 *   - `POST /v1internal:loadCodeAssist` — the project-discovery bootstrap,
 *     only reached by a spec that leaves `project` unset.
 *
 * The token refresh is deliberately NOT served here: a credential starting
 * with `ya29.` short-circuits `AntigravityTokenMint::get_token` to the value
 * itself, so the mock IS the stubbed Google token mint — put such a
 * credential on the ProviderKey and no OAuth round-trip is ever attempted.
 * A spec wanting the refresh path itself would have to point the bridge at
 * `oauth2.googleapis.com`, which this harness does not stand up.
 */
export async function startAntigravityUpstream(
  opts: AntigravityUpstreamOptions = {},
): Promise<AntigravityUpstream> {
  const received: ReceivedAntigravityRequest[] = [];

  const handler = (
    req: import("node:http").IncomingMessage,
    res: import("node:http").ServerResponse,
  ) => {
    res.on("error", () => {});
    let raw = "";
    req.on("data", (c: Buffer) => (raw += c.toString("utf8")));
    req.on("end", () => {
      const [path = "", query = ""] = (req.url ?? "/").split("?");
      received.push({
        method: req.method ?? "GET",
        path,
        query,
        headers: Object.fromEntries(
          Object.entries(req.headers).map(([k, v]) => [
            k,
            Array.isArray(v) ? v.join(",") : (v ?? ""),
          ]),
        ),
        body: raw,
      });

      if (path === "/v1internal:loadCodeAssist") {
        if (opts.discoveredProject === undefined) {
          res.statusCode = 404;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ error: "not served by this mock" }));
          return;
        }
        res.statusCode = 200;
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            cloudaicompanionProject: opts.discoveredProject,
          }),
        );
        return;
      }

      if (path !== ANTIGRAVITY_RPC_PATH) {
        res.statusCode = 404;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: `unexpected path ${path}` }));
        return;
      }

      const status = opts.status ?? 200;
      if (status >= 300) {
        res.statusCode = status;
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify(opts.errorBody ?? { error: { message: "mock error" } }),
        );
        return;
      }

      res.statusCode = 200;
      res.setHeader("content-type", "text/event-stream");
      res.setHeader("cache-control", "no-cache");
      res.flushHeaders();
      res.write(
        `data: ${JSON.stringify({
          response: {
            candidates: [
              {
                content: { parts: [{ text: opts.content ?? "mock reply" }] },
                finishReason: "STOP",
              },
            ],
            usageMetadata: opts.usage ?? {
              promptTokenCount: 120,
              candidatesTokenCount: 7,
              totalTokenCount: 127,
              cachedContentTokenCount: 96,
            },
          },
        })}\n\n`,
      );
      res.end("data: [DONE]\n\n");
    });
  };

  const server: Server = createServer(handler);
  const port = await pickFreePort();
  await new Promise<void>((resolve) =>
    server.listen(port, "127.0.0.1", resolve),
  );
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    baseUrl,
    rpcUrl: `${baseUrl}${ANTIGRAVITY_RPC_PATH}?alt=sse`,
    receivedRequests: received,
    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}
