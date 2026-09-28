//! aisix-admin::resources_handler — Atomic resources update & static dashboard serving.
//!
//! Provides:
//! - `POST /admin/v1/resources`: validates and updates resources atomically in memory
//! - `GET /dashboard`: serves the OmniRoute SPA dashboard
//! - `GET /dashboard/*path`: route documents, RSC payloads and segment files
//! - `GET /_next/*path` and the origin-root document assets: the files the
//!   exported documents request without the `dashboard` prefix
//! - `GET /` and the origin-root app routes: the export's own non-dashboard
//!   surface, resolved by the same chokepoint as the two above
//! - `GET /providers/*path`: the vendor-logo tree, whose contents are a
//!   property of the catalog rather than of the build, so it is mounted as a
//!   tree — see [`PROVIDERS_DIR`]

use std::path::{Path, PathBuf};

use axum::extract::State;
use axum::http::header::{HeaderValue, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::auth::AdminAuth;
use crate::error::AdminError;
use crate::state::AdminState;

pub async fn update_resources(
    _auth: AdminAuth,
    State(state): State<AdminState>,
    body: String,
) -> Result<Response, AdminError> {
    if body.trim().is_empty() {
        return Err(AdminError::BadRequest("empty resources payload".into()));
    }

    let env_lookup = |name: &str| std::env::var(name).ok();
    // Revision stamped into the loaded snapshot. It is a pre-read
    // counter, i.e. a hint: see the commit note below for why it cannot
    // be exact.
    let revision = state.snapshot.version() + 1;

    let new_snapshot =
        aisix_core::filesource::load_from_str(&body, "admin_api", revision as i64, &env_lookup)
            .map_err(|errs| {
                // Cap the surfaced validation detail: a hostile payload
                // can produce thousands of errors with unbounded
                // messages, and this string lands in the admin API
                // response verbatim.
                const MAX_VALIDATION_ERRORS: usize = 10;
                const MAX_ERROR_CHARS: usize = 500;
                let total = errs.errors.len();
                let msgs: Vec<String> = errs
                    .errors
                    .into_iter()
                    .take(MAX_VALIDATION_ERRORS)
                    .map(|e| {
                        let text = e.to_string();
                        if text.chars().count() > MAX_ERROR_CHARS {
                            let truncated: String = text.chars().take(MAX_ERROR_CHARS).collect();
                            format!("{truncated}…")
                        } else {
                            text
                        }
                    })
                    .collect();
                let suffix = if total > MAX_VALIDATION_ERRORS {
                    format!("; …and {} more", total - MAX_VALIDATION_ERRORS)
                } else {
                    String::new()
                };
                AdminError::BadRequest(format!("Validation failed: {}{suffix}", msgs.join("; ")))
            })?;

    // Commit via `rcu`, which swaps the whole snapshot atomically: an
    // in-flight reader that already loaded the previous one keeps a
    // valid `Arc` to it for as long as it needs, and never observes a
    // half-applied snapshot. It is NOT a version-keyed
    // compare-and-swap here — the closure ignores its argument, so this
    // is a last-writer-wins full replace and two concurrent POSTs both
    // apply, the later one winning. Consequently two concurrent writers
    // can also stamp the SAME revision above (both pre-read the same
    // counter); the response therefore reports the publish counter read
    // back AFTER the commit, which is the value the snapshot consumers
    // actually observe.
    state.snapshot.rcu(|_| new_snapshot.clone());
    let applied_version = state.snapshot.version();

    // Durable persistence: configured `resources_file` first, then
    // `CAVORA_RESOURCES_PATH`, then `resources.yaml`.
    let target_path: PathBuf = state
        .resources_file
        .clone()
        .or_else(|| {
            std::env::var("CAVORA_RESOURCES_PATH")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("resources.yaml"));
    persist_resources_file(&target_path, &body).map_err(AdminError::Store)?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "applied",
            "version": applied_version,
            "message": "Resources validated and applied in memory"
        })),
    )
        .into_response())
}

/// Atomically persist the validated payload: write tmp, fsync the file,
/// rename over the target, then fsync the parent directory. Any I/O
/// failure is returned for a 500 — never silently ignored.
fn persist_resources_file(target: &Path, body: &str) -> Result<(), String> {
    use std::io::Write;

    // Sibling tmp so the rename stays atomic on one filesystem.
    let tmp_path = PathBuf::from(format!("{}.tmp", target.display()));

    let mut file =
        std::fs::File::create(&tmp_path).map_err(|e| format!("write tmp file failed: {e}"))?;
    file.write_all(body.as_bytes())
        .map_err(|e| format!("write tmp file failed: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("fsync tmp file failed: {e}"))?;
    drop(file);
    std::fs::rename(&tmp_path, target).map_err(|e| format!("rename tmp file failed: {e}"))?;
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            if let Ok(dir) = std::fs::File::open(parent) {
                if let Err(e) = dir.sync_all() {
                    tracing::warn!(path = %target.display(), error = %e, "parent dir fsync failed after resources persist");
                }
            }
        }
    }
    Ok(())
}

/// Test-only override for [`dashboard_root`], so the real router can be
/// driven against a fixture root. The process environment cannot be used:
/// the crate is `#![forbid(unsafe_code)]`, and `std::env::set_var` is unsafe
/// in this edition. Held for the duration of one test, so the tests that set
/// it must not run concurrently — they are one test for that reason.
#[cfg(test)]
static TEST_DASHBOARD_ROOT: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// Point [`dashboard_root`] at `root` for the duration of a test. Returns
/// the previous override so it can be restored.
#[cfg(test)]
fn with_test_dashboard_root(root: &Path) -> Option<PathBuf> {
    let mut guard = TEST_DASHBOARD_ROOT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.replace(root.to_path_buf())
}

fn dashboard_root() -> PathBuf {
    #[cfg(test)]
    {
        let guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(root) = guard.as_ref() {
            return root.clone();
        }
    }
    if let Ok(custom) = std::env::var("CAVORA_DASHBOARD_DIR") {
        PathBuf::from(custom)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let p1 = PathBuf::from(format!("{home}/.cavora/dashboard/out"));
        if p1.exists() {
            return p1;
        }
        let p2 = PathBuf::from("dashboard/out");
        if p2.exists() {
            return p2;
        }
        let p3 = PathBuf::from("out");
        if p3.exists() {
            return p3;
        }
        p1
    }
}

fn mime_for_path(path: &Path) -> &'static str {
    match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        // The RSC payload a client-side navigation fetches (`<page>.txt`,
        // `<page>/__next._tree.txt`, `__next._index.txt`, `__next._full.txt`)
        // is text, and Next only accepts it as a Flight response in
        // `output: "export"` mode when the content type starts with
        // `text/plain` — `next/dist/client/components/router-reducer/
        // fetch-server-response.js:136-139`. Served as
        // `application/octet-stream` it is rejected as "not a flight
        // response" and the router degrades to a full-page navigation that
        // dumps raw Flight text at the operator.
        "txt" => "text/plain; charset=utf-8",
        "webmanifest" => "application/manifest+json",
        "wasm" => "application/wasm",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        // The export ships `openapi.yaml` at its root. `application/yaml` is
        // the registered media type (RFC 9512), and it is what stops the file
        // falling through to the octet-stream default below.
        "yaml" => "application/yaml",
        _ => "application/octet-stream",
    }
}

/// `GET /dashboard` — the SPA entry document. Named for the mount; the
/// resolution is identical to every other dashboard URL, and the built-in
/// landing page is reachable from here alone because only the entry point
/// resolves to [`DashboardResolution::NoBuildAtEntry`]. `/` is the same
/// handler: which of the two a URL is comes from the path, not the mount.
pub async fn serve_dashboard_index(uri: Uri) -> Response {
    dashboard_response(&uri)
}

/// Every other dashboard URL: route documents, RSC payloads, per-segment
/// files, the export's origin-root app routes (`/login`, `/auth/callback`, …)
/// and their payloads, the origin-root assets an exported document references
/// without a prefix (`basePath` and `assetPrefix` are both empty in the
/// export, so every `<script src>` is `/_next/static/...`), and the origin-root
/// families a static export can never carry (`/docs/*`, a single-use
/// `/connect/codex/:token`).
///
/// Mounted on `/dashboard/*path`, on `/_next/*path`, on `/`, on each entry of
/// [`ORIGIN_ROOT_ROUTES`], and on the handful of named root-level files a
/// document links to. All of them resolve identically, so they are all one
/// handler: a mount that had its own copy of this logic is exactly how the
/// layout rules would drift.
pub async fn serve_dashboard_path(uri: Uri) -> Response {
    dashboard_response(&uri)
}

/// The script the exported dashboard registers, at the origin root.
const SERVICE_WORKER_FILE: &str = "sw.js";

/// The one dashboard-origin URL this host answers WITHOUT consulting the
/// export, and the reasoning that makes it the only one.
///
/// The export ships a real service worker at its root and registers it from
/// `_next/static/chunks/*` as `serviceWorker.register("/sw.js?v=<build stamp>")`
/// — measured on artifact `omniroute-dashboard-out` #10932864997, in
/// `02mvteclift3s.js`. This host did not mount it, so the browser's script
/// fetch answered 404, the registration never existed, and every load of
/// `/dashboard` logged `A bad HTTP response code (404) was received when
/// fetching the script`. A 404 on a file the artifact really contains is a
/// broken artifact, and that much is not in doubt.
///
/// Whether the admin origin should then RUN that worker is a decision, and the
/// answer is no. Read out of the shipped `out/sw.js`:
///
/// * `CACHE_NAME = "omniroute-pwa-v3"` (line 1) is a hand-maintained literal,
///   NOT stamped at build time — the build stamp is the `?v=` on the
///   registration, and it never reaches the cache name. The comment at lines
///   33-35 asserts that deleting every other cache name "already drops all
///   stale generations", which is only true for a generation that was renamed.
///   The cache-first branch at lines 80-83 therefore serves last release's
///   `public/` CSS, fonts and vendor logos to a returning operator under a name
///   that is unchanged. The artifact's stated safety invariant does not hold
///   of the artifact.
/// * `APP_SHELL` (lines 2-7) precaches `/` — on this origin, this admin
///   export's own document — into Cache Storage at install (line 21).
/// * The Cache API is keyed by URL and has no notion of credentials, so
///   anything a worker stores is replayable by any client at the origin, with
///   or without a session. This origin's authenticated surface is
///   `/admin/v1/*`, authorised by `cavora_admin_session`
///   (`HttpOnly; SameSite=Strict; Path=/admin/v1`).
/// * That document is never actually served from the cache today, and the
///   reason is incidental rather than stated: navigations return early
///   (line 57) and a document's `destination` is not a static type (line 63).
///   `EXCLUDED_PATH_PREFIXES` (line 8) does not name `/admin/v1` at all — the
///   authenticated API sits inside the worker's scope and is spared only
///   because an XHR has `destination === ""`.
/// * The `notificationclick` handler (lines 124-143) focuses an existing
///   same-origin window. On a public origin that is a convenience; on the
///   ADMIN origin it is a lock-screen tap re-entering a live authenticated
///   session.
///
/// So every one of those protections lives in a file this repository does not
/// own, is regenerated by a dashboard release with no signal here, and rests on
/// an invariant the file itself misstates. A policy this repo cannot express as
/// code and cannot test is not a policy. The offline shell is worth nothing on
/// a control plane an offline operator cannot act on.
///
/// What this serves instead is a script that registers — so the fetch is a 200
/// and the console is clean — and has no `fetch` listener at all, which is
/// stronger than any strategy inside one: no request on this origin can be
/// answered from a cache, so documents, `/_next/*` chunks and every
/// `/admin/v1/*` read and write are answered by the network exactly as they
/// were before any worker existed. The one thing it does run is the cache
/// sweep, so storage an earlier build left on this origin is removed rather
/// than left on an operator's disk.
///
/// The registration is left standing rather than torn down on purpose: it is
/// the visible, auditable form of this decision (fetch `/sw.js` on an admin
/// origin and read the policy), and the alternative — a script that
/// unregisters — leaves an operator with the same 404 console error and no
/// trace of the choice.
///
/// Do NOT "fix" this by mounting [`serve_dashboard_path`] on `/sw.js`, and do
/// not add a cache-first worker here without reading this first. The hazard is
/// an operator seeing a revoked key, a cooldowned provider or a stale topology
/// as healthy, on a page that is the control plane.
pub async fn serve_service_worker_standing_down() -> Response {
    let mut resp = ADMIN_ORIGIN_SERVICE_WORKER.into_response();
    let headers = resp.headers_mut();
    // The browser REJECTS a service-worker script served with a non-JS media
    // type, and that rejection is its own console error — so the type comes
    // from the same table as every other artifact rather than being spelled
    // again here.
    if let Ok(value) = HeaderValue::from_str(mime_for_path(Path::new(SERVICE_WORKER_FILE))) {
        headers.insert(CONTENT_TYPE, value);
    }
    // `no-store`, not the `no-cache` the export's own files get: this body is a
    // policy statement, not a versioned asset, and a stored copy is
    // indistinguishable from a stale one. A browser is permitted to reuse a
    // cached service-worker script, so forbidding the cache is the only way the
    // policy that ran is the policy in the body. The `?v=` stamp cannot weaken
    // this — the router matches on the path, so the query never reaches a
    // filename (pinned by `a_cache_busting_query_answers_the_same_script`).
    if let Ok(value) = HeaderValue::from_str("no-store") {
        headers.insert(CACHE_CONTROL, value);
    }
    resp
}

/// The body [`serve_service_worker_standing_down`] serves. Kept as a constant
/// rather than read from the export, and kept byte-stable, so the browser's
/// service-worker update check sees an unchanged script and does not churn a
/// new registration on every load.
const ADMIN_ORIGIN_SERVICE_WORKER: &str = r#"// AISIX admin origin — this host runs no service worker.
//
// The dashboard export ships a PWA worker at its root and registers this URL
// (`/sw.js?v=<build stamp>`). This script registers, and then deliberately does
// nothing: it declares NO `fetch` listener, so the browser answers every
// request on this origin — documents, `/_next/*` chunks, and every
// `/admin/v1/*` read and write — from the network, exactly as it did before any
// worker existed.
//
// Why, in the one place a reader is guaranteed to land: a service worker owns
// its whole origin, this origin's authenticated surface is `/admin/v1/*`, and
// the Cache API is keyed by URL with no notion of credentials — so anything a
// worker stores is replayable by any client at this origin, with or without a
// session. The export's worker precaches `/` (this origin's own document) and
// keeps that policy in a file this host does not own, behind an invariant the
// file itself misstates. The reason that document is never served stale today
// is incidental, not stated. An offline shell is worth nothing on a control
// plane an offline operator cannot act on.
//
// The only thing that runs is the sweep: storage an earlier build left on this
// origin is removed rather than left on an operator's disk.
const sweep = async () => {
  try {
    const keys = await caches.keys();
    await Promise.allSettled(keys.map((key) => caches.delete(key)));
  } catch (_) {
    // A sweep that cannot run must not fail the install: a rejected install is
    // a console error and no registration, which is the exact failure this
    // endpoint exists to remove.
  }
};

self.addEventListener("install", (event) => event.waitUntil(sweep()));
self.addEventListener("activate", (event) => event.waitUntil(sweep()));
"#;

/// The chokepoint's response side: one dashboard request URI, and the answer
/// for it.
fn dashboard_response(uri: &Uri) -> Response {
    let root = dashboard_root();
    match resolve_dashboard(&root, uri.path()) {
        DashboardResolution::File { path, immutable } => match std::fs::read(&path) {
            Ok(bytes) => file_response(bytes, &path, immutable),
            Err(error) => broken_build_response(&path, error),
        },
        // A sub-resource of a build that is not deployed is absent, not the
        // entry point: answering with the landing page here is exactly the
        // "silently dump the operator on /dashboard" failure.
        DashboardResolution::NoBuild => {
            tracing::debug!(path = uri.path(), "no dashboard build deployed");
            route_absent_response(uri.path())
        }
        DashboardResolution::NoBuildAtEntry => landing_page_response(),
        DashboardResolution::RouteAbsent => route_absent_response(uri.path()),
        DashboardResolution::AssetMissing => asset_missing_response(uri.path()),
        DashboardResolution::Refused => refused_response(uri.path()),
    }
}

fn file_response(bytes: Vec<u8>, path: &Path, immutable: bool) -> Response {
    let mut resp = bytes.into_response();
    let headers = resp.headers_mut();
    if let Ok(value) = HeaderValue::from_str(mime_for_path(path)) {
        headers.insert(CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(if immutable {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }) {
        headers.insert(CACHE_CONTROL, value);
    }
    resp
}

fn route_absent_response(url_path: &str) -> Response {
    // Honest 404: the export carries no such route. Route families that are
    // legitimately absent by construction — a DB row
    // (`/dashboard/combos/[id]`), an installed plugin
    // (`/dashboard/plugins/[name]/config`), a single-use token
    // (`/connect/codex/[token]`), a force-dynamic docs tree (`/docs/*`) — and
    // no static export can produce any of them. This is deliberately NOT the
    // entry document: a 200 carrying `dashboard.html` would drop the operator
    // on `/dashboard` and report a page that was never asked for as a success.
    tracing::debug!(url_path, "dashboard route is not in this build");
    plain_response(
        StatusCode::NOT_FOUND,
        "not found: this route is not part of the deployed dashboard build",
    )
}

fn asset_missing_response(url_path: &str) -> Response {
    // Every segment/payload/chunk file is mandatory per Next's export
    // protocol, and a 404 on one makes the client call
    // `rejectRouteCacheEntry` (`next/dist/client/components/segment-cache/
    // cache.js:1263-1268`) — the route becomes unreachable with no
    // operator-visible cause. So its absence is a broken deployment, not a
    // missing page: answer 5xx and say so in the log.
    tracing::error!(
        url_path,
        "dashboard build is incomplete: a required asset is missing"
    );
    plain_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "dashboard build is incomplete: a required static asset is missing",
    )
}

fn broken_build_response(path: &Path, error: std::io::Error) -> Response {
    tracing::error!(path = %path.display(), %error, "dashboard file resolved but could not be read");
    plain_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "dashboard build is incomplete: a required static asset could not be read",
    )
}

fn refused_response(url_path: &str) -> Response {
    // 400, not 404: the request is malformed/hostile, and a 404 would
    // report it as merely absent. `debug` rather than `warn` — this is an
    // unauthenticated surface, so a prober must not be able to fill the log.
    tracing::debug!(
        url_path,
        "refused a dashboard path that leaves the dashboard root"
    );
    plain_response(
        StatusCode::BAD_REQUEST,
        "bad request: the dashboard path is not addressable",
    )
}

fn plain_response(status: StatusCode, body: &'static str) -> Response {
    (status, [(CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

/// Clean status landing page if dashboard SPA build has not been placed yet.
/// English, matching the rest of the admin surface (this is an
/// operator fallback, not a dashboard locale).
fn landing_page_response() -> Response {
    Html(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Cavora Gateway Dashboard</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0a0a0c; color: #ededed; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .card { background: #141419; border: 1px solid #282832; border-radius: 12px; padding: 32px; max-width: 500px; text-align: center; }
    h1 { font-size: 24px; margin-bottom: 12px; color: #fff; }
    p { color: #9e9e9e; line-height: 1.5; font-size: 14px; }
    .btn { display: inline-block; background: #3b82f6; color: #fff; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 500; margin-top: 20px; }
    .btn:hover { background: #2563eb; }
    .badge { display: inline-block; background: #1e3a8a; color: #93c5fd; padding: 4px 10px; border-radius: 20px; font-size: 12px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">Cavora Unified Native Gateway</div>
    <h1>Gateway dashboard</h1>
    <p>The gateway core is running and serving requests. The static SPA dashboard is expected in <code>~/.cavora/dashboard/out</code>.</p>
    <a href="/admin/openapi-scalar" class="btn">Open Scalar UI (OpenAPI)</a>
  </div>
</body>
</html>"#)
        .into_response()
}

/// The SPA entry route inside the export. The `dashboard` segment is the
/// *app route* (`src/app/(dashboard)/dashboard/…`), not a `basePath`:
/// `OMNIROUTE_BASE_PATH` is unset, so the export emits it as the first
/// directory of every route document.
const DASHBOARD_ENTRY: &str = "dashboard";

/// The export's ORIGIN-ROOT app routes — the ones that are not under
/// `dashboard/`, and that therefore 404 for an operator who opens the
/// gateway's own address. Measured from export artifact
/// `omniroute-dashboard-out` #10932864997: the 22 documents the export lays
/// down as `<route>.html` beside `index.html`, plus `auth/callback`, the one
/// nested document at the origin root.
///
/// Mounted four ways each, because that is how many ways a client asks for
/// one: the document (`/login`), its RSC payload on a client-side navigation
/// (`/login.txt`), the same route with a trailing slash (`/login/`), and the
/// per-segment files of a cold segment cache (`/login/__next._tree.txt`).
/// Every mount is the same chokepoint — see [`resolve_dashboard`] — so this
/// table is a routing statement, not a second implementation.
///
/// Nothing here may start with a segment the admin surface owns (`admin`,
/// `livez`, `readyz`, `playground`, `_next`, `dashboard`): the admin listener
/// is one flat router, so a mount here and a route there would be the same
/// path, and `tests::origin_root_routes_cannot_take_an_admin_path` is what
/// keeps the two lists from overlapping.
pub(crate) const ORIGIN_ROOT_ROUTES: &[&str] = &[
    "/400",
    "/401",
    "/403",
    "/404",
    "/408",
    "/429",
    "/500",
    "/502",
    "/503",
    "/_not-found",
    "/auth/callback",
    "/callback",
    "/forbidden",
    "/forgot-password",
    "/home",
    "/landing",
    "/login",
    "/maintenance",
    "/miniapp",
    "/offline",
    "/privacy",
    "/status",
    "/terms",
];

/// The content-hashed asset tree inside the export. Two decisions key on it —
/// the immutable caching contract and [`names_build_artifact`] — so it is one
/// constant rather than two spellings that can drift.
const NEXT_STATIC_DIR: &str = "_next/static";

/// The export's vendor-logo tree, at its root, because `assetPrefix` is empty
/// in the export and a document draws a vendor as `<img src="/providers/<id>.svg">`.
///
/// Mounted as a TREE and not as a list of names, and that is the whole point:
/// the tree's contents are a property of the vendor catalog, not of the build,
/// so a name list is a list that rots silently against every catalog change —
/// the mounted-by-name form left 136 of the 141 shipped logos 404ing on
/// `/dashboard/providers/openai`, which is a grid of empty logo frames and
/// nothing on the page that says why. Measured from the deployed export
/// artifact: 141 files, every one of them `.svg`, no subdirectory, no
/// symlink.
///
/// Because the mount answers for whatever is in the directory, it is bounded
/// to what a logo tree is for — see [`is_provider_logo`].
const PROVIDERS_DIR: &str = "providers";

/// Whether a file inside [`PROVIDERS_DIR`] is one this mount may serve: what
/// the mime table classifies as an image.
///
/// The alternative — answering for every file in the tree — would put
/// whatever a future export drops into `providers/` on the admin origin,
/// which is the origin `/admin/v1/*` answers on. A `.js` or an `.html` there
/// would be served as a script or a document, and the refusal is deliberately
/// decided on the TYPE the response would carry rather than on the name of a
/// second extension list: an extension is servable here exactly when the one
/// mime table already in this file gives it an `image/*` type. So admitting a
/// new image format is one line in [`mime_for_path`] — the same line the
/// artifact census already requires — and there is no second list to fall
/// out of step. The default arm is `application/octet-stream`, so an
/// extension the table does not know is not an image either.
///
/// Cost against the measured tree: none (141/141 are `.svg`). What it costs a
/// future export that puts a non-image in a logo directory is a 404 saying
/// the path is not part of the build — which is the honest answer, and a
/// better one than serving it.
fn is_provider_logo(path: &Path) -> bool {
    mime_for_path(path).starts_with("image/")
}

/// The export root's own document: a null-rendering `EntryRedirector` whose
/// whole job is to `router.replace('/dashboard')`. Addressable by exactly one
/// URL shape — a request that reduces to an empty remainder — so that no
/// route document is ever answered with it (see
/// `tests::the_root_shell_is_never_what_a_route_request_answers_with`).
const ROOT_SHELL: &str = "index.html";

/// The file extensions the export's own protocol names, and the only ones
/// whose absence indicts the build. Measured from artifact #10932864997:
/// `.txt .html .js .css .svg .png .json .webmanifest .ico .woff2 .yaml`
/// actually ship. The remainder are what the mime table already answers for
/// and what an export with images, source maps or a WASM bridge can add.
const BUILD_ARTIFACT_EXTENSIONS: &[&str] = &[
    "css",
    "html",
    "ico",
    "jpeg",
    "jpg",
    "js",
    "json",
    "map",
    "mjs",
    "png",
    "svg",
    "txt",
    "ttf",
    "wasm",
    "webmanifest",
    "webp",
    "woff",
    "woff2",
    "xml",
    "yaml",
];

/// What a dashboard request resolved to.
#[derive(Debug, PartialEq, Eq)]
enum DashboardResolution {
    /// A file inside the dashboard root, safe to serve.
    File { path: PathBuf, immutable: bool },
    /// The request is a route document the deployed build does not carry.
    RouteAbsent,
    /// The request is a build artifact the deployed build does not carry,
    /// which means the build itself is incomplete.
    AssetMissing,
    /// The request tries to leave the dashboard root.
    Refused,
    /// No dashboard build is deployed, and this is not the SPA entry point.
    NoBuild,
    /// No dashboard build is deployed, and this IS the SPA entry point — the
    /// one URL the built-in landing page is an honest answer for. A live
    /// deployment depends on it; no other URL may claim it, or a deep link
    /// would silently dump the operator on `/dashboard`.
    NoBuildAtEntry,
}

/// Resolve one dashboard request. The single place the export's layout is
/// translated into filesystem lookups, for every mount and every kind of
/// request (document, RSC payload, segment file, chunk).
///
/// `url_path` is the whole request path (`/dashboard/providers/openai`,
/// `/_next/static/chunks/x.js`, `/favicon.ico`); the mount prefixes are
/// stripped here, not by the handlers, so no handler can disagree with
/// another about what a URL means.
///
/// A static export lays its files out like this, and each shape below is one
/// client request form:
///
/// | request | resolves to | who asks for it |
/// |---|---|---|
/// | `/dashboard` | `dashboard.html` | `GET /dashboard` (the SPA entry) |
/// | `/dashboard/providers/openai` | `dashboard/providers/openai.html` | the document, plus a `HEAD` probe first (`cache.js:1241`) |
/// | `/dashboard/providers/openai.txt` | `dashboard/providers/openai.txt` | the RSC payload of a client-side navigation (`fetch-server-response.js:104-113`) |
/// | `/dashboard/providers/openai/__next._tree.txt` | same path, exact | the route tree on a cold segment cache (`cache.js:1254`) |
/// | `/dashboard/providers/openai/__next._index.txt`, `__next._full.txt` | same path, exact | per-segment prefetches (`cache.js:1517`) |
/// | `/_next/static/chunks/x.js` | `_next/static/chunks/x.js` | the form the document actually requests |
/// | `/dashboard/_next/static/chunks/x.js` | `_next/static/chunks/x.js` | the re-rooted form under the mount |
/// | `/favicon.ico`, `/manifest.webmanifest` | the same name at the export root | `public/` assets, referenced without a prefix |
/// | `/` | `index.html` | the export's `EntryRedirector` shell, which `router.replace`s to `/dashboard` |
/// | `/index.txt`, `/__next._tree.txt`, `/__next.__PAGE__.txt` | the same names at the export root | the RSC payload, the route tree and the page segment of the root route itself |
/// | `/dashboard.txt` | `dashboard.txt` | the payload of the `/dashboard` route, which the export puts at the ROOT |
/// | `/login`, `/auth/callback` | `login.html`, `auth/callback.html` | an origin-root app route document |
/// | `/login.txt` | `login.txt` | its RSC payload on a client-side navigation |
/// | `/login/__next._tree.txt` | same path, exact | its route tree on a cold segment cache |
///
/// The candidates are tried in that order and the first existing file wins;
/// nothing else is consulted, so no request shape can reach a file that is
/// not one of these.
fn resolve_dashboard(root: &Path, url_path: &str) -> DashboardResolution {
    let Some(rel) = dashboard_relative_path(url_path) else {
        return DashboardResolution::Refused;
    };
    let rel = split_dashboard_entry(rel);
    // `canonicalize` once per request, on the root: it is what makes a
    // symlink pointing outside the root detectable at all, and comparing
    // canonical paths is the only sound way to do that.
    let Ok(real_root) = root.canonicalize() else {
        return no_build(rel.at_entry);
    };
    // A deployed build is identified structurally, by the app-route tree it
    // always emits, never by whether THIS request happened to hit a file —
    // otherwise one missing chunk would read as "no build deployed" and
    // downgrade to a 404 that says nothing is wrong.
    if !real_root.join(DASHBOARD_ENTRY).is_dir() {
        return no_build(rel.at_entry);
    }

    // A candidate the logo bound rejected is remembered, so the answer for the
    // request does not fall out of which mount spelled it: see the bound below.
    let mut logo_bound_refused = false;
    for candidate in dashboard_candidates(&real_root, &rel) {
        if !candidate.is_file() {
            continue;
        }
        // A file that reached the filesystem through a symlink can name
        // anything. Re-check where it actually lives, not where it was
        // spelled: `starts_with` compares whole components, so `<root>-evil`
        // cannot pass for `<root>`.
        let Ok(real) = candidate.canonicalize() else {
            return DashboardResolution::Refused;
        };
        if !real.starts_with(&real_root) {
            return DashboardResolution::Refused;
        }
        // The logo tree is mounted as a tree, so it is bounded to what a logo
        // tree holds. Decided on the RESOLVED path, not on how the URL spelled
        // the request, so neither the re-rooted `/dashboard/providers/x.svg`
        // form nor a symlink into the tree can present a file the tree is not
        // for — and so the app-route documents under `dashboard/providers/`
        // (`openai.html`, `openai.txt`, the per-segment files), which are a
        // different tree at a different place, are untouched by it.
        if real.starts_with(real_root.join(PROVIDERS_DIR)) && !is_provider_logo(&real) {
            logo_bound_refused = true;
            continue;
        }
        // Decided here, next to the resolution, so the caching contract cannot
        // drift from the layout it describes: `_next/static/**` is
        // build-id-scoped and content-hashed, so it is immutable; every other
        // dashboard file keeps a stable name whose bytes change on the next
        // export and must be revalidated. A logo is the second kind — a
        // stable name, redeployed bytes.
        return DashboardResolution::File {
            immutable: real.starts_with(real_root.join(NEXT_STATIC_DIR)),
            path: real,
        };
    }

    // The bound refused a file that IS in the build, so the request is not
    // asking for a route this build does not have and its absence indicts
    // nothing either: it is asking for something the logo mount does not
    // serve. Answering from the artifact classification below would make a
    // perfectly complete build answer 500 "the build is incomplete" — and log
    // it — for a URL no document emits, on a request anyone can make. `debug`
    // is the same reasoning as `refused_response`: this is an unauthenticated
    // surface and a prober must not be able to fill the log.
    if logo_bound_refused {
        tracing::debug!(
            url_path,
            "a file in the provider-logo tree is not a logo and was not served"
        );
        return DashboardResolution::RouteAbsent;
    }

    // A build IS deployed; it just does not carry this path. Which of the
    // two honest answers applies is decided by [`names_build_artifact`],
    // beside the layout that decides it: an artifact the export's protocol
    // names is a broken deployment (5xx, logged), and a route the build does
    // not carry is a plain absence (404, explained).
    if rel.named_artifact {
        DashboardResolution::AssetMissing
    } else {
        DashboardResolution::RouteAbsent
    }
}

/// Whether a request names a build artifact — a file the export's own
/// protocol asks for by name — rather than a route. Two conditions, and both
/// are load-bearing:
///
/// * the last segment carries a **known artifact extension**
///   ([`BUILD_ARTIFACT_EXTENSIONS`]). "Carries a dot" is not the test: a
///   provider id, a plugin name, or a token routinely carries one, and
///   calling `/dashboard/providers/acme.corp` an artifact made an absent
///   document answer 500 — "the build is incomplete", a different and false
///   claim about a page that simply is not in this export.
/// * the request addresses a tree that can hold one: the app-route tree
///   (`/dashboard/**`, which carries the `<route>.txt` payloads and the
///   per-segment files) or the content-hashed [`NEXT_STATIC_DIR`] tree. At
///   the export root a dotted last segment is a route name, because no Next
///   build protocol ever asks for `/dashboard.txt` or `/favicon.png` — their
///   absence says nothing about the build, so the honest answer is 404.
fn names_build_artifact(rest: &Path, in_app_route_tree: bool) -> bool {
    let Some(extension) = rest.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    BUILD_ARTIFACT_EXTENSIONS.contains(&extension)
        && (in_app_route_tree || rest.starts_with(NEXT_STATIC_DIR))
}

/// One dashboard request split into the export namespaces it can address.
struct DashboardPaths {
    /// The request path relative to the export root, after the `dashboard`
    /// mount prefix has been taken off (or unchanged, for a request that
    /// addressed the export root directly).
    rest: PathBuf,
    /// Whether the request can name a route document at all — i.e. whether
    /// it arrived under the `dashboard` mount, the only place the export
    /// puts them.
    wants_document: bool,
    /// Whether the request names a build artifact rather than a route, i.e.
    /// which of the two absent-answers it draws. Decided in one place —
    /// [`names_build_artifact`] — because a request shape that counts as an
    /// artifact here must not read as a route there.
    named_artifact: bool,
    /// Whether the request addresses the SPA entry point itself, with or
    /// without a trailing slash.
    at_entry: bool,
    /// Whether the request addresses the export ROOT rather than a path in
    /// it: it reduced to an empty remainder, the one shape that can name
    /// [`ROOT_SHELL`].
    at_export_root: bool,
    /// The same remainder relative to the export root, for a request that
    /// DID arrive under the `dashboard` mount, so an origin-root asset is
    /// addressable from either mount.
    origin_asset: Option<PathBuf>,
}

/// Take the `dashboard` mount prefix off, if it is there. A request that
/// does not carry it — `/_next/static/…`, `/favicon.ico`, `/login` — is
/// already relative to the export root and resolves against it.
fn split_dashboard_entry(rel: PathBuf) -> DashboardPaths {
    let mut segments = rel.components();
    match segments.next() {
        Some(std::path::Component::Normal(first)) if first == DASHBOARD_ENTRY => {
            let rest = segments.as_path().to_path_buf();
            DashboardPaths {
                at_entry: rest.as_os_str().is_empty(),
                at_export_root: false,
                named_artifact: names_build_artifact(&rest, true),
                origin_asset: Some(rest.clone()),
                rest,
                wants_document: true,
            }
        }
        _ => DashboardPaths {
            at_entry: false,
            at_export_root: rel.as_os_str().is_empty(),
            named_artifact: names_build_artifact(&rel, false),
            rest: rel,
            wants_document: false,
            origin_asset: None,
        },
    }
}

/// The "no build deployed" answer, which differs for the one URL the
/// built-in landing page may stand in for.
fn no_build(at_entry: bool) -> DashboardResolution {
    if at_entry {
        DashboardResolution::NoBuildAtEntry
    } else {
        DashboardResolution::NoBuild
    }
}

/// Every file a dashboard request is allowed to resolve to, in priority
/// order. Each is `real_root`-relative by construction, so no request shape
/// can reach a file outside the five forms below.
fn dashboard_candidates(real_root: &Path, rel: &DashboardPaths) -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(4);
    if rel.at_export_root {
        // The export root is one file, and one URL shape reaches it. Handled
        // apart from the forms below so that no route request can be answered
        // with the null-rendering shell.
        candidates.push(real_root.join(ROOT_SHELL));
    } else {
        // The two bases the export lays its files out in: the app-route tree
        // under the `dashboard` mount, and the export root for everything
        // else. An origin-root route document is as real a document as one
        // under `dashboard/` — it is the export that puts it at the root.
        let base = if rel.wants_document {
            real_root.join(DASHBOARD_ENTRY)
        } else {
            real_root.to_path_buf()
        };
        // Exact name first: the RSC payload of a client-side navigation
        // (`<page>.txt`) and the per-segment files (`__next._tree.txt`,
        // `__next._index.txt`, `__next._full.txt`).
        // MUST precede the document form — an extension-appending candidate
        // tried first would answer a payload request with the HTML document.
        candidates.push(base.join(&rel.rest));
        if !rel.named_artifact {
            // Document: `trailingSlash` is unset, so the export emits a flat
            // `<route>.html`, not a directory index. Restricted to a request
            // that is not naming an artifact, which is exactly what makes it a
            // route request.
            candidates.push(appended_extension(&base.join(&rel.rest), "html"));
            // Directory index, for a trailing-slash request and for a build
            // that does emit `index.html`.
            candidates.push(base.join(&rel.rest).join("index.html"));
        }
    }
    // Origin-root asset, reachable from the `dashboard` mount too.
    if let Some(asset) = &rel.origin_asset {
        candidates.push(real_root.join(asset));
    }
    candidates
}

/// `<name>.html`, APPENDING the extension rather than replacing it.
/// `Path::with_extension` turns a dotted route name (`providers/acme.corp`)
/// into `acme.html` — a *different* route — so the one request form that can
/// reach a document for a dotted route would 404 a document the build ships.
fn appended_extension(path: &Path, extension: &str) -> PathBuf {
    let Some(name) = path.file_name() else {
        return path.to_path_buf();
    };
    let mut appended = name.to_os_string();
    appended.push(".");
    appended.push(extension);
    path.with_file_name(appended)
}

/// The export-root-relative path a dashboard request resolves to, or `None`
/// when the request tries to leave the export root.
///
/// Rejecting a `..` segment outright is the point: the previous
/// `trim_start_matches('/').replace("..", "")` did not. `....//`
/// strips to `//`, and `root.join("//etc/passwd")` is an ABSOLUTE
/// path, so the read landed outside the root on any unix host.
///
/// `\` is rejected outright even though it is not a separator here: it
/// is on Windows, and the `/` split below would not see it. NUL is
/// rejected because it truncates the argument at the syscall, leaving
/// a different path than the one validated.
///
/// The path is percent-decoded here, exactly once, because a router that
/// hands over a raw path must still refuse `%2e%2e%2f` as a traversal
/// rather than report it as an absent file. It is decoded ONCE and only
/// once: a double-encoded `%252e%252e%252f` therefore stays the ordinary
/// (absent) directory name `%2e%2e%2f` and can never become a traversal.
///
/// An empty remainder is NOT a rejection: it is the export root, which names
/// exactly one file ([`ROOT_SHELL`]) and no path at all — see
/// [`DashboardPaths::at_export_root`]. A request that reduced to nothing can
/// therefore read `/` , `//` and `/.` and nothing more, and none of those
/// spellings can carry a traversal.
fn dashboard_relative_path(path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(path.trim_start_matches('/'));
    if decoded.contains('\\') || decoded.contains('\0') {
        return None;
    }
    let mut rel = PathBuf::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => continue,
            ".." => return None,
            other => rel.push(other),
        }
    }
    Some(rel)
}

/// Percent-decode a URL path. `+` is left alone: this is a path, not a form
/// body. An invalid or truncated escape is passed through unchanged, which
/// can only make the result an odd (absent) file name, never a traversal.
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use std::fs;
    use tempfile::TempDir;
    use tower::ServiceExt;

    /// A dashboard root shaped like the real export (artifact
    /// `omniroute-dashboard-out` #10932864997): a flat `<route>.html` per
    /// route, `<route>.txt` beside it, the segment files in a directory of the
    /// same name, the origin-root app routes beside them, and the `_next/`
    /// and `public/` assets the documents reference without a prefix.
    fn export_root() -> TempDir {
        let dir = TempDir::new().unwrap();
        populate_export(dir.path());
        dir
    }

    /// The same build with a canary file BESIDE the root rather than inside
    /// it: a traversal that actually left the root would answer 200 with
    /// those bytes, so the assertion has to be able to see them.
    fn export_root_with_a_canary_beside_it() -> (TempDir, PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("out");
        populate_export(&root);
        let canary = dir.path().join("canary.txt");
        fs::write(&canary, b"aisix-traversal-canary").unwrap();
        (dir, canary)
    }

    fn populate_export(root: &Path) {
        fs::create_dir_all(root).unwrap();
        // The `/` shell is a null-rendering redirector: it must never be
        // what a route request answers with.
        fs::write(
            root.join("index.html"),
            b"ROOT SHELL: router.replace('/dashboard')",
        )
        .unwrap();
        fs::write(root.join("dashboard.html"), b"<html>dashboard entry</html>").unwrap();
        // The RSC payload, route tree and page segment of the root route, and
        // the payload of the `/dashboard` route: the export writes all four
        // at the ROOT, not under `dashboard/`.
        fs::write(root.join("index.txt"), b"ROOT RSC PAYLOAD").unwrap();
        fs::write(root.join("__next._tree.txt"), b"ROOT TREE").unwrap();
        fs::write(root.join("__next.__PAGE__.txt"), b"ROOT PAGE SEGMENT").unwrap();
        fs::write(root.join("dashboard.txt"), b"DASHBOARD RSC PAYLOAD").unwrap();
        let route = root.join("dashboard/providers/openai");
        fs::create_dir_all(&route).unwrap();
        fs::write(
            root.join("dashboard/providers.html"),
            b"<html>providers</html>",
        )
        .unwrap();
        fs::write(
            root.join("dashboard/providers/openai.html"),
            b"<html>openai</html>",
        )
        .unwrap();
        fs::write(
            root.join("dashboard/providers/openai.txt"),
            "RSC FLIGHT PAYLOAD",
        )
        .unwrap();
        fs::write(route.join("__next._tree.txt"), "TREE WITH id PARAM").unwrap();
        fs::write(route.join("__next._index.txt"), "SEGMENT INDEX").unwrap();
        fs::write(route.join("__next._full.txt"), "SEGMENT FULL").unwrap();
        fs::create_dir_all(root.join("_next/static/chunks")).unwrap();
        fs::write(root.join("_next/static/chunks/app.js"), b"console.log(1)").unwrap();
        fs::create_dir_all(root.join(".well-known")).unwrap();
        fs::write(root.join(".well-known/agent.json"), b"{}").unwrap();
        fs::write(root.join("manifest.webmanifest"), b"{}").unwrap();
        fs::write(root.join("favicon.ico"), b"ICO").unwrap();
        // The origin-root app routes: a document beside its payload and its
        // per-segment directory, one nested document, and a provider logo a
        // document links to.
        fs::write(root.join("login.html"), b"<html>login</html>").unwrap();
        fs::write(root.join("login.txt"), b"LOGIN RSC PAYLOAD").unwrap();
        fs::create_dir_all(root.join("login")).unwrap();
        fs::write(root.join("login/__next._tree.txt"), b"LOGIN TREE").unwrap();
        fs::write(
            root.join("login/__next.login.__PAGE__.txt"),
            b"LOGIN PAGE SEGMENT",
        )
        .unwrap();
        fs::create_dir_all(root.join("auth")).unwrap();
        fs::write(
            root.join("auth/callback.html"),
            b"<html>auth callback</html>",
        )
        .unwrap();
        fs::create_dir_all(root.join("providers")).unwrap();
        // The provider logos, a sample of the tree the mount now answers for
        // as a whole. The export ships 141 of them; the five below are the ones
        // an origin-root document links to, and the sixth is one NO document
        // links to — which is the case the named mount left 404ing.
        for (name, body) in [
            ("claude.svg", &b"<svg id='claude'/>"[..]),
            ("cline.svg", &b"<svg id='cline'/>"[..]),
            ("codex.svg", &b"<svg id='codex'/>"[..]),
            ("cursor.svg", &b"<svg id='cursor'/>"[..]),
            (
                "kimi-logomark-light.svg",
                &b"<svg id='kimi-logomark-light'/>"[..],
            ),
            ("baidu.svg", &b"<svg id='baidu'/>"[..]),
        ] {
            fs::write(root.join("providers").join(name), body).unwrap();
        }
        // The tree a wildcard newly invites: files that are in the build and
        // are not logos. A future export could drop any of these into
        // `providers/`, and none of them may be served — see `is_provider_logo`.
        for (name, body) in [
            (
                "catalog.js",
                &b"console.log('aisix-provider-logo-escape')"[..],
            ),
            (
                "catalog.html",
                &b"<html>aisix-provider-logo-escape</html>"[..],
            ),
            ("notes.txt", &b"aisix-provider-logo-escape"[..]),
            ("brand.wasm", b"\0asm\x01\0\0\0aisix-provider-logo-escape"),
            ("blob.xyzzy", b"aisix-provider-logo-escape"),
        ] {
            fs::write(root.join("providers").join(name), body).unwrap();
        }
        // A route name that carries a dot: a provider id, not a file type.
        fs::write(
            root.join("dashboard/providers/acme.corp.html"),
            b"<html>acme corp</html>",
        )
        .unwrap();
    }

    /// A root that exists but holds no dashboard at all.
    fn empty_root() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("nothing-here")).unwrap();
        dir
    }

    fn resolved(root: &TempDir, url_path: &str) -> DashboardResolution {
        resolve_dashboard(root.path(), url_path)
    }

    fn resolved_file(root: &TempDir, url_path: &str) -> (PathBuf, bool) {
        match resolved(root, url_path) {
            DashboardResolution::File { path, immutable } => (path, immutable),
            other => panic!("{url_path} should have resolved to a file, got {other:?}"),
        }
    }

    #[test]
    fn every_client_request_form_of_a_route_resolves() {
        let root = export_root();
        // The document, for `GET` and for the `HEAD` probe the client router
        // issues first (`cache.js:1241`).
        assert_eq!(
            std::fs::read(resolved_file(&root, "dashboard/providers/openai").0).unwrap(),
            b"<html>openai</html>"
        );
        // The RSC payload of a client-side navigation
        // (`fetch-server-response.js:104-113`) — and NOT the document, which
        // an extension-appending candidate tried first would have answered.
        assert_eq!(
            std::fs::read(resolved_file(&root, "dashboard/providers/openai.txt").0).unwrap(),
            b"RSC FLIGHT PAYLOAD"
        );
        for segment in ["__next._tree.txt", "__next._index.txt", "__next._full.txt"] {
            let (path, _) = resolved_file(&root, &format!("dashboard/providers/openai/{segment}"));
            assert!(path.ends_with(segment), "{segment} resolved to {path:?}");
        }
        // The entry, and a parent route.
        assert_eq!(
            std::fs::read(resolved_file(&root, "dashboard").0).unwrap(),
            b"<html>dashboard entry</html>"
        );
        assert_eq!(
            std::fs::read(resolved_file(&root, "dashboard/providers").0).unwrap(),
            b"<html>providers</html>"
        );
    }

    #[test]
    fn a_trailing_slash_request_resolves_to_the_same_route() {
        let root = export_root();
        let (with_slash, _) = resolved_file(&root, "dashboard/providers/openai/");
        let (without, _) = resolved_file(&root, "dashboard/providers/openai");
        assert_eq!(with_slash, without);
    }

    #[test]
    fn origin_root_assets_answer_from_both_mounts() {
        let root = export_root();
        // The form the documents actually request.
        let (chunk, immutable) = resolved_file(&root, "_next/static/chunks/app.js");
        assert!(chunk.ends_with("_next/static/chunks/app.js"));
        assert!(
            immutable,
            "_next/static is content-hashed and must be immutable"
        );
        // The re-rooted form under the mount, same bytes.
        let (rerooted, _) = resolved_file(&root, "dashboard/_next/static/chunks/app.js");
        assert_eq!(rerooted, chunk);
        // `public/` assets, referenced by the document without a prefix.
        for name in ["manifest.webmanifest", ".well-known/agent.json"] {
            let (path, _) = resolved_file(&root, name);
            assert!(path.ends_with(name), "{name} resolved to {path:?}");
            let (rerooted, _) = resolved_file(&root, &format!("dashboard/{name}"));
            assert_eq!(rerooted, path);
        }
    }

    #[test]
    fn only_next_static_is_cached_immutably() {
        let root = export_root();
        for (url_path, immutable) in [
            ("dashboard", false),
            ("dashboard/providers/openai", false),
            ("dashboard/providers/openai.txt", false),
            ("dashboard/providers/openai/__next._tree.txt", false),
            ("manifest.webmanifest", false),
            ("_next/static/chunks/app.js", true),
        ] {
            let (_, actual) = resolved_file(&root, url_path);
            assert_eq!(actual, immutable, "{url_path} caching");
        }
    }

    #[test]
    fn the_rsc_payload_is_served_as_text_plain() {
        // `fetch-server-response.js:136-139` only accepts a `<page>.txt` as a
        // Flight response in export mode when the content type starts with
        // `text/plain`; anything else and the router degrades to a full-page
        // navigation that dumps raw Flight text at the operator.
        assert_eq!(
            mime_for_path(Path::new("providers/openai.txt")),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            mime_for_path(Path::new("openai/__next._tree.txt")),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            mime_for_path(Path::new("chunks/app.js")),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(
            mime_for_path(Path::new("app.css")),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            mime_for_path(Path::new("manifest.webmanifest")),
            "application/manifest+json"
        );
    }

    #[test]
    fn every_known_artifact_extension_has_a_content_type_of_its_own() {
        // The catch-all over the classification rule: an extension the
        // artifact rule trusts must never reach the octet-stream default,
        // because a browser that is told "application/octet-stream"
        // DOWNLOADS a chunk or a stylesheet instead of running it.
        for extension in BUILD_ARTIFACT_EXTENSIONS {
            let mime = mime_for_path(Path::new(&format!("fixture.{extension}")));
            assert_ne!(
                mime, "application/octet-stream",
                ".{extension} has no content type of its own"
            );
            assert!(
                !mime.is_empty(),
                ".{extension} produced an empty content type"
            );
        }
        // And the default is pinned on an extension no build ships, so the
        // loop above cannot pass by making the table total.
        assert_eq!(
            mime_for_path(Path::new("fixture.xyzzy")),
            "application/octet-stream"
        );
    }

    #[test]
    fn the_export_root_answers_its_own_shell() {
        let root = export_root();
        // `/` is the export's `EntryRedirector`: a null-rendering document
        // whose whole job is `router.replace('/dashboard')`.
        let (shell, immutable) = resolved_file(&root, "/");
        assert!(shell.ends_with(ROOT_SHELL), "/ resolved to {shell:?}");
        assert_eq!(
            std::fs::read(&shell).unwrap(),
            b"ROOT SHELL: router.replace('/dashboard')"
        );
        assert!(
            !immutable,
            "the shell keeps a stable name and must be revalidated"
        );
        // Every spelling that reduces to the same empty remainder names that
        // one file — and nothing else, so none of them can carry a traversal.
        for spelling in ["//", "/./", "/."] {
            assert_eq!(resolved_file(&root, spelling).0, shell, "{spelling}");
        }
        assert_eq!(resolved(&root, "/../"), DashboardResolution::Refused);
        // The shell is also addressable by its own name, which is the same
        // document rather than a route answered with the wrong one.
        assert_eq!(resolved_file(&root, "index").0, shell);
        assert_eq!(resolved_file(&root, "index.html").0, shell);
    }

    #[test]
    fn the_root_shell_is_never_what_a_route_request_answers_with() {
        // `out/index.html` is a null-rendering redirector whose only job is to
        // `router.replace('/dashboard')`. Serving it for any route silently
        // dumps the operator on `/dashboard` and reports a page that was never
        // asked for as a success.
        let root = export_root();
        for url_path in [
            "dashboard",
            "dashboard/providers",
            "dashboard/providers/openai",
            "dashboard/_next/static/chunks/app.js",
            "login",
            "login/",
            "login.txt",
            "login/__next._tree.txt",
            "auth/callback",
            "favicon.ico",
            "manifest.webmanifest",
            "providers/claude.svg",
            "_next/static/chunks/app.js",
        ] {
            let (path, _) = resolved_file(&root, url_path);
            assert!(
                !path.ends_with(ROOT_SHELL),
                "{url_path} resolved to the root shell {path:?}",
            );
        }
    }

    #[test]
    fn an_origin_root_route_resolves_in_every_client_request_form() {
        let root = export_root();
        // The document, the RSC payload of a client-side navigation, the
        // trailing-slash spelling, and the route tree of a cold segment cache.
        assert_eq!(
            std::fs::read(resolved_file(&root, "login").0).unwrap(),
            b"<html>login</html>"
        );
        assert_eq!(
            std::fs::read(resolved_file(&root, "login.txt").0).unwrap(),
            b"LOGIN RSC PAYLOAD"
        );
        assert_eq!(
            resolved_file(&root, "login/").0,
            resolved_file(&root, "login").0
        );
        assert_eq!(
            std::fs::read(resolved_file(&root, "login/__next._tree.txt").0).unwrap(),
            b"LOGIN TREE"
        );
        // The one nested document at the origin root.
        assert_eq!(
            std::fs::read(resolved_file(&root, "auth/callback").0).unwrap(),
            b"<html>auth callback</html>"
        );
        // The root route's own payload and segment files, and the payload of
        // the `/dashboard` route: the export writes all of them at the ROOT,
        // which is why they are mounted there and not under `/dashboard`.
        for (url_path, body) in [
            ("index.txt", &b"ROOT RSC PAYLOAD"[..]),
            ("__next._tree.txt", b"ROOT TREE"),
            ("__next.__PAGE__.txt", b"ROOT PAGE SEGMENT"),
            ("dashboard.txt", b"DASHBOARD RSC PAYLOAD"),
        ] {
            assert_eq!(
                std::fs::read(resolved_file(&root, url_path).0).unwrap(),
                body,
                "{url_path}"
            );
        }
        // A `public/` asset an origin-root document links to.
        assert_eq!(
            std::fs::read(resolved_file(&root, "providers/claude.svg").0).unwrap(),
            b"<svg id='claude'/>"
        );
    }

    #[test]
    fn a_dotted_route_name_is_a_route_and_not_a_missing_artifact() {
        // The defect: "the last segment carries a dot" read `acme.corp` as a
        // file type, so a document that is simply not in this export answered
        // 500 — "the build is incomplete", a claim about the deployment
        // rather than about the page.
        let root = export_root();
        // Present: the document is `<id>.html` with the dot KEPT. A
        // `with_extension("html")` candidate would ask for `acme.html` — a
        // different route — and 404 a document the build ships.
        assert_eq!(
            std::fs::read(resolved_file(&root, "dashboard/providers/acme.corp").0).unwrap(),
            b"<html>acme corp</html>"
        );
        // Absent: a route, so the honest 404.
        assert_eq!(
            resolved(&root, "dashboard/providers/absent.corp"),
            DashboardResolution::RouteAbsent
        );
        // The same dotted id, asked for as a payload, is still an artifact:
        // the export's protocol names `<route>.txt`, and its absence indicts
        // the build.
        assert_eq!(
            resolved(&root, "dashboard/providers/acme.corp.txt"),
            DashboardResolution::AssetMissing
        );
        assert_eq!(
            resolved(&root, "dashboard/providers/acme.corp/__next._tree.txt"),
            DashboardResolution::AssetMissing
        );
        // And a genuinely missing chunk is still loud.
        assert_eq!(
            resolved(&root, "_next/static/chunks/gone.js"),
            DashboardResolution::AssetMissing
        );
    }

    #[test]
    fn a_dotted_path_at_the_export_root_is_a_route_too() {
        let root = export_root();
        // The export DOES ship `dashboard.txt` — the payload of the
        // `/dashboard` route, which it writes at the root — and a file that
        // exists is a file.
        assert_eq!(
            std::fs::read(resolved_file(&root, "dashboard.txt").0).unwrap(),
            b"DASHBOARD RSC PAYLOAD"
        );
        fs::remove_file(root.path().join("dashboard.txt")).unwrap();
        // Absent, a dotted path at the root is a ROUTE name, not a missing
        // artifact: no Next build protocol ever asks for `/favicon.png`, so
        // its absence says nothing about the build and 500 would be a lie.
        for url_path in [
            "dashboard.txt",
            "favicon.png",
            "openapi.yaml",
            "sitemap.xml",
            "status.json",
        ] {
            assert_eq!(
                resolved(&root, url_path),
                DashboardResolution::RouteAbsent,
                "{url_path}"
            );
        }
        // The content-hashed tree, which the protocol DOES name by path, keeps
        // the loud answer — so the rule above is a tree, not a blanket.
        for url_path in [
            "_next/static/media/gone.woff2",
            "_next/static/chunks/gone.js",
            "_next/static/css/gone.css",
        ] {
            assert_eq!(
                resolved(&root, url_path),
                DashboardResolution::AssetMissing,
                "{url_path}"
            );
        }
        // And `_next/` outside `static/` is not that tree.
        assert_eq!(
            resolved(&root, "_next/gone.js"),
            DashboardResolution::RouteAbsent
        );
    }

    #[test]
    fn an_absent_route_and_a_missing_asset_answer_differently() {
        let root = export_root();
        // A route the export cannot carry: a DB row, an installed plugin, a
        // single-use token, a force-dynamic docs tree.
        assert_eq!(
            resolved(&root, "dashboard/combos/some-uuid"),
            DashboardResolution::RouteAbsent
        );
        assert_eq!(
            resolved(&root, "dashboard/plugins/some-plugin/config"),
            DashboardResolution::RouteAbsent
        );
        // An artifact the export protocol REQUIRES. Its absence is a broken
        // deployment, so it must not be reported as a merely-absent page.
        assert_eq!(
            resolved(&root, "dashboard/combos/__next._tree.txt"),
            DashboardResolution::AssetMissing
        );
        // The present one, pinned on its own bytes, so the arm above is
        // shown to distinguish the two rather than always take the first.
        assert_eq!(
            std::fs::read(resolved_file(&root, "dashboard/providers/openai/__next._index.txt").0)
                .unwrap(),
            b"SEGMENT INDEX"
        );
        assert_eq!(
            resolved(&root, "_next/static/chunks/gone.js"),
            DashboardResolution::AssetMissing
        );
    }

    #[test]
    fn no_deployed_build_is_its_own_answer() {
        // An absent root and an empty one both mean "no build", and must not
        // be confused with a request for a path a build does not carry.
        let missing = TempDir::new().unwrap();
        fs::remove_dir_all(missing.path()).unwrap();
        assert_eq!(
            resolved(&missing, "dashboard"),
            DashboardResolution::NoBuildAtEntry
        );
        let empty = empty_root();
        assert_eq!(
            resolved(&empty, "dashboard"),
            DashboardResolution::NoBuildAtEntry
        );
        // And the entry is the ONLY url that may fall back to the landing
        // page, so it must be distinguished from every other path — the
        // origin-root routes included, or a deep link to `/login` on a host
        // with no build would land the operator on `/dashboard`.
        assert_ne!(
            resolved(&empty, "dashboard/providers"),
            resolved(&empty, "dashboard")
        );
        assert_eq!(
            resolved(&empty, "dashboard/providers"),
            DashboardResolution::NoBuild
        );
        for url_path in ["/", "/login", "/login.txt", "/docs/intro", "/status"] {
            assert_eq!(
                resolved(&empty, url_path),
                DashboardResolution::NoBuild,
                "{url_path}"
            );
        }
    }

    #[test]
    fn asset_paths_resolve_under_the_root() {
        assert_eq!(
            dashboard_relative_path("assets/app.js").unwrap(),
            PathBuf::from("assets/app.js")
        );
        // A leading slash and a redundant `.` carry no meaning for the
        // join and must not be able to smuggle one in.
        assert_eq!(
            dashboard_relative_path("/static/./app.js").unwrap(),
            PathBuf::from("static/app.js")
        );
    }

    #[test]
    fn traversal_segments_are_rejected() {
        assert_eq!(
            resolved(&export_root(), "dashboard/../etc/passwd"),
            DashboardResolution::Refused
        );
        assert_eq!(
            resolved(&export_root(), "dashboard/providers/../../../etc/passwd"),
            DashboardResolution::Refused
        );
        assert_eq!(
            resolved(&export_root(), "_next/../../etc/passwd"),
            DashboardResolution::Refused
        );
        assert!(dashboard_relative_path("assets/..").is_none());
        assert!(dashboard_relative_path("assets\\..\\..\\etc\\passwd").is_none());
        assert!(dashboard_relative_path("assets/app.js\0.png").is_none());
        // An empty remainder is not a rejection but it is not a path either:
        // it names the export root, and the only file there is the shell.
        assert_eq!(dashboard_relative_path(""), Some(PathBuf::new()));
        assert_eq!(dashboard_relative_path("/"), Some(PathBuf::new()));
        assert!(!dashboard_relative_path("").unwrap().is_absolute());
    }

    #[test]
    fn the_origin_root_mounts_are_covered_by_the_same_containment() {
        // The wider surface invited new spellings of the same attack, and
        // they must land on the same refusal as the two the dashboard mount
        // already refused: a route mount, a nested mount, a `:param` mount
        // and the export root itself.
        let root = export_root();
        for url_path in [
            "login/../../etc/passwd",
            "login/../dashboard.html",
            "auth/callback/../../../etc/passwd",
            "docs/../../etc/passwd",
            "docs/a/b/../../../etc/passwd",
            "connect/codex/../../etc/passwd",
            "connect/codex/..%2f..%2fetc%2fpasswd",
            "providers/../dashboard.html",
            "status/../..%2fetc%2fpasswd",
            "404/..%2f..%2fetc%2fpasswd",
            "login%2f..%2f..%2fetc%2fpasswd",
            "login\\..\\..\\etc\\passwd",
            "login/__next._tree.txt\0.png",
            "/../../etc/passwd",
        ] {
            assert_eq!(
                resolve_dashboard(root.path(), &format!("/{url_path}")),
                DashboardResolution::Refused,
                "/{url_path} was not refused",
            );
        }
    }

    #[test]
    fn an_encoded_traversal_is_refused_not_merely_absent() {
        // The value reaches `dashboard_relative_path` already percent-decoded
        // by axum's `Path` extractor, so these are `..` segments by then and
        // must be REFUSED — answering 404 would report a hostile request as a
        // merely absent page.
        let root = export_root();
        for encoded in [
            "%2e%2e%2fetc%2fpasswd",
            "..%2f..%2fetc%2fpasswd",
            "%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
            ".%2e/.%2e/etc/passwd",
            "..%5c..%5cetc%5cpasswd",
            "..%00/etc/passwd",
        ] {
            assert_eq!(
                resolve_dashboard(root.path(), &format!("/dashboard/{encoded}")),
                DashboardResolution::Refused,
                "{encoded} was not refused",
            );
        }
    }

    #[test]
    fn a_double_encoded_traversal_is_an_ordinary_name_and_never_a_file() {
        // Decoded exactly once, so `%252e%252e%252f` is the ordinary name
        // `%2e%2e%2fetc%2fpasswd` — a single segment that is neither a `..`
        // segment nor a file. Which of the two absent-answers it draws
        // depends only on the decoded NAME and the tree it addresses, so only
        // the security property is asserted for all of them…
        let root = export_root();
        for mount in ["/dashboard", "/login", "/auth/callback", "/docs", ""] {
            for encoded in [
                "..%252f..%252fetc%252fpasswd",
                "%252e%252e%252fetc%252fpasswd",
                "..%255c..%255cetc%255cpasswd",
            ] {
                let url_path = format!("{mount}/{encoded}");
                let resolution = resolve_dashboard(root.path(), &url_path);
                assert!(
                    !matches!(
                        resolution,
                        DashboardResolution::File { .. } | DashboardResolution::Refused
                    ),
                    "{url_path} was not treated as an ordinary absent name: {resolution:?}",
                );
            }
        }
        // …and the no-literal-dot form is pinned exactly, so a SECOND decode
        // pass — which would turn it into `../etc/passwd` and flip the answer
        // to `Refused` — cannot pass unnoticed. Pinned on both trees, since
        // they classify it differently and both answers must stay honest.
        assert_eq!(
            resolve_dashboard(root.path(), "/dashboard/%252e%252e%252fetc%252fpasswd"),
            DashboardResolution::RouteAbsent,
        );
        assert_eq!(
            resolve_dashboard(root.path(), "/login/%252e%252e%252fetc%252fpasswd"),
            DashboardResolution::RouteAbsent,
        );
    }

    #[test]
    fn a_symlink_out_of_the_root_is_refused() {
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("out");
        fs::create_dir_all(root.join("dashboard")).unwrap();
        fs::write(root.join("dashboard.html"), b"<html>entry</html>").unwrap();
        let outside = dir.path().join("outside-secret.txt");
        fs::write(&outside, b"TOP SECRET").unwrap();
        // Where a document candidate actually looks, i.e. inside the
        // app-route tree — a symlink at the export root is not reachable by
        // any mount and would prove nothing.
        std::os::unix::fs::symlink(&outside, root.join("dashboard/escape.html")).unwrap();
        // Also a symlinked segment, so the escape is not only in the leaf.
        fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
        fs::write(dir.path().join("elsewhere/leaf.html"), b"TOP SECRET").unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), root.join("dashboard/hop"))
            .unwrap();

        assert_eq!(
            resolve_dashboard(&root, "dashboard/escape"),
            DashboardResolution::Refused
        );
        assert_eq!(
            resolve_dashboard(&root, "dashboard/hop/leaf"),
            DashboardResolution::Refused
        );
    }

    #[test]
    fn a_symlink_out_of_the_root_is_refused_on_the_origin_root_surface_too() {
        // The wider surface is the same chokepoint, so the same three places a
        // document candidate looks: the export root's own shell, an
        // origin-root route document, and a segment inside a route's
        // directory.
        let dir = TempDir::new().unwrap();
        let root = dir.path().join("out");
        populate_export(&root);
        let outside = dir.path().join("outside-secret.txt");
        fs::write(&outside, b"TOP SECRET").unwrap();
        // The shell, which is the one file the export root names.
        fs::remove_file(root.join("index.html")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("index.html")).unwrap();
        // An origin-root route document.
        fs::remove_file(root.join("login.html")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("login.html")).unwrap();
        // A symlinked segment under a route, so the escape is not only a leaf.
        fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
        fs::write(dir.path().join("elsewhere/leaf.html"), b"TOP SECRET").unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), root.join("login/hop")).unwrap();

        for url_path in ["/", "/login", "/login/hop/leaf"] {
            assert_eq!(
                resolve_dashboard(&root, url_path),
                DashboardResolution::Refused,
                "{url_path} was not refused",
            );
        }
        // The payload beside the refused document is a real file, so the
        // three refusals above are about the symlinks and not about a root
        // that answers nothing.
        assert!(matches!(
            resolve_dashboard(&root, "/login.txt"),
            DashboardResolution::File { .. }
        ));
    }

    #[test]
    fn a_segment_named_like_a_dotdot_is_not_a_traversal() {
        // The shape the old textual strip broke on, and the reason it
        // broke: `....//` collapsed to `//`, and `root.join("//etc/passwd")`
        // is ABSOLUTE, so the read left the root. Segment-wise, `....` is
        // an ordinary directory name, so the resolved path stays relative
        // and can only ever land under the root. `..foo` / `foo..` are
        // ordinary names too — rejecting them would break real assets.
        let rel = dashboard_relative_path("....//....//etc/passwd").unwrap();
        assert_eq!(rel, PathBuf::from("..../..../etc/passwd"));
        assert!(!rel.is_absolute(), "resolved asset path must stay relative");
        assert_eq!(
            dashboard_relative_path("..foo/bar..").unwrap(),
            PathBuf::from("..foo/bar..")
        );
    }

    // ── End-to-end through the real router ────────────────────────────────
    //
    // Resolution is only half the contract; what the operator's browser
    // receives is the other half. The dashboard root is process-global (the
    // override above), so every test that sets it holds this lock for its
    // duration — otherwise two concurrent `#[tokio::test]`s would each assert
    // against the other's fixture.

    static TEST_ROOT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    type Headers = std::collections::HashMap<String, String>;

    /// One request against the real router, with the raw bytes: a served
    /// `.png` is binary, so a `String` body would assert against a lossy
    /// rendering of it rather than the file.
    async fn request(app: axum::Router, method: &str, uri: &str) -> (StatusCode, Vec<u8>, Headers) {
        let resp = app
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        (status, bytes.to_vec(), headers)
    }

    async fn get(app: axum::Router, uri: &str) -> (StatusCode, String, Headers) {
        let (status, bytes, headers) = request(app, "GET", uri).await;
        (
            status,
            String::from_utf8_lossy(&bytes).into_owned(),
            headers,
        )
    }

    /// `HEAD` — the probe `next/dist/client/components/segment-cache/cache.js:1241`
    /// issues before it fetches a route document, and the only method the
    /// browser sends for it.
    async fn head(app: axum::Router, uri: &str) -> (StatusCode, Vec<u8>, Headers) {
        request(app, "HEAD", uri).await
    }

    fn content_type(headers: &Headers) -> Option<&str> {
        headers.get("content-type").map(String::as_str)
    }

    /// A build that carries a document, a payload and a segment directory for
    /// EVERY entry of the route table, so the census below drives the whole
    /// table rather than a sample of it.
    fn export_root_with_every_origin_root_route() -> TempDir {
        let dir = export_root();
        for route in ORIGIN_ROOT_ROUTES {
            let name = route.trim_start_matches('/');
            fs::write(
                dir.path().join(format!("{name}.html")),
                format!("<html>{name}</html>"),
            )
            .unwrap();
            fs::write(
                dir.path().join(format!("{name}.txt")),
                format!("{name} RSC PAYLOAD"),
            )
            .unwrap();
            fs::create_dir_all(dir.path().join(name)).unwrap();
            fs::write(
                dir.path().join(name).join("__next._tree.txt"),
                format!("{name} TREE"),
            )
            .unwrap();
        }
        dir
    }

    fn dashboard_app() -> axum::Router {
        use aisix_core::snapshot::SnapshotHandle;
        use aisix_core::AdminConfig;
        crate::build_router(crate::AdminState::new(
            SnapshotHandle::new(aisix_core::AisixSnapshot::new()),
            crate::InMemoryStore::new(),
            &AdminConfig {
                enabled: true,
                addr: "127.0.0.1:0".into(),
                admin_keys: vec!["admin-secret".into()],
                tls: None,
            },
        ))
    }

    /// One test, two phases, because the root override is process-global and
    /// `#[tokio::test]` bodies run concurrently.
    #[tokio::test]
    async fn the_router_serves_a_deployed_build_and_still_works_without_one() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let root = export_root();
        // A canary beside the root: a traversal that escaped would answer 200
        // with these bytes, so the assertion is on the BODY, not the status.
        let canary = root.path().join("canary.txt");
        fs::write(&canary, b"aisix-traversal-canary").unwrap();

        // ── Phase 1: a build is deployed ──────────────────────────────────
        let previous = with_test_dashboard_root(root.path());

        let (status, body, headers) = get(dashboard_app(), "/dashboard").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("dashboard entry"), "body was {body:?}");
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("text/html; charset=utf-8")
        );

        // The trailing-slash entry. `matchit` 0.7.3 leaves `/dashboard/`
        // unmatched against `/dashboard/*path` (`tree.rs:519`), so this is a
        // ROUTER fact, not a resolution one, and it is pinned here: without
        // the explicit route it answers a bare 404.
        let (status, body, _) = get(dashboard_app(), "/dashboard/").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("dashboard entry"), "body was {body:?}");

        // The document, the RSC payload and the segment file a client-side
        // navigation to a deep route needs, each with its own answer.
        for (uri, expected) in [
            ("/dashboard/providers/openai", "<html>openai</html>"),
            ("/dashboard/providers/openai.txt", "RSC FLIGHT PAYLOAD"),
            (
                "/dashboard/providers/openai/__next._tree.txt",
                "TREE WITH id PARAM",
            ),
        ] {
            let (status, body, headers) = get(dashboard_app(), uri).await;
            assert_eq!(status, StatusCode::OK, "{uri} answered {body:?}");
            assert!(body.contains(expected), "{uri} body was {body:?}");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some(if uri.ends_with(".txt") {
                    "text/plain; charset=utf-8"
                } else {
                    "text/html; charset=utf-8"
                }),
                "{uri} content-type",
            );
        }

        // The chunks the document asks for at the ORIGIN ROOT.
        let (status, body, headers) = get(dashboard_app(), "/_next/static/chunks/app.js").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "console.log(1)");
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/javascript; charset=utf-8")
        );
        assert_eq!(
            headers.get("cache-control").map(String::as_str),
            Some("public, max-age=31536000, immutable")
        );

        // HTML must not be cached that way.
        let (_, _, headers) = get(dashboard_app(), "/dashboard").await;
        assert_eq!(
            headers.get("cache-control").map(String::as_str),
            Some("no-cache")
        );

        // An absent route: an honest 404, never the entry document.
        for uri in [
            "/dashboard/combos/some-uuid",
            "/dashboard/plugins/some-plugin/config",
        ] {
            let (status, body, _) = get(dashboard_app(), uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(
                !body.contains("dashboard entry") && !body.contains("Gateway dashboard"),
                "{uri} must not answer with a document: {body:?}",
            );
        }

        // A missing artifact: loud, and distinguishable from the above.
        for uri in [
            "/_next/static/chunks/gone.js",
            "/dashboard/combos/__next._tree.txt",
        ] {
            let (status, body, _) = get(dashboard_app(), uri).await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{uri}");
            assert!(body.contains("incomplete"), "{uri} body was {body:?}");
        }

        // Traversal: refused, with no file content in the body.
        for uri in [
            "/dashboard/../canary.txt",
            "/dashboard/%2e%2e%2fcanary.txt",
            "/dashboard/providers/..%2f..%2fcanary.txt",
            "/_next/../canary.txt",
            "/_next/%2e%2e%2fcanary.txt",
        ] {
            let (status, body, headers) = get(dashboard_app(), uri).await;
            // 400, not 404: the request is malformed or hostile, and a 404
            // would report it as a merely absent page.
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} answered {body:?}");
            assert!(
                !body.contains("aisix-traversal-canary"),
                "{uri} leaked file content: {body:?}"
            );
            // A refused request is a plain explanation, never a document and
            // never the shell.
            assert_eq!(
                content_type(&headers),
                Some("text/plain; charset=utf-8"),
                "{uri}"
            );
            assert!(
                !body.contains("<html>"),
                "{uri} answered a document: {body:?}"
            );
        }

        // Admin auth is untouched by any of this.
        let (status, _, _) = get(dashboard_app(), "/admin/v1/models").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // ── Phase 2: no build is deployed ────────────────────────────────
        // A live deployment depends on this: the binary must stay a valid API
        // server with no dashboard build in place.
        let empty = empty_root();
        with_test_dashboard_root(empty.path());

        let (status, body, _) = get(dashboard_app(), "/dashboard").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("Gateway dashboard"), "body was {body:?}");
        assert!(body.contains("/admin/openapi-scalar"), "body was {body:?}");

        // But a sub-resource of a build that is not there is absent, not the
        // entry point.
        for uri in ["/dashboard/providers", "/_next/static/chunks/app.js"] {
            let (status, body, _) = get(dashboard_app(), uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}");
            assert!(
                !body.contains("Gateway dashboard"),
                "{uri} body was {body:?}"
            );
        }

        // The API surface still answers.
        let (status, _, _) = get(dashboard_app(), "/livez").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, _) = get(dashboard_app(), "/admin/openapi.json").await;
        assert_eq!(status, StatusCode::OK);

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    /// The whole origin-root route table, in every form a client asks for a
    /// route in. A census rather than a sample: a mount that resolves nothing
    /// is indistinguishable from a route that does not exist until someone
    /// opens that page.
    #[tokio::test]
    async fn every_origin_root_route_answers_in_every_request_form() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let root = export_root_with_every_origin_root_route();
        let previous = with_test_dashboard_root(root.path());

        for route in ORIGIN_ROOT_ROUTES {
            let name = route.trim_start_matches('/');
            // The document.
            let (status, body, headers) = get(dashboard_app(), route).await;
            assert_eq!(status, StatusCode::OK, "{route} answered {body:?}");
            assert_eq!(body, format!("<html>{name}</html>"), "{route} body");
            assert_eq!(
                content_type(&headers),
                Some("text/html; charset=utf-8"),
                "{route} content-type"
            );
            // The trailing-slash spelling an operator types by hand.
            let (status, body, _) = get(dashboard_app(), &format!("{route}/")).await;
            assert_eq!(status, StatusCode::OK, "{route}/ answered {body:?}");
            assert_eq!(body, format!("<html>{name}</html>"), "{route}/ body");
            // The RSC payload of a client-side navigation, which the router
            // only accepts as Flight when it arrives as `text/plain`.
            let (status, body, headers) = get(dashboard_app(), &format!("{route}.txt")).await;
            assert_eq!(status, StatusCode::OK, "{route}.txt answered {body:?}");
            assert_eq!(body, format!("{name} RSC PAYLOAD"), "{route}.txt body");
            assert_eq!(
                content_type(&headers),
                Some("text/plain; charset=utf-8"),
                "{route}.txt content-type"
            );
            // The route tree of a cold segment cache.
            let uri = format!("{route}/__next._tree.txt");
            let (status, body, _) = get(dashboard_app(), &uri).await;
            assert_eq!(status, StatusCode::OK, "{uri} answered {body:?}");
            assert_eq!(body, format!("{name} TREE"), "{uri} body");
            // And the `HEAD` probe the client router issues before it fetches
            // a document (`cache.js:1241`): the same status and the same
            // content type, with no body.
            let (status, body, headers) = head(dashboard_app(), route).await;
            assert_eq!(status, StatusCode::OK, "HEAD {route} answered {status}");
            assert!(body.is_empty(), "HEAD {route} carried a body");
            assert_eq!(
                content_type(&headers),
                Some("text/html; charset=utf-8"),
                "HEAD {route} content-type"
            );
            let (status, body, headers) = head(dashboard_app(), &format!("{route}.txt")).await;
            assert_eq!(status, StatusCode::OK, "HEAD {route}.txt answered {status}");
            assert!(body.is_empty(), "HEAD {route}.txt carried a body");
            assert_eq!(
                content_type(&headers),
                Some("text/plain; charset=utf-8"),
                "HEAD {route}.txt content-type"
            );
        }

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    #[tokio::test]
    async fn the_export_root_and_its_own_client_request_forms_are_served() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let root = export_root();
        let previous = with_test_dashboard_root(root.path());

        // `/` is the export's `EntryRedirector`, and it must stay that: the
        // null-rendering shell, revalidated rather than cached immutably.
        for method in ["GET", "HEAD"] {
            let (status, body, headers) = request(dashboard_app(), method, "/").await;
            assert_eq!(status, StatusCode::OK, "{method} / answered {status}");
            assert_eq!(
                content_type(&headers),
                Some("text/html; charset=utf-8"),
                "{method} / content-type"
            );
            assert_eq!(
                headers.get("cache-control").map(String::as_str),
                Some("no-cache")
            );
            if method == "GET" {
                assert!(
                    body.windows(b"router.replace('/dashboard')".len())
                        .any(|window| window == b"router.replace('/dashboard')"),
                    "/ body was {body:?}"
                );
            } else {
                assert!(body.is_empty(), "HEAD / carried a body");
            }
        }

        // The root route's own payload and segment files, and the payload of
        // the `/dashboard` route — all four are written at the export ROOT, so
        // a client-side navigation to `/` or to `/dashboard` needs them there.
        for (uri, expected, content_type_expected) in [
            (
                "/index.txt",
                "ROOT RSC PAYLOAD",
                "text/plain; charset=utf-8",
            ),
            (
                "/__next._tree.txt",
                "ROOT TREE",
                "text/plain; charset=utf-8",
            ),
            (
                "/__next.__PAGE__.txt",
                "ROOT PAGE SEGMENT",
                "text/plain; charset=utf-8",
            ),
            (
                "/dashboard.txt",
                "DASHBOARD RSC PAYLOAD",
                "text/plain; charset=utf-8",
            ),
        ] {
            let (status, body, headers) = get(dashboard_app(), uri).await;
            assert_eq!(status, StatusCode::OK, "{uri} answered {body:?}");
            assert_eq!(body, expected, "{uri} body");
            assert_eq!(content_type(&headers), Some(content_type_expected), "{uri}");
        }

        // The provider logos the origin-root documents link to: `/landing`
        // renders four of them as `<img src>` and `/home` one, so without
        // these the served routes render broken images.
        for name in [
            "claude.svg",
            "cline.svg",
            "codex.svg",
            "cursor.svg",
            "kimi-logomark-light.svg",
            // The one no document links to. Named mounts serve exactly the set
            // a document references, so this is the shape that was 404ing —
            // and a test that only walked the five referenced names could not
            // have seen it.
            "baidu.svg",
        ] {
            let uri = format!("/providers/{name}");
            let (status, body, headers) = get(dashboard_app(), &uri).await;
            assert_eq!(status, StatusCode::OK, "{uri} answered {body:?}");
            assert_eq!(
                content_type(&headers),
                Some("image/svg+xml"),
                "{uri} content-type"
            );
            assert!(!body.is_empty(), "{uri} was empty");
        }

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    /// The export that ships a real PWA worker at its root, which is the
    /// artifact this host deliberately does not run. The file is written with
    /// the two properties that make serving it a hazard, so an assertion that
    /// says "not the export's file" is checking something real: it precaches
    /// the origin root, and it reads from cache before it reads from network.
    fn export_root_shipping_a_service_worker() -> TempDir {
        let dir = export_root();
        fs::write(
            dir.path().join(SERVICE_WORKER_FILE),
            "const APP_SHELL = [\"/\"];\n\
             caches.open(\"omniroute-pwa-v3\").then((c) => c.addAll(APP_SHELL));\n\
             self.addEventListener(\"fetch\", (event) => {\n  \
             const hit = await caches.match(event.request);\n  \
             if (hit) { event.respondWith(hit); }\n});\n\
             // EXPORT-PWA-WORKER-MARKER\n",
        )
        .unwrap();
        dir
    }

    /// `GET /sw.js` answers 200 with a JavaScript media type and a body that
    /// can never answer a request — through the real router, with the export
    /// that really does ship the worker.
    ///
    /// Every assertion here is a browser behaviour, not a preference:
    ///
    /// * **200** — a 404 is the console error this exists to remove
    ///   (`A bad HTTP response code (404) was received when fetching the
    ///   script.`), and it leaves `getRegistrations()` empty.
    /// * **A JavaScript media type** — the browser REJECTS a service-worker
    ///   script served with any other type, and that rejection is itself a
    ///   console error, so `text/plain` would fail the same acceptance.
    /// * **`no-store`** — a browser may reuse a cached worker script, and a
    ///   stored copy of a policy statement is indistinguishable from a stale
    ///   one.
    /// * **not the export's file** — the marker is in the fixture, so this
    ///   fails the moment `/sw.js` is mounted on the dashboard chokepoint
    ///   again.
    /// * **no `fetch` listener, no `respondWith`, no `caches.match`, no
    ///   `addAll`** — the property that closes the hazard. The defence is not
    ///   "our strategy is network-first", it is "there is no strategy": with
    ///   no fetch handler the browser cannot answer a single request on this
    ///   origin from Cache Storage, so the authenticated `/admin/v1/*` surface
    ///   and the documents it is reached through cannot be served stale. This
    ///   is also the assertion that goes red if a future dashboard build
    ///   regresses the script, which is the whole point of holding the policy
    ///   here rather than in a file this repo does not own.
    #[tokio::test]
    async fn the_admin_origin_registers_a_worker_that_cannot_answer_a_request() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let root = export_root_shipping_a_service_worker();
        let previous = with_test_dashboard_root(root.path());

        let (status, body, headers) = get(dashboard_app(), "/sw.js").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a 404 on the registered script is the console error this exists to remove, and it \
             leaves the browser with no registration at all. Body was {body:?}"
        );
        // Body first, then headers: the body IS the policy, and a header
        // regression must not mask a body regression.
        assert!(
            !body.contains("EXPORT-PWA-WORKER-MARKER"),
            "the export's own worker was served: it precaches this origin's root document into \
             credential-blind Cache Storage. Mount /sw.js on the dashboard chokepoint and this \
             fails. Body was {body:?}"
        );
        for forbidden in [
            "addEventListener(\"fetch\"",
            "respondWith",
            "caches.match",
            "addAll",
        ] {
            assert!(
                !body.contains(forbidden),
                "the served worker can answer a request ({forbidden} is present). The property \
                 that makes this origin safe is that it has NO fetch handler, so no request here \
                 can come from Cache Storage. Body was {body:?}"
            );
        }
        // …and it does enforce the invariant rather than merely not creating
        // it: storage an earlier build left on this origin is swept, so a
        // precached admin document does not outlive the decision.
        assert!(
            body.contains("caches.delete"),
            "the script must sweep Cache Storage on this origin, not just decline to write to it"
        );
        assert_eq!(
            content_type(&headers),
            Some("application/javascript; charset=utf-8"),
            "the browser rejects a service-worker script served with any other media type, and \
             that rejection is its own console error"
        );
        assert_eq!(
            headers.get("cache-control").map(String::as_str),
            Some("no-store"),
            "a browser may reuse a cached worker script, so a stored copy of this policy is \
             indistinguishable from a stale one"
        );

        // The answer is for exactly this URL. A near-miss is not the script —
        // otherwise the inert policy would be reachable under a name that
        // could also be a build artifact.
        let (status, body, _) = get(dashboard_app(), "/sw.js.txt").await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "/sw.js.txt answered the script: {body:?}"
        );

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    /// The `?v=` stamp on the registration is a query string, and a query
    /// string is not part of a path. Two things must hold, and both are
    /// assertions that can fail:
    ///
    /// * the router matches on the path, so the stamp cannot become part of a
    ///   filename and cannot select a different answer;
    /// * the `no-store` policy is the stamp's answer too, so a cache-busting
    ///   query cannot buy a differently-cached script.
    ///
    /// The `/dashboard?v=` leg is the one that would catch the real defect. If
    /// the chokepoint ever read the whole request URI instead of `uri.path()`,
    /// the stamp would join the filename, `dashboard.html` would stop being
    /// found, and the operator would get a 404 for the SPA entry on every
    /// stamped URL — with the dashboard itself looking perfectly healthy in
    /// every other test.
    #[tokio::test]
    async fn a_cache_busting_query_answers_the_same_script() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let root = export_root_shipping_a_service_worker();
        let previous = with_test_dashboard_root(root.path());

        let (_, plain, plain_headers) = get(dashboard_app(), "/sw.js").await;
        for query in [
            "/sw.js?v=1790517990052",
            "/sw.js?v=0",
            "/sw.js?v=1&v=2",
            "/sw.js?",
            "/sw.js?a=b#frag",
        ] {
            let (status, body, headers) = get(dashboard_app(), query).await;
            assert_eq!(status, StatusCode::OK, "{query} answered {body:?}");
            assert_eq!(body, plain, "{query} answered a different script");
            assert_eq!(
                headers.get("cache-control").map(String::as_str),
                plain_headers.get("cache-control").map(String::as_str),
                "{query} answered under a different cache policy"
            );
        }

        // The same query-ignoring on a file that really is read off disk, and
        // a control that the two bodies are distinguishable at all — without
        // this the comparison above would hold for two identical answers.
        let (plain_status, entry, _) = get(dashboard_app(), "/dashboard").await;
        let (query_status, stamped, _) = get(dashboard_app(), "/dashboard?v=1790517990052").await;
        assert_eq!(plain_status, StatusCode::OK);
        assert_eq!(
            query_status,
            StatusCode::OK,
            "the SPA entry 404'd on a stamped URL"
        );
        assert_eq!(
            stamped, entry,
            "a query string reached the filename: the stamp must not become part of the path"
        );
        // Non-vacuity: both bodies are the real entry document, so the
        // comparison above is document-vs-document and not two identical error
        // pages.
        assert!(entry.contains("dashboard entry"), "body was {entry:?}");
        assert!(stamped.contains("dashboard entry"), "body was {stamped:?}");

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    /// The origin-root families a static export can never carry, and the
    /// classification defect, through the real router — where the previous
    /// answers were axum's bare 404 (empty body, no content type) and a 500
    /// for a route that is simply not in the build.
    #[tokio::test]
    async fn the_routes_a_static_export_cannot_carry_explain_themselves() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let root = export_root_with_every_origin_root_route();
        let previous = with_test_dashboard_root(root.path());

        for uri in [
            // `/docs/*` is force-dynamic by design, and the origin-root
            // documents link to it; `/connect/codex/[token]` is a single-use
            // token row. A token that carries a dot is still a token.
            "/docs",
            "/docs/",
            "/docs/intro",
            "/docs/api/reference",
            "/docs/openapi.json",
            "/connect/codex/single-use-token",
            "/connect/codex/tok-en.vec",
            "/connect/codex/tok%2Fen",
            // A provider id that is not in this export, dotted or not.
            "/dashboard/providers/absent.corp",
            "/dashboard/providers/acme.corp.txt",
        ] {
            let (status, body, headers) = get(dashboard_app(), uri).await;
            if uri.ends_with(".txt") {
                // The one shape that is an artifact: the export's protocol
                // names `<route>.txt`, so its absence indicts the build and
                // must stay loud.
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{uri}");
                assert!(body.contains("incomplete"), "{uri} body was {body:?}");
                continue;
            }
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri} answered {body:?}");
            assert_eq!(
                content_type(&headers),
                Some("text/plain; charset=utf-8"),
                "{uri} answered the router's bare 404, not the honest one"
            );
            assert!(
                body.contains("not part of the deployed dashboard build"),
                "{uri} body was {body:?}"
            );
            assert!(
                !body.contains("<html>"),
                "{uri} answered with a document: {body:?}"
            );
            // The same honest answer for the `HEAD` probe.
            let (status, body, headers) = head(dashboard_app(), uri).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "HEAD {uri} answered {status}"
            );
            assert!(body.is_empty(), "HEAD {uri} carried a body");
            assert_eq!(content_type(&headers), Some("text/plain; charset=utf-8"));
        }

        // And a dotted provider id the build DOES carry answers 200 — the
        // document is `<id>.html` with the dot kept.
        fs::write(
            root.path().join("dashboard/providers/acme.corp.html"),
            b"<html>acme corp</html>",
        )
        .unwrap();
        let (status, body, headers) = get(dashboard_app(), "/dashboard/providers/acme.corp").await;
        assert_eq!(status, StatusCode::OK, "body was {body:?}");
        assert_eq!(body, "<html>acme corp</html>");
        assert_eq!(content_type(&headers), Some("text/html; charset=utf-8"));

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    /// The attack surface grew with the origin-root surface, so containment is
    /// re-proven here rather than assumed: every case is asserted on the BODY,
    /// because a 200 that leaks file content is the failure that matters.
    #[tokio::test]
    async fn the_wider_surface_still_refuses_to_leave_the_dashboard_root() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let (dir, _canary) = export_root_with_a_canary_beside_it();
        let previous = with_test_dashboard_root(&dir.path().join("out"));

        for uri in [
            // The mounts that existed before this change.
            "/dashboard/../canary.txt",
            "/dashboard/%2e%2e%2fcanary.txt",
            "/dashboard/providers/..%2f..%2fcanary.txt",
            "/_next/../canary.txt",
            "/_next/%2e%2e%2fcanary.txt",
            "/_next/static/..%2f..%2fcanary.txt",
            // The origin-root route mount, its nested form, the docs family
            // and the token family.
            "/login/../../canary.txt",
            "/login/%2e%2e/%2e%2e/canary.txt",
            "/login/__next._tree.txt/../../../canary.txt",
            "/auth/callback/../../canary.txt",
            "/status/../canary.txt",
            "/docs/../../canary.txt",
            "/docs/a/../../../canary.txt",
            "/connect/codex/..%2f..%2fcanary.txt",
            // A backslash and a NUL, which the `/` split would not see and
            // which truncates the path at the syscall.
            "/login/..%5c..%5ccanary.txt",
            "/login/canary.txt%00.png",
            // The logo tree, which is a mount by NAME WILDECARD and so is the
            // first surface where a path segment is whatever the request says
            // it is. Every spelling of the same escape, on the new mount.
            "/providers/../canary.txt",
            "/providers/..%2f..%2fcanary.txt",
            "/providers/%2e%2e%2fcanary.txt",
            "/providers/%2E%2E%2Fcanary.txt",
            "/providers/..%5c..%5ccanary.txt",
            "/providers/canary.txt%00.svg",
            "/providers/hop/../../../canary.txt",
            "/providers/./../../canary.txt",
            "/providers//..%2fcanary.txt",
        ] {
            let (status, body, headers) = get(dashboard_app(), uri).await;
            // 400, not 404: the request is malformed or hostile, and a 404
            // would report it as a merely absent page.
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri} answered {body:?}");
            assert!(
                !body.contains("aisix-traversal-canary"),
                "{uri} leaked file content: {body:?}"
            );
            // A refused request is a plain explanation, never a document and
            // never the shell.
            assert_eq!(
                content_type(&headers),
                Some("text/plain; charset=utf-8"),
                "{uri}"
            );
            assert!(
                !body.contains("<html>"),
                "{uri} answered a document: {body:?}"
            );
        }

        // Three shapes the ROUTER refuses before a handler ever sees them,
        // because their first segment is not a mounted one: `..` where a
        // mount expects a name, and an encoded backslash where a mount
        // expects a `/`. They answer the router's own 404, and the property
        // that matters still holds — no file content, no document. The
        // chokepoint's own refusal of these shapes is pinned at the
        // resolution level in
        // `the_origin_root_mounts_are_covered_by_the_same_containment`.
        for uri in [
            "/../canary.txt",
            "/./../../canary.txt",
            "/login%5c..%5ccanary.txt",
        ] {
            let (status, body, _) = get(dashboard_app(), uri).await;
            assert!(status.is_client_error(), "{uri} answered {status}");
            assert!(
                !body.contains("aisix-traversal-canary"),
                "{uri} leaked file content: {body:?}"
            );
            assert!(
                !body.contains("<html>"),
                "{uri} answered a document: {body:?}"
            );
        }

        // A symlink that leaves the root is refused on the new mounts too,
        // and the canary's bytes are still not in the body.
        let root = dir.path().join("out");
        fs::remove_file(root.join("login.html")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("canary.txt"), root.join("login.html")).unwrap();
        fs::remove_file(root.join("index.html")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("canary.txt"), root.join("index.html")).unwrap();
        fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
        fs::write(
            dir.path().join("elsewhere/leaf.html"),
            b"aisix-traversal-canary",
        )
        .unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), root.join("login/hop")).unwrap();
        for uri in ["/login", "/", "/login/hop/leaf"] {
            let (status, body, _) = get(dashboard_app(), uri).await;
            assert!(
                status.is_client_error(),
                "{uri} answered {status} with {body:?}"
            );
            assert!(
                !body.contains("aisix-traversal-canary"),
                "{uri} leaked file content through a symlink: {body:?}"
            );
        }

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    /// Real bytes for an extension, so the content-type table is asserted
    /// about files and not about names: a real 1×1 PNG (the 8-byte signature
    /// plus an `IHDR` chunk), a real `<svg>` document, and text otherwise.
    fn artifact_bytes(extension: &str) -> Vec<u8> {
        match extension {
            "png" => vec![
                0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
                0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00,
                0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78,
                0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00,
                0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
            ],
            "svg" => {
                br#"<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"></svg>"#.to_vec()
            }
            other => format!("fixture {other}").into_bytes(),
        }
    }

    /// Fixture-backed, not a table lookup: every extension the classification
    /// rule trusts is a real file in a real build, planted under the
    /// content-hashed tree, requested through the router, and the RESPONSE's
    /// content type is what is asserted. Before this, the `.png`/`.svg`/font
    /// arms of `mime_for_path` had never been exercised by a served file —
    /// this export happens to ship no images under `_next/static`.
    #[tokio::test]
    async fn every_known_artifact_extension_is_served_with_its_own_content_type() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let root = export_root();
        let previous = with_test_dashboard_root(root.path());

        for extension in BUILD_ARTIFACT_EXTENSIONS {
            let name = format!("fixture.{extension}");
            let planted = artifact_bytes(extension);
            let path = root.path().join(NEXT_STATIC_DIR).join("media").join(&name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, &planted).unwrap();
            let uri = format!("/{NEXT_STATIC_DIR}/media/{name}");
            let (status, body, headers) = request(dashboard_app(), "GET", &uri).await;
            assert_eq!(status, StatusCode::OK, "{uri} answered {status}");
            assert_eq!(body, planted, "{uri} served other bytes");
            let served = content_type(&headers);
            let expected = mime_for_path(Path::new(&name));
            assert_eq!(served, Some(expected), "{uri} content type");
            assert_ne!(
                served,
                Some("application/octet-stream"),
                ".{extension} is served as a download"
            );
            // The content-hashed tree keeps the immutable contract, so a
            // browser never re-fetches a file whose name cannot change.
            assert_eq!(
                headers.get("cache-control").map(String::as_str),
                Some("public, max-age=31536000, immutable"),
                "{uri} cache-control"
            );
        }

        // An extension no build ships falls through to the download type,
        // pinned so the loop above cannot pass by making the table total.
        let path = root
            .path()
            .join(NEXT_STATIC_DIR)
            .join("media")
            .join("fixture.xyzzy");
        fs::write(&path, b"\x00\x01\x02").unwrap();
        let (status, _, headers) = get(
            dashboard_app(),
            &format!("/{NEXT_STATIC_DIR}/media/fixture.xyzzy"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            content_type(&headers),
            Some("application/octet-stream"),
            "the default arm moved"
        );

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    // ── The vendor-logo tree ───────────────────────────────────────────────
    //
    // The mount answers for a DIRECTORY, so these are not the five names a
    // document happens to link to. What a wildcard newly invites has to be
    // measured rather than assumed: a file that is in the tree and is not a
    // logo, a symlinked file, a symlinked directory segment, and the same
    // containment the other mounts already have.

    /// The servability fact itself, derived rather than restated: a file in the
    /// logo tree is servable exactly when the ONE mime table gives it an
    /// `image/*` type. Enumerated both ways, because a one-way assertion is the
    /// shape that cannot fail — "it is not servable" passes for every extension
    /// nobody thought about, including the next one the table learns.
    #[test]
    fn every_extension_the_table_names_decides_whether_a_logo_is_servable() {
        for extension in BUILD_ARTIFACT_EXTENSIONS {
            let path = PathBuf::from(format!("{PROVIDERS_DIR}/vendor.{extension}"));
            let mime = mime_for_path(&path);
            assert_eq!(
                is_provider_logo(&path),
                mime.starts_with("image/"),
                ".{extension} is {mime} but servability says otherwise"
            );
        }
        // The extensions the logo bound must refuse, named — an `.js` and an
        // `.html` in this tree would be a script and a document on the origin
        // `/admin/v1/*` answers on, which is the whole reason the bound is
        // here. Pinned by name so the arms that make it a decision cannot be
        // deleted quietly.
        for refused in [
            "html",
            "js",
            "mjs",
            "json",
            "map",
            "txt",
            "wasm",
            "webmanifest",
            "xml",
            "yaml",
            "css",
            "woff",
            "woff2",
            "ttf",
        ] {
            let path = PathBuf::from(format!("{PROVIDERS_DIR}/vendor.{refused}"));
            assert!(
                !is_provider_logo(&path),
                ".{refused} became servable from the logo tree"
            );
        }
        // And the images the bound admits — every one the export can ship a
        // logo in, so adding a format to the table admits it here with no
        // second edit.
        for served in ["svg", "png", "jpg", "jpeg", "webp", "ico"] {
            let path = PathBuf::from(format!("{PROVIDERS_DIR}/vendor.{served}"));
            assert!(
                is_provider_logo(&path),
                ".{served} is not servable from the logo tree"
            );
        }
        // The default arm: an extension the table has never heard of is a
        // download, so it is not a logo either.
        assert!(!is_provider_logo(Path::new("providers/vendor.xyzzy")));
        assert!(!is_provider_logo(Path::new("providers/README")));
    }

    /// The whole tree answers, not the sample a document links to: a census
    /// over the fixture's own `providers/` directory, so a file that is there
    /// and is servable cannot be silently unmounted.
    #[tokio::test]
    async fn the_whole_logo_tree_answers_with_its_own_bytes() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let root = export_root();
        let previous = with_test_dashboard_root(root.path());

        let logos: Vec<String> = fs::read_dir(root.path().join(PROVIDERS_DIR))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".svg"))
            .collect();
        assert!(
            logos.len() > 1,
            "the fixture carries no logo tree, so this would pass while serving nothing"
        );
        for name in &logos {
            let uri = format!("/{PROVIDERS_DIR}/{name}");
            let on_disk = fs::read(root.path().join(PROVIDERS_DIR).join(name)).unwrap();
            let (status, body, headers) = request(dashboard_app(), "GET", &uri).await;
            assert_eq!(status, StatusCode::OK, "{uri} answered {status}");
            // Byte-identical, not merely "a 200 with something in it": a logo
            // the browser cannot parse renders as an empty frame, which is the
            // exact failure this mount exists to remove.
            assert_eq!(body, on_disk, "{uri} served other bytes");
            assert_eq!(
                content_type(&headers),
                Some("image/svg+xml"),
                "{uri} content-type"
            );
            // A logo keeps a stable name and is redeployed, so it must be
            // revalidated — the same contract as every other non-hashed file.
            assert_eq!(
                headers.get("cache-control").map(String::as_str),
                Some("no-cache"),
                "{uri} cache-control",
            );
            // The `HEAD` probe an image decider issues, so it cannot be the
            // one request form that 404s.
            let (status, body, headers) = head(dashboard_app(), &uri).await;
            assert_eq!(status, StatusCode::OK, "HEAD {uri} answered {status}");
            assert!(body.is_empty(), "HEAD {uri} carried a body");
            assert_eq!(
                content_type(&headers),
                Some("image/svg+xml"),
                "HEAD {uri} content-type"
            );
        }

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    /// A file that is in the logo tree and is not a logo is not served. The
    /// whole point of the mount being a directory rather than a name list is
    /// that nothing decides which files are in it by name — so the bound is on
    /// the TYPE the response would carry, and it is asserted on the body: a
    /// 200 that leaked a script is the failure that matters, and a status
    /// check alone would call that green.
    #[tokio::test]
    async fn a_non_logo_in_the_tree_is_not_served_from_the_admin_origin() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let root = export_root();
        let previous = with_test_dashboard_root(root.path());

        for name in [
            "catalog.js",
            "catalog.html",
            "notes.txt",
            "brand.wasm",
            "blob.xyzzy",
        ] {
            let uri = format!("/{PROVIDERS_DIR}/{name}");
            let (status, body, headers) = get(dashboard_app(), &uri).await;
            assert!(
                status.is_client_error(),
                "{uri} is in the build and was served: {status} {body:?}"
            );
            assert!(
                !body.contains("aisix-provider-logo-escape"),
                "{uri} leaked its content: {body:?}"
            );
            // Never a document, never the shell.
            assert!(
                !body.contains("<html>"),
                "{uri} answered a document: {body:?}"
            );
            // Whatever the status, the answer is this surface's own plain
            // explanation. Asserting the type is what rules out the failure
            // that matters: a 200 carrying `application/javascript` or
            // `text/html` from the origin `/admin/v1/*` answers on. The type of
            // a 404 is not a defect, so the type of a 2xx is pinned by
            // `every_extension_the_table_names_decides_whether_a_logo_is_servable`
            // instead of by a list of types to avoid.
            assert_eq!(
                content_type(&headers),
                Some("text/plain; charset=utf-8"),
                "{uri} carried a content type other than the explanation's"
            );
        }

        // A non-logo in the tree is answered EXACTLY as an absent one is, so
        // the mount is not an existence oracle over the export tree. (The
        // build's contents are no secret from this origin anyway — every
        // document in it is served by name — but a mount that answered two
        // ways for the same question would be answering one nobody asked.)
        for name in ["catalog.js", "catalog.html", "absent.svg", "absent.js"] {
            let present = get(dashboard_app(), &format!("/{PROVIDERS_DIR}/{name}")).await;
            let absent = get(
                dashboard_app(),
                &format!("/{PROVIDERS_DIR}/never-shipped-{name}"),
            )
            .await;
            assert_eq!(
                (present.0, content_type(&present.2), present.1.is_empty()),
                (absent.0, content_type(&absent.2), absent.1.is_empty()),
                "{name} is distinguishable from a file that is not in the build"
            );
        }

        // The tree's own two directory spellings answer the surface's honest
        // 404 rather than the router's bare one, which is the reason they are
        // mounted at all (`matchit` 0.7.3, `tree.rs:519`).
        for uri in ["/providers", "/providers/"] {
            let (status, body, headers) = get(dashboard_app(), uri).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri} answered {body:?}");
            assert_eq!(
                content_type(&headers),
                Some("text/plain; charset=utf-8"),
                "{uri} answered the router's bare 404, not the honest one"
            );
            assert!(
                body.contains("not part of the deployed dashboard build"),
                "{uri} body was {body:?}"
            );
        }

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    /// The bound is on the RESOLVED file, not on how the URL spelled the
    /// request. Every spelling that reaches the tree reaches the same verdict,
    /// and the app-route documents under `dashboard/providers/` — a different
    /// tree at a different place — are untouched by it.
    #[tokio::test]
    async fn the_logo_bound_lands_on_the_file_and_not_on_the_spelling() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let root = export_root();
        let previous = with_test_dashboard_root(root.path());

        // The re-rooted form reaches the same bytes, because the export puts
        // the tree at its root and the mount reads it from either mount.
        for name in ["claude.svg", "baidu.svg"] {
            let origin = request(dashboard_app(), "GET", &format!("/providers/{name}")).await;
            let rerooted = request(
                dashboard_app(),
                "GET",
                &format!("/dashboard/providers/{name}"),
            )
            .await;
            assert_eq!(origin.0, StatusCode::OK, "/providers/{name}");
            assert_eq!(rerooted.0, origin.0, "/dashboard/providers/{name}");
            assert_eq!(rerooted.1, origin.1, "/dashboard/providers/{name} bytes");
        }

        // …and the bound follows the file through that same spelling: the
        // re-rooted form of a non-logo is refused too, not served because the
        // URL said `/dashboard/`.
        for name in ["catalog.js", "catalog.html"] {
            let (status, body, _) =
                get(dashboard_app(), &format!("/dashboard/providers/{name}")).await;
            assert!(
                status.is_client_error(),
                "/dashboard/providers/{name} was served: {status} {body:?}"
            );
            assert!(
                !body.contains("aisix-provider-logo-escape"),
                "/dashboard/providers/{name} leaked its content: {body:?}"
            );
        }

        // The app-route tree that shares the SEGMENT NAME is unaffected: those
        // are route documents, served as documents, exactly as before. A bound
        // that keyed on the path's first segment would have broken every one
        // of them, which is why it is decided on the resolved file.
        for (uri, expected) in [
            (
                "/dashboard/providers/openai",
                "<html>openai</html>".to_string(),
            ),
            (
                "/dashboard/providers/openai.txt",
                "RSC FLIGHT PAYLOAD".to_string(),
            ),
            (
                "/dashboard/providers/acme.corp",
                "<html>acme corp</html>".to_string(),
            ),
        ] {
            let (status, body, headers) = get(dashboard_app(), uri).await;
            assert_eq!(status, StatusCode::OK, "{uri} answered {body:?}");
            assert_eq!(body, expected, "{uri} body");
            assert!(
                content_type(&headers).is_some_and(|value| value.starts_with("text/")),
                "{uri} content-type was {:?}",
                content_type(&headers)
            );
        }

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    /// The logo tree is the first mount here whose shape is a WILDCARD, so the
    /// surface it can reach is proven rather than assumed. Two things are
    /// asserted, and both on the body: every path the admin listener already
    /// owned answers what it answered, and the export is planted with a DECOY
    /// file for each of them — so a mount that intercepted one would answer 200
    /// with those bytes, which a status check alone would call a pass.
    #[tokio::test]
    async fn the_logo_mount_cannot_intercept_a_path_the_admin_surface_owns() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let root = export_root();
        // A decoy for every protected path, at the exact place the dashboard
        // chokepoint would look if the router ever sent it there. Byte-distinct
        // from anything the surface legitimately serves.
        const DECOY: &[u8] = b"AISIX-LOGO-MOUNT-DECOY";
        //
        // NOT `status/*`: `/status` is an entry of `ORIGIN_ROOT_ROUTES`, and
        // that loop derives a `/status/*path` mount from it, so a file at
        // `<root>/status/<name>` is legitimately addressable and a decoy there
        // would be served BY THAT mount. The real export's `status/` carries
        // only `__next.status.__PAGE__.txt` and `__next._tree.txt`, which is
        // why the assertion below is a 404 against a build shaped like it.
        // `admin/v1/typo` is here for the sharpest case of all: a path NO route
        // claims, which is precisely what a catch-all fallback would answer.
        for decoy in [
            "admin/v1/models",
            "admin/v1/combos",
            "admin/v1/typo",
            "livez",
            "readyz",
            "dashboard/providers/baidu.html",
            "_next/static/chunks/decoy.js",
        ] {
            let path = root.path().join(decoy);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, DECOY).unwrap();
        }
        // And one in the logo tree itself, so a path that IS a logo answers
        // with the logo and nothing else can.
        fs::write(
            root.path().join("providers/baidu.svg"),
            b"<svg id='baidu'/>",
        )
        .unwrap();
        let previous = with_test_dashboard_root(root.path());

        // Each path's own answer, as this surface gave it before the mount
        // existed. `/status/*` is the metrics listener's on another address and
        // the export ships no such file, so the admin listener's answer for it
        // is the surface's own 404 — asserted rather than assumed.
        for (uri, expected) in [
            ("/admin/v1/models", StatusCode::UNAUTHORIZED),
            ("/admin/v1/combos", StatusCode::UNAUTHORIZED),
            ("/livez", StatusCode::OK),
            ("/admin/openapi.json", StatusCode::OK),
            ("/admin/openapi-scalar", StatusCode::OK),
            ("/status/config", StatusCode::NOT_FOUND),
            ("/status/ready", StatusCode::NOT_FOUND),
            ("/status/models", StatusCode::NOT_FOUND),
        ] {
            let (status, body, _) = get(dashboard_app(), uri).await;
            assert_eq!(status, expected, "{uri} answered {status} with {body:?}");
            assert!(
                !body.contains("AISIX-LOGO-MOUNT-DECOY"),
                "{uri} was intercepted by the dashboard mount: {body:?}"
            );
        }
        // `/admin/v1/typo` is claimed by no route, so its status alone cannot
        // tell the router's own 404 from a fallback that answered out of the
        // export. The DECOY is what tells them apart: a fallback would return
        // it, 200, on this path.
        {
            let (status, body, _) = get(dashboard_app(), "/admin/v1/typo").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "/admin/v1/typo");
            assert!(
                !body.contains("AISIX-LOGO-MOUNT-DECOY"),
                "a path no route claims was answered out of the export: {body:?}"
            );
        }
        // `/readyz` is 200 or 503 on a configuration that has not been
        // applied, so it is asserted on the property and not the code.
        let (status, body, _) = get(dashboard_app(), "/readyz").await;
        assert!(
            matches!(status, StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE),
            "/readyz answered {status} with {body:?}"
        );
        assert!(
            !body.contains("AISIX-LOGO-MOUNT-DECOY"),
            "/readyz was intercepted"
        );

        // `/_next/*` still resolves the real chunk, and the app-route tree
        // under `/dashboard/*` still resolves the real document — a decoy
        // planted at each is never what answers.
        for (uri, expected) in [
            ("/_next/static/chunks/app.js", "console.log(1)"),
            ("/dashboard/providers/baidu", "AISIX-LOGO-MOUNT-DECOY"),
        ] {
            let (status, body, _) = get(dashboard_app(), uri).await;
            assert_eq!(status, StatusCode::OK, "{uri} answered {status}");
            assert_eq!(body, expected, "{uri} body");
        }
        // The app-route decoy is the route's own file, and it answers as a
        // DOCUMENT — the logo bound, which keys on the resolved path, did not
        // reach into the tree that merely shares the segment name.
        let (status, _, headers) = get(dashboard_app(), "/dashboard/providers/baidu").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            content_type(&headers),
            Some("text/html; charset=utf-8"),
            "a route document under dashboard/providers/ was answered as a logo"
        );

        // The CSRF gate is hoisted over the whole router and the auth gate is
        // per-route; both are asserted here because a wildcard mount is
        // exactly the kind of change that can quietly displace one. With a
        // cross-origin `Origin` the method is refused BEFORE the credential is
        // ever looked at (403); with none it authenticates and refuses (401).
        for (method, uri) in [
            ("POST", "/admin/v1/resources"),
            ("PATCH", "/admin/v1/combos/some-uuid"),
            ("DELETE", "/admin/v1/combos/some-uuid"),
        ] {
            // `None` sends NO declaration, which is the case the gate
            // deliberately lets through (no browser produces it for an unsafe
            // request); `Some` sends a cross-origin one, which it refuses
            // before the credential is looked at.
            for (origin, expected) in [
                (Some("https://evil.example"), StatusCode::FORBIDDEN),
                (None, StatusCode::UNAUTHORIZED),
            ] {
                let mut builder = Request::builder().method(method).uri(uri);
                if let Some(origin) = origin {
                    builder = builder.header(axum::http::header::ORIGIN, origin);
                }
                let resp = dashboard_app()
                    .oneshot(builder.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let status = resp.status();
                let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
                    .await
                    .unwrap();
                assert_eq!(
                    status, expected,
                    "{method} {uri} with origin {origin:?} answered {status}"
                );
                assert!(
                    !bytes.windows(DECOY.len()).any(|window| window == DECOY),
                    "{method} {uri} with origin {origin:?} was intercepted by the dashboard mount"
                );
            }
        }
        // A method an endpoint does not have is still 405, on the admin surface
        // and on the new mount alike — the mount takes GET and HEAD only, so no
        // unsafe method on it can reach a handler that mutates anything.
        for (method, uri) in [
            ("PUT", "/admin/v1/resources"),
            ("POST", "/providers/claude.svg"),
            ("DELETE", "/providers/baidu.svg"),
        ] {
            let (status, bytes, _) = request(dashboard_app(), method, uri).await;
            assert_eq!(
                status,
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {uri} answered {status}"
            );
            assert!(
                !bytes.windows(DECOY.len()).any(|window| window == DECOY),
                "{method} {uri} was intercepted by the dashboard mount"
            );
        }

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }

    /// A symlink inside the logo tree, in both shapes the previous mounts    /// A symlink inside the logo tree, in both shapes the previous mounts
    /// already covered: the file, and a directory SEGMENT. Both are given a
    /// `.svg` name so they pass the logo bound — otherwise a green result
    /// would prove nothing about the containment check, only about the bound.
    #[tokio::test]
    async fn a_symlink_in_the_logo_tree_is_refused() {
        let _serialized = TEST_ROOT_LOCK.lock().await;
        let (dir, _canary) = export_root_with_a_canary_beside_it();
        let root = dir.path().join("out");
        // A symlinked FILE, and a symlinked DIRECTORY SEGMENT with a logo in
        // it, both pointing beside the root.
        std::os::unix::fs::symlink(
            dir.path().join("canary.txt"),
            root.join("providers/escape.svg"),
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("elsewhere")).unwrap();
        fs::write(
            dir.path().join("elsewhere/leaf.svg"),
            b"aisix-traversal-canary",
        )
        .unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere"), root.join("providers/hop"))
            .unwrap();
        // And one INSIDE the root, which must be served — the check is
        // containment, not "is it a symlink".
        fs::write(root.join("providers/real.svg"), b"<svg id='real'/>").unwrap();
        std::os::unix::fs::symlink(
            root.join("providers/real.svg"),
            root.join("providers/alias.svg"),
        )
        .unwrap();

        let previous = with_test_dashboard_root(&root);

        for uri in ["/providers/escape.svg", "/providers/hop/leaf.svg"] {
            let (status, body, _) = get(dashboard_app(), uri).await;
            assert!(
                status.is_client_error(),
                "{uri} answered {status} with {body:?}"
            );
            assert!(
                !body.contains("aisix-traversal-canary"),
                "{uri} leaked file content through a symlink: {body:?}"
            );
        }

        // Both in-root symlinks still serve their bytes, so the two refusals
        // above are about leaving the root and not about being a symlink.
        for name in ["real.svg", "alias.svg"] {
            let uri = format!("/providers/{name}");
            let (status, body, headers) = get(dashboard_app(), &uri).await;
            assert_eq!(status, StatusCode::OK, "{uri} answered {body:?}");
            assert_eq!(body, "<svg id='real'/>", "{uri} body");
            assert_eq!(
                content_type(&headers),
                Some("image/svg+xml"),
                "{uri} content-type"
            );
        }

        let mut guard = TEST_DASHBOARD_ROOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = previous;
    }
}
