//! aisix-admin::resources_handler — Atomic resources update & static dashboard serving.
//!
//! Provides:
//! - `POST /admin/v1/resources`: validates and updates resources atomically in memory
//! - `GET /dashboard`: serves the OmniRoute SPA dashboard
//! - `GET /dashboard/*path`: route documents, RSC payloads and segment files
//! - `GET /_next/*path` and the origin-root document assets: the files the
//!   exported documents request without the `dashboard` prefix

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
    // `AISIX_RESOURCES_PATH`, then `resources.yaml`.
    let target_path: PathBuf = state
        .resources_file
        .clone()
        .or_else(|| {
            std::env::var("AISIX_RESOURCES_PATH")
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
    if let Ok(custom) = std::env::var("AISIX_DASHBOARD_DIR") {
        PathBuf::from(custom)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let p1 = PathBuf::from(format!("{home}/.aisix/dashboard/out"));
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
        _ => "application/octet-stream",
    }
}

/// `GET /dashboard` — the SPA entry document. Named for the mount; the
/// resolution is identical to every other dashboard URL, and the built-in
/// landing page is reachable from here alone because only the entry point
/// resolves to [`DashboardResolution::NoBuildAtEntry`].
pub async fn serve_dashboard_index(uri: Uri) -> Response {
    dashboard_response(&uri)
}

/// Every other dashboard URL: route documents, RSC payloads, per-segment
/// files, and the origin-root assets an exported document references
/// without the `dashboard` prefix (`basePath` and `assetPrefix` are both
/// empty in the export, so every `<script src>` is `/_next/static/...`).
///
/// Mounted on `/dashboard/*path`, on `/_next/*path`, and on the handful of
/// named root-level files a document links to. All of them resolve
/// identically, so they are all one handler: a mount that had its own copy
/// of this logic is exactly how the layout rules would drift.
pub async fn serve_dashboard_path(uri: Uri) -> Response {
    dashboard_response(&uri)
}

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
    // Honest 404: the export carries no such route. Four route families are
    // legitimately absent by construction — a DB row (`/dashboard/combos/[id]`),
    // an installed plugin (`/dashboard/plugins/[name]/config`), a single-use
    // token, and a force-dynamic docs tree — and a static export cannot
    // produce any of them. This is deliberately NOT the entry document: a
    // 200 carrying `dashboard.html` would drop the operator on `/dashboard`
    // and report a page that was never asked for as a success.
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
  <title>AISIX Gateway Dashboard</title>
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
    <div class="badge">AISIX Unified Native Gateway</div>
    <h1>Gateway dashboard</h1>
    <p>The gateway core is running and serving requests. The static SPA dashboard is expected in <code>~/.aisix/dashboard/out</code>.</p>
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

    for candidate in dashboard_candidates(&real_root, &rel) {
        if !candidate.is_file() {
            continue;
        }
        // A file that reached the filesystem through a symlink can name
        // anything. Re-check where it actually lives, not where it was
        // spelled: `starts_with` compares whole components, so `<root>-evil`
        // cannot pass for `<root>`.
        return match candidate.canonicalize() {
            Ok(real) if real.starts_with(&real_root) => DashboardResolution::File {
                // Decided here, next to the resolution, so the caching
                // contract cannot drift from the layout it describes:
                // `_next/static/**` is build-id-scoped and content-hashed, so
                // it is immutable; every other dashboard file keeps a stable
                // name whose bytes change on the next export and must be
                // revalidated.
                immutable: real.starts_with(real_root.join("_next").join("static")),
                path: real,
            },
            _ => DashboardResolution::Refused,
        };
    }

    // A build IS deployed; it just does not carry this path. Which of the
    // two honest answers applies is decided by the request's own shape, which
    // is the export's own split: a request whose last segment carries a file
    // extension is asking for a named build artifact, and one that does not
    // is asking for a route document.
    if rel.named_artifact {
        DashboardResolution::AssetMissing
    } else {
        DashboardResolution::RouteAbsent
    }
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
    /// Whether the request's last segment carries a file extension, i.e.
    /// whether it names a build artifact rather than a route.
    named_artifact: bool,
    /// Whether the request addresses the SPA entry point itself, with or
    /// without a trailing slash.
    at_entry: bool,
    /// The same remainder relative to the export root, for a request that
    /// DID arrive under the `dashboard` mount, so an origin-root asset is
    /// addressable from either mount.
    origin_asset: Option<PathBuf>,
}

/// Take the `dashboard` mount prefix off, if it is there. A request that
/// does not carry it — `/_next/static/…`, `/favicon.ico` — is already
/// relative to the export root and can only name an asset.
fn split_dashboard_entry(rel: PathBuf) -> DashboardPaths {
    let mut segments = rel.components();
    match segments.next() {
        Some(std::path::Component::Normal(first)) if first == DASHBOARD_ENTRY => {
            let rest = segments.as_path().to_path_buf();
            let named_artifact = rest.extension().is_some();
            DashboardPaths {
                at_entry: rest.as_os_str().is_empty(),
                named_artifact,
                origin_asset: Some(rest.clone()),
                rest,
                wants_document: true,
            }
        }
        _ => {
            let named_artifact = rel.extension().is_some();
            DashboardPaths {
                at_entry: false,
                named_artifact,
                rest: rel,
                wants_document: false,
                origin_asset: None,
            }
        }
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
/// can reach a file outside the four forms below.
fn dashboard_candidates(real_root: &Path, rel: &DashboardPaths) -> Vec<PathBuf> {
    let mut candidates = Vec::with_capacity(4);
    if rel.wants_document {
        let route_root = real_root.join(DASHBOARD_ENTRY);
        // Exact name inside the app-route tree: the RSC payload of a
        // client-side navigation (`<page>.txt`) and the per-segment files
        // (`__next._tree.txt`, `__next._index.txt`, `__next._full.txt`).
        // MUST precede the document form — an extension-appending candidate
        // tried first would answer a payload request with the HTML document.
        candidates.push(route_root.join(&rel.rest));
        if !rel.named_artifact {
            // Document: `trailingSlash` is unset, so the export emits a flat
            // `<route>.html`, not a directory index. Restricted to a path
            // with no extension, which is exactly what makes it a route
            // request rather than an asset request.
            candidates.push(route_root.join(&rel.rest).with_extension("html"));
            // Directory index, for a trailing-slash request and for a build
            // that does emit `index.html`.
            candidates.push(route_root.join(&rel.rest).join("index.html"));
        }
    } else {
        candidates.push(real_root.join(&rel.rest));
    }
    // Origin-root asset, reachable from the `dashboard` mount too.
    if let Some(asset) = &rel.origin_asset {
        candidates.push(real_root.join(asset));
    }
    candidates
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
    (!rel.as_os_str().is_empty()).then_some(rel)
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

    /// A dashboard root shaped like the real export (artifact `10928452044`):
    /// a flat `<route>.html` per route, `<route>.txt` beside it, the segment
    /// files in a directory of the same name, and the origin-root `_next/`
    /// and `public/` assets the documents reference without a prefix.
    fn export_root() -> TempDir {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        // The `/` shell is a null-rendering redirector: it must never be
        // what a dashboard request answers with.
        fs::write(
            root.join("index.html"),
            b"ROOT SHELL: router.replace('/dashboard')",
        )
        .unwrap();
        fs::write(root.join("dashboard.html"), b"<html>dashboard entry</html>").unwrap();
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
        dir
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
    fn the_root_shell_is_never_what_a_dashboard_request_answers_with() {
        // `out/index.html` is a null-rendering redirector whose only job is to
        // `router.replace('/dashboard')`. Serving it for any dashboard URL
        // silently dumps the operator on `/dashboard` and reports success.
        let root = export_root();
        for url_path in [
            "dashboard",
            "dashboard/providers",
            "dashboard/providers/openai",
            "dashboard/_next/static/chunks/app.js",
        ] {
            let (path, _) = resolved_file(&root, url_path);
            assert!(
                !path.ends_with("index.html"),
                "{url_path} resolved to the root shell {path:?}",
            );
        }
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
        // page, so it must be distinguished from every other path.
        assert_ne!(
            resolved(&empty, "dashboard/providers"),
            resolved(&empty, "dashboard")
        );
        assert_eq!(
            resolved(&empty, "dashboard/providers"),
            DashboardResolution::NoBuild
        );
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
        // Nothing to read.
        assert!(dashboard_relative_path("").is_none());
        assert!(dashboard_relative_path("/").is_none());
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
        // depends only on whether the decoded NAME happens to contain a `.`
        // (that is what makes it a named artifact rather than a route), so
        // only the security property is asserted for all of them…
        let root = export_root();
        for encoded in [
            "..%252f..%252fetc%252fpasswd",
            "%252e%252e%252fetc%252fpasswd",
            "..%255c..%255cetc%255cpasswd",
        ] {
            let resolution = resolve_dashboard(root.path(), &format!("/dashboard/{encoded}"));
            assert!(
                !matches!(
                    resolution,
                    DashboardResolution::File { .. } | DashboardResolution::Refused
                ),
                "{encoded} was not treated as an ordinary absent name: {resolution:?}",
            );
        }
        // …and the no-literal-dot form is pinned exactly, so a SECOND decode
        // pass — which would turn it into `../etc/passwd` and flip the answer
        // to `Refused` — cannot pass unnoticed.
        assert_eq!(
            resolve_dashboard(root.path(), "/dashboard/%252e%252e%252fetc%252fpasswd"),
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
    // receives is the other half. `AISIX_DASHBOARD_DIR` is process-global, so
    // these run in one test to keep them from racing each other.

    async fn get(
        app: axum::Router,
        uri: &str,
    ) -> (
        StatusCode,
        String,
        std::collections::HashMap<String, String>,
    ) {
        let resp = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
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
        (
            status,
            String::from_utf8_lossy(&bytes).into_owned(),
            headers,
        )
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
            let (status, body, _) = get(dashboard_app(), uri).await;
            assert!(
                status.is_client_error(),
                "{uri} answered {status} with {body:?}",
            );
            assert!(
                !body.contains("aisix-traversal-canary"),
                "{uri} leaked file content: {body:?}",
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
}
