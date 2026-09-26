//! aisix-admin::resources_handler — Atomic resources update & static dashboard serving.
//!
//! Provides:
//! - `POST /admin/v1/resources`: validates and updates resources atomically in memory
//! - `GET /dashboard`: serves the OmniRoute SPA dashboard
//! - `GET /dashboard/*path`: serves static assets with proper MIME types and SPA fallback

use std::path::{Path, PathBuf};

use axum::extract::{Path as AxumPath, State};
use axum::http::header::{HeaderValue, CONTENT_TYPE};
use axum::http::StatusCode;
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
                let msgs: Vec<String> = errs.errors.into_iter().map(|e| e.to_string()).collect();
                AdminError::BadRequest(format!("Validation failed: {}", msgs.join("; ")))
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

fn dashboard_root() -> PathBuf {
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
        "json" => "application/json",
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

pub async fn serve_dashboard_index() -> Response {
    let root = dashboard_root();
    let index_file = root.join("index.html");
    if index_file.exists() {
        if let Ok(bytes) = std::fs::read(&index_file) {
            let mut resp = bytes.into_response();
            resp.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            return resp;
        }
    }

    // Clean status landing page if dashboard SPA build has not been placed yet.
    // English, matching the rest of the admin surface (this is an
    // operator fallback, not a dashboard locale).
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
</html>"#).into_response()
}

pub async fn serve_dashboard_asset(AxumPath(path): AxumPath<String>) -> Response {
    let root = dashboard_root();
    // Security: resolve the request against the asset root segment by
    // segment (see `dashboard_asset_relative`) instead of stripping
    // `..` textually — the textual strip is defeated by `....//`.
    let Some(rel) = dashboard_asset_relative(&path) else {
        // `/` (and an all-empty path) is the SPA root, not a file; a
        // `..` segment is an escape attempt and never gets a document.
        return if path.split('/').all(|s| s.is_empty()) {
            serve_dashboard_index().await
        } else {
            StatusCode::NOT_FOUND.into_response()
        };
    };
    let file_path = root.join(&rel);

    if file_path.is_file() {
        if let Ok(bytes) = std::fs::read(&file_path) {
            let mime = mime_for_path(&file_path);
            let mut resp = bytes.into_response();
            if let Ok(val) = HeaderValue::from_str(mime) {
                resp.headers_mut().insert(CONTENT_TYPE, val);
            }
            return resp;
        }
    }

    // SPA fallback: for client-side routing, non-asset paths fallback to index.html
    if !rel.to_string_lossy().contains('.') {
        return serve_dashboard_index().await;
    }

    StatusCode::NOT_FOUND.into_response()
}

/// The asset-root-relative path a dashboard request resolves to, or
/// `None` when the request tries to leave the asset root.
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
fn dashboard_asset_relative(path: &str) -> Option<PathBuf> {
    if path.contains('\\') || path.contains('\0') {
        return None;
    }
    let mut rel = PathBuf::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => continue,
            ".." => return None,
            other => rel.push(other),
        }
    }
    (!rel.as_os_str().is_empty()).then_some(rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_paths_resolve_under_the_root() {
        assert_eq!(
            dashboard_asset_relative("assets/app.js").unwrap(),
            PathBuf::from("assets/app.js")
        );
        // A leading slash and a redundant `.` carry no meaning for the
        // join and must not be able to smuggle one in.
        assert_eq!(
            dashboard_asset_relative("/static/./app.js").unwrap(),
            PathBuf::from("static/app.js")
        );
    }

    #[test]
    fn traversal_segments_are_rejected() {
        assert!(dashboard_asset_relative("../../etc/passwd").is_none());
        assert!(dashboard_asset_relative("assets/../../etc/passwd").is_none());
        assert!(dashboard_asset_relative("assets/..").is_none());
        assert!(dashboard_asset_relative("assets\\..\\..\\etc\\passwd").is_none());
        assert!(dashboard_asset_relative("assets/app.js\0.png").is_none());
        // Nothing to read: the SPA root, served by the index handler.
        assert!(dashboard_asset_relative("").is_none());
        assert!(dashboard_asset_relative("/").is_none());
    }

    #[test]
    fn a_segment_named_like_a_dotdot_is_not_a_traversal() {
        // The shape the old textual strip broke on, and the reason it
        // broke: `....//` collapsed to `//`, and `root.join("//etc/passwd")`
        // is ABSOLUTE, so the read left the root. Segment-wise, `....` is
        // an ordinary directory name, so the resolved path stays relative
        // and can only ever land under the root. `..foo` / `foo..` are
        // ordinary names too — rejecting them would break real assets.
        let rel = dashboard_asset_relative("....//....//etc/passwd").unwrap();
        assert_eq!(rel, PathBuf::from("..../..../etc/passwd"));
        assert!(!rel.is_absolute(), "resolved asset path must stay relative");
        assert_eq!(
            dashboard_asset_relative("..foo/bar..").unwrap(),
            PathBuf::from("..foo/bar..")
        );
    }
}
