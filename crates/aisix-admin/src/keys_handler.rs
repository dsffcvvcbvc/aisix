//! aisix-admin::keys_handler — native CRUD for `provider_keys`.
//!
//! The read surface (`GET`) lives in [`crate::provider_keys_handlers`];
//! this module adds the three write operations the dashboard needs, plus
//! the durable-file half of the same contract:
//!
//! - `POST   /admin/v1/provider_keys` — create one key
//! - `PATCH  /admin/v1/provider_keys/:id` — update the mutable fields
//! - `DELETE /admin/v1/provider_keys/:id` — remove one key
//! - `GET    /admin/v1/preset_providers` — the catalog of vendors a key
//!   can point at with no code of its own
//!
//! Every write goes through the SAME two validators the declarative file
//! source uses, so a document accepted here is a document
//! `aisix_core::filesource::load_from_str` accepts:
//!
//! 1. `validate_provider_key` — the strict (write-contract) JSON Schema
//!    for one resource, the exact call `load_from_str` makes for a
//!    `provider_keys` entry. It is also what pins the set of fields a
//!    PATCH may carry: the patch is merged onto the stored document and
//!    the MERGED document is what the schema judges, so an unknown field
//!    fails as the unknown field it is instead of being accepted and
//!    silently dropped.
//! 2. `load_from_str` over the whole document about to be written, so the
//!    file this handler persists is proved loadable before it lands.
//!
//! Commit is an RCU swap of the whole snapshot, then a durable write to
//! the configured `resources_file` (`AISIX_RESOURCES_PATH` /
//! `resources.yaml` fallback) — the same order, and the same
//! last-writer-wins semantics, [`crate::resources_handler`] documents.

use std::path::{Path, PathBuf};

use aisix_core::filesource::load_from_str;
use aisix_core::models::validate_provider_key;
use aisix_core::resource::ResourceEntry;
use aisix_core::{AisixSnapshot, ProviderKey};
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Map, Value};

use crate::auth::AdminAuth;
use crate::error::{AdminError, ErrorBody};
use crate::state::AdminState;

/// The collection name the file source keys this resource by. Also the
/// first half of a derived id (`<kind>/<identity>`), so the id handed out
/// here is the id a later file reload reproduces.
const KIND: &str = "provider_keys";

/// `POST /admin/v1/provider_keys` — create one provider key.
///
/// The id is derived the way the file source derives it (UUIDv5 of
/// `provider_keys/<display_name>`), so a row created here reloads from
/// the persisted file under the very same id.
pub async fn create_provider_key(
    _auth: AdminAuth,
    State(state): State<AdminState>,
    body: String,
) -> Result<Response, AdminError> {
    let document = parse_body_object(&body)?;
    let key = validate_provider_key_document(&Value::Object(document))?;

    let id = aisix_core::filesource::derive_id(KIND, &key.display_name);
    let snapshot = state.snapshot.load();

    if snapshot
        .provider_keys
        .name_conflicts(&key.display_name, None)
    {
        return Ok(conflict(format!(
            "a provider key named {:?} already exists",
            key.display_name
        )));
    }

    // A hint only — see `update_resources` for why the applied value is
    // read back after the commit instead.
    let revision = state.snapshot.version() + 1;
    let entry = ResourceEntry::new(id.clone(), key, revision as i64);

    // Last-writer-wins full replace, exactly as `update_resources` is: the
    // closure ignores its argument, so two concurrent creates both apply
    // and the later one wins. The id is derived from the display name, so
    // a same-name race contends for one row rather than creating two.
    state.snapshot.rcu(|current| {
        let next = (*current).clone();
        next.provider_keys.insert(entry.clone());
        next
    });
    let applied_version = state.snapshot.version();

    let applied = state.snapshot.load();
    persist_snapshot(&state, &applied)?;
    let entry = applied
        .provider_keys
        .get_by_id(&id)
        .map(|e| (*e).clone())
        .ok_or_else(|| {
            AdminError::Store("the created provider key is missing from the snapshot".into())
        })?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": entry.id,
            "value": entry.value,
            "revision": entry.revision,
            "version": applied_version,
        })),
    )
        .into_response())
}

/// `PATCH /admin/v1/provider_keys/:id` — update one provider key.
///
/// The patchable set is the model's own field set, decided by the strict
/// schema rather than by a list maintained here: a field the model has no
/// place for — `enabled` among them — is rejected as the unknown field it
/// is, rather than accepted and then dropped.
pub async fn update_provider_key(
    _auth: AdminAuth,
    State(state): State<AdminState>,
    AxumPath(id): AxumPath<String>,
    body: String,
) -> Result<Response, AdminError> {
    let patch = parse_body_object(&body)?;
    let snapshot = state.snapshot.load();

    let current = snapshot
        .provider_keys
        .get_by_id(&id)
        .ok_or(AdminError::NotFound)?;

    let mut merged = serde_json::to_value(&current.value)
        .map_err(|e| AdminError::Store(format!("stored provider key is unreadable: {e}")))?;
    let Value::Object(ref mut fields) = merged else {
        return Err(AdminError::Store(
            "stored provider key does not serialise as an object".into(),
        ));
    };
    // `null` clears an `Option` field the same way an absent field leaves
    // it unset — which is what the model documents for `api_base` and
    // `project`.
    for (field, value) in patch {
        fields.insert(field, value);
    }

    let key = validate_provider_key_document(&merged)?;

    if snapshot
        .provider_keys
        .name_conflicts(&key.display_name, Some(&id))
    {
        return Ok(conflict(format!(
            "a provider key named {:?} already exists",
            key.display_name
        )));
    }

    let revision = state.snapshot.version() + 1;
    let entry = ResourceEntry::new(id.clone(), key, revision as i64);

    state.snapshot.rcu(|current| {
        let next = (*current).clone();
        next.provider_keys.insert(entry.clone());
        next
    });
    let applied_version = state.snapshot.version();

    let applied = state.snapshot.load();
    persist_snapshot(&state, &applied)?;
    let entry = applied
        .provider_keys
        .get_by_id(&id)
        .map(|e| (*e).clone())
        .ok_or(AdminError::NotFound)?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "id": entry.id,
            "value": entry.value,
            "revision": entry.revision,
            "version": applied_version,
        })),
    )
        .into_response())
}

/// `DELETE /admin/v1/provider_keys/:id` — remove one provider key.
///
/// Refuses with 409 while anything still references the key. A model or
/// passthrough route naming a deleted `provider_key_id` keeps dispatching
/// with no credential to send, so the reference has to go first —
/// silently orphaning a live model is exactly the quiet downgrade this
/// surface must not produce.
pub async fn delete_provider_key(
    _auth: AdminAuth,
    State(state): State<AdminState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, AdminError> {
    let snapshot = state.snapshot.load();
    snapshot
        .provider_keys
        .get_by_id(&id)
        .ok_or(AdminError::NotFound)?;

    let dependents = dependents_of(&snapshot, &id);
    if !dependents.is_empty() {
        return Ok(conflict(format!(
            "provider key {id} is still referenced by {} ({}); remove the references first",
            dependents.len(),
            dependents.join(", ")
        )));
    }

    state.snapshot.rcu(|current| {
        let next = (*current).clone();
        next.provider_keys.remove(&id);
        next
    });
    let applied_version = state.snapshot.version();

    let applied = state.snapshot.load();
    persist_snapshot(&state, &applied)?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "deleted",
            "id": id,
            "version": applied_version,
        })),
    )
        .into_response())
}

/// The display names of every resource still pointing at `id`, sorted so
/// the 409 body does not churn between identical calls.
/// `provider_key_id` is a reference, never a copy — the gateway resolves it
/// on the read path — so a row naming a deleted key is a broken row, not a
/// degraded one.
fn dependents_of(snapshot: &AisixSnapshot, id: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for entry in snapshot.models.entries() {
        if entry.value.provider_key_id.as_deref() == Some(id) {
            names.push(format!("model {:?}", entry.value.display_name));
        }
    }
    for entry in snapshot.passthrough_routes.entries() {
        if entry.value.provider_key_id.as_deref() == Some(id) {
            names.push(format!(
                "passthrough route {:?}",
                aisix_core::resource::Resource::name(&entry.value)
            ));
        }
    }
    names.sort_unstable();
    names
}

/// `GET /admin/v1/preset_providers` — the vendors a Provider Key can be
/// pointed at with no code of its own.
///
/// A thin read of the embedded catalog in `aisix-provider-openai`
/// ([`aisix_provider_openai::PRESET_PROVIDERS`]), projected onto the wire
/// shape a create form needs. The catalog is the single source: nothing
/// here adds, drops, reorders, or overrides an entry, so what the
/// dashboard offers and what dispatch resolves cannot drift.
///
/// No secret is reachable from that table, and none is added here — only
/// base URLs, the *name* of the header or `Authorization` scheme that
/// carries the credential, and public header values.
///
/// `base_url` is the canonical `api_base` to set on the Provider Key,
/// byte-identical to the source registry entry. The rule the gateway
/// applies to it is "**a base**": the OpenAI family bridge appends
/// `/chat/completions` to reach the vendor's chat endpoint. A full
/// endpoint is TOLERATED rather than published as the contract — the
/// bridge strips a known OpenAI operation before extending, so
/// `https://api.openai.com/v1/chat/completions` and
/// `https://api.openai.com/v1` both land on the same URL, which is what
/// 169 of the 184 rows record and what the other 15 (bases such as
/// `https://api.haiper.ai/v1`) need. Either form therefore gives the
/// request a URL the vendor serves: the catalog carries no row whose path
/// names an operation the family bridge cannot produce.
pub async fn list_preset_providers(_auth: AdminAuth) -> Result<Json<Vec<Value>>, AdminError> {
    Ok(Json(
        aisix_provider_openai::PRESET_PROVIDERS
            .iter()
            .map(preset_provider_view)
            .collect(),
    ))
}

/// One catalog entry as the dashboard consumes it.
fn preset_provider_view(preset: &aisix_provider_openai::PresetProvider) -> Value {
    let headers: Vec<Value> = preset
        .headers
        .iter()
        .map(|(name, value)| json!({"name": name, "value": value}))
        .collect();
    json!({
        "id": preset.id,
        "display_name": preset.display_name,
        "base_url": preset.base_url,
        "auth": preset_auth_view(preset.auth),
        "headers": headers,
    })
}

/// Where the credential goes on the wire. The payload is the shape, never
/// the credential.
///
/// The two non-Bearer shapes are separate `type` values, not one type with
/// a string that means different things per vendor: `api_key_header`'s
/// `header` is a header NAME, while `authorization_scheme`'s `scheme` is a
/// scheme name that belongs in `Authorization`. Collapsing them publishes
/// `{"type":"api_key_header","header":"key"}` for `maritalk`, which reads
/// as "send the secret in a header called `key`" — the one instruction a
/// client cannot act on correctly, because the vendor reads
/// `Authorization: Key <key>`.
fn preset_auth_view(auth: aisix_provider_openai::PresetAuth) -> Value {
    match auth {
        aisix_provider_openai::PresetAuth::Bearer => json!({"type": "bearer"}),
        aisix_provider_openai::PresetAuth::ApiKeyHeader(header) => {
            json!({"type": "api_key_header", "header": header})
        }
        aisix_provider_openai::PresetAuth::AuthorizationScheme(scheme) => {
            json!({"type": "authorization_scheme", "scheme": scheme})
        }
        aisix_provider_openai::PresetAuth::None => json!({"type": "none"}),
    }
}

/// A 409 in the admin envelope. `AdminError` has no conflict arm (it is
/// not a value this module may add), so the response is built here.
fn conflict(message: String) -> Response {
    (StatusCode::CONFLICT, Json(ErrorBody { error_msg: message })).into_response()
}

/// Parse a request body as one JSON object.
fn parse_body_object(body: &str) -> Result<Map<String, Value>, AdminError> {
    if body.trim().is_empty() {
        return Err(AdminError::BadRequest("empty request body".into()));
    }
    let value: Value = serde_json::from_str(body)
        .map_err(|e| AdminError::BadRequest(format!("body is not valid JSON: {e}")))?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(AdminError::BadRequest(
            "body must be a single JSON object".into(),
        )),
    }
}

/// Validate one provider-key document against the strict write contract,
/// then decode it.
///
/// The message is capped for the reason `update_resources` caps its
/// aggregate: it lands in the API response verbatim, and a hostile
/// document can otherwise pad it without bound. Only the schema's own
/// field path and message are surfaced — never a file path or a backend
/// address.
fn validate_provider_key_document(document: &Value) -> Result<ProviderKey, AdminError> {
    const MAX_ERROR_CHARS: usize = 500;
    if let Err(err) = validate_provider_key(document) {
        let text = err.to_string();
        let text = if text.chars().count() > MAX_ERROR_CHARS {
            let truncated: String = text.chars().take(MAX_ERROR_CHARS).collect();
            format!("{truncated}…")
        } else {
            text
        };
        return Err(AdminError::BadRequest(format!(
            "Validation failed at `/{}`: {text}",
            err.path
        )));
    }
    serde_json::from_value(document.clone())
        .map_err(|e| AdminError::BadRequest(format!("body does not decode: {e}")))
}

/// Render the snapshot's provider keys as a resources-file document and
/// write it to the configured file, atomically.
///
/// The document is proved loadable through the file source's own entry
/// point BEFORE it is written, so a file this handler leaves behind can
/// never be one a reload rejects.
fn persist_snapshot(state: &AdminState, snapshot: &AisixSnapshot) -> Result<(), AdminError> {
    let target = resources_file_path(state);
    refuse_if_file_holds_other_resources(&target)?;
    let body = render_resources_document(snapshot)?;
    persist_file(&target, &body).map_err(AdminError::Store)
}

/// The configured durable path: `resources_file` first, then
/// `AISIX_RESOURCES_PATH`, then `resources.yaml`. Same order
/// `update_resources` uses.
fn resources_file_path(state: &AdminState) -> PathBuf {
    state
        .resources_file
        .clone()
        .or_else(|| {
            std::env::var("AISIX_RESOURCES_PATH")
                .ok()
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("resources.yaml"))
}

/// The resources-file document for `snapshot`'s provider keys.
///
/// JSON is emitted deliberately: it is a YAML 1.2 subset, so the file
/// source parses it unchanged and no emitter is needed here. The test
/// module pins the round-trip — a document this function produced must
/// load back into the same rows.
pub(super) fn render_resources_document(snapshot: &AisixSnapshot) -> Result<String, AdminError> {
    let keys: Vec<Value> = snapshot
        .provider_keys
        .entries()
        .iter()
        .map(|entry| serde_json::to_value(&entry.value))
        .collect::<Result<_, _>>()
        .map_err(|e| AdminError::Store(format!("provider key is unserialisable: {e}")))?;
    let body = serde_json::to_string_pretty(&json!({ "_format_version": "1", KIND: keys }))
        .map_err(|e| AdminError::Store(format!("resources document is unserialisable: {e}")))?;
    verify_loadable(&body)?;
    Ok(body)
}

/// Feed a document through the file source's own loader. A failure means
/// this handler is about to write a file no reload accepts — a 500, never
/// a silent success.
fn verify_loadable(body: &str) -> Result<(), AdminError> {
    let env_lookup = |name: &str| std::env::var(name).ok();
    load_from_str(body, "admin_api", 1, &env_lookup)
        .map(|_| ())
        .map_err(|errs| {
            let total = errs.errors.len();
            let first = errs
                .errors
                .first()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown validation failure".to_string());
            AdminError::Store(format!(
                "refusing to persist a resources file the file source would reject \
                 ({total} problem(s)): {first}"
            ))
        })
}

/// Refuse to write when the target file already declares resources this
/// handler does not carry.
///
/// A per-key write replaces the whole document, and this module renders
/// only the `provider_keys` collection: re-emitting the other thirteen
/// needs the id-to-name resugaring the `aisix export` document builder
/// does, and that lives in `aisix-server`. Rather than publish a second,
/// drifting exporter, a write into a file that also holds models (or any
/// other collection) is refused with the reason, leaving the operator's
/// file untouched.
fn refuse_if_file_holds_other_resources(target: &Path) -> Result<(), AdminError> {
    let Ok(contents) = std::fs::read_to_string(target) else {
        // No readable file yet: there is nothing to lose.
        return Ok(());
    };
    if contents.trim().is_empty() {
        return Ok(());
    }
    let env_lookup = |name: &str| std::env::var(name).ok();
    let Ok(loaded) = load_from_str(&contents, "admin_api", 1, &env_lookup) else {
        // A file the source cannot load is not one this handler may
        // overwrite either — the operator has to see their own error.
        return Err(AdminError::Store(
            "the configured resources file does not load; fix it before writing through the \
             provider key endpoints"
                .into(),
        ));
    };
    let others = loaded.total_entries() - loaded.provider_keys.len();
    if others > 0 {
        return Err(AdminError::Store(format!(
            "the configured resources file holds {others} resource(s) outside `{KIND}`, which a \
             per-key write cannot re-emit; use `POST /admin/v1/resources` to write the whole file"
        )));
    }
    Ok(())
}

/// Atomically persist: write tmp, fsync the file, rename over the target,
/// then fsync the parent directory. Any I/O failure is a 500 — never
/// silently ignored.
fn persist_file(target: &Path, body: &str) -> Result<(), String> {
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
                    tracing::warn!(path = %target.display(), error = %e, "parent dir fsync failed after provider key persist");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "keys_handler_tests.rs"]
mod tests;
