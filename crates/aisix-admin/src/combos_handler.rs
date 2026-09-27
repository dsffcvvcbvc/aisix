//! aisix-admin::combos_handler — native CRUD for combos.
//!
//! A combo — a named group of models a request is routed across — is a
//! **virtual routing model** in this gateway: a [`Model`] carrying a
//! `routing` block. That is the whole reason this surface is a projection
//! and not a resource of its own: a combo row nothing dispatches would be
//! accepted configuration that does nothing, and a second spelling of the
//! routing model would be a second thing to keep in step with it. So every
//! write here lands in the `models` collection, and a combo created through
//! `POST /admin/v1/combos` is served, metered, guardrailed and rate-limited
//! by the same code path as one loaded from a resources file.
//!
//! Routes:
//! - `GET    /admin/v1/combos`      — list combos
//! - `POST   /admin/v1/combos`      — create one combo
//! - `GET    /admin/v1/combos/:id`  — read one combo
//! - `PATCH  /admin/v1/combos/:id`  — update the mutable fields
//! - `DELETE /admin/v1/combos/:id`  — remove one combo
//!
//! # The wire contract
//!
//! The request and response shape is the subset of the combo document that
//! this gateway's routing model actually models:
//!
//! ```json
//! {
//!   "name": "fast-coding",
//!   "strategy": "round_robin",
//!   "models": [
//!     { "model": "gpt-4o", "weight": 3, "priority": 0, "tags": ["fast"] },
//!     { "model_id": "9f1c…" }
//!   ]
//! }
//! ```
//!
//! Every other field a combo document may carry — `description`,
//! `displayName`, `config`, `allowedProviders`, `allowedModelFamilies`,
//! `system_message`, `tool_filter_regex`, `context_cache_protection`,
//! `context_length`, `dimensions`, `isActive`, `isHidden`, and the per-step
//! `label`, `connectionId`, `allowedConnectionIds`, `prompt`,
//! `fallbackOnlyOnQuotaExhaustion` and `kind` — is **rejected by name**
//! with 400. It is never accepted and dropped: a field that arrives,
//! validates and then disappears reads on the dashboard as "configured" and
//! does nothing, which is the one outcome this surface must not produce.
//! Those fields have no home on a routing model, and saying so is more
//! useful than inventing one.
//!
//! # Validation
//!
//! The same two gates the declarative file source uses, in the same order:
//!
//! 1. [`validate_model`] — the strict (write-contract) JSON Schema for one
//!    resource. The translated document is what it judges, so the schema
//!    stays the single definition of a legal routing model.
//! 2. `load_from_str` over the whole document about to be written, so the
//!    file this handler persists is proved loadable before it lands.
//!
//! On top of the schema, one rule the schema cannot state: every target
//! must resolve, in the current configuration, to a **direct** model. A
//! target naming nothing dispatches nowhere, and a target naming another
//! virtual model would nest routing groups with no cycle guard to stop it,
//! so both are refused at the write boundary instead of being discovered on
//! the request path.
//!
//! Commit is an RCU swap of the whole snapshot, then a durable write to the
//! configured `resources_file` (`AISIX_RESOURCES_PATH` / `resources.yaml`
//! fallback) — the same order, and the same last-writer-wins semantics,
//! [`crate::keys_handler`] and [`crate::resources_handler`] document. The
//! persisted document carries the `models` and `provider_keys` collections
//! and nothing else, so a write into a file that also holds other
//! collections is refused with the reason rather than truncating it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aisix_core::filesource::load_from_str;
use aisix_core::models::validate_model;
use aisix_core::resource::ResourceEntry;
use aisix_core::{AisixSnapshot, Model, RoutingStrategy, RoutingTarget};
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Map, Value};

use crate::auth::AdminAuth;
use crate::error::{AdminError, ErrorBody};
use crate::state::AdminState;

/// The collection a combo lives in. Also the first half of a derived id
/// (`<kind>/<identity>`), so the id handed out here is the id a later file
/// reload reproduces.
const KIND: &str = "models";

/// The other collection a combo write re-emits. See
/// [`render_resources_document`]: a direct model's `provider_key_id` is a
/// reference the file source validates, so the key has to travel with the
/// model that names it.
const PROVIDER_KEYS_KIND: &str = "provider_keys";

/// The top-level fields a combo document may carry. Anything else is
/// rejected by name — see the module doc.
const COMBO_FIELDS: &[&str] = &["name", "strategy", "models"];

/// The fields one entry of `models` may carry. A target names its model
/// with `model` (the display name); `weight` is a relative share (not a
/// percentage), `priority` is a tier — a higher value is preferred — and
/// `tags` gate a target on the request's routing tags.
///
/// `model_id` is deliberately absent. A model resource id is the control
/// plane's reference style, and the durable target of this surface is the
/// declarative resources file, which resolves a target by name and rejects
/// the id outright — so a `model_id` accepted here would validate and then
/// leave behind a file no reload accepts.
const COMBO_MODEL_FIELDS: &[&str] = &["model", "weight", "priority", "tags"];

/// The strategy spellings, named only so a rejection can list them. The
/// accepted set itself is the enum — a request is parsed through
/// [`RoutingStrategy`] — and a test pins this list against the enum values
/// the model schema publishes, so a new strategy cannot be accepted while
/// this message still claims a shorter list.
const SUPPORTED_STRATEGIES: &[&str] = &[
    "round_robin",
    "consistent_hash",
    "failover",
    "least_cost",
    "least_latency",
    "least_busy",
];

/// `GET /admin/v1/combos` — list every combo in the configuration.
///
/// Combos are read from the serving snapshot, so the list is what dispatch
/// would resolve, not a second index that can fall behind it.
pub async fn list_combos(
    _auth: AdminAuth,
    State(state): State<AdminState>,
) -> Result<Json<Vec<Value>>, AdminError> {
    let snapshot = state.snapshot.load();
    let mut views: Vec<Value> = snapshot
        .models
        .entries()
        .iter()
        .filter(|entry| is_combo(&entry.value))
        .map(|entry| combo_view(&entry.id, &entry.value))
        .collect();
    // Stable order so a UI list does not reshuffle between identical reads.
    views.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(Json(views))
}

/// `GET /admin/v1/combos/:id` — read one combo.
pub async fn get_combo(
    _auth: AdminAuth,
    State(state): State<AdminState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AdminError> {
    let snapshot = state.snapshot.load();
    let entry = snapshot.models.get_by_id(&id).ok_or(AdminError::NotFound)?;
    if !is_combo(&entry.value) {
        return Err(AdminError::BadRequest(not_a_combo(&entry.value)));
    }
    Ok(Json(combo_view(&entry.id, &entry.value)))
}

/// `POST /admin/v1/combos` — create one combo.
///
/// The id is derived the way the file source derives it (UUIDv5 of
/// `models/<display_name>`), so a combo created here reloads from the
/// persisted file under the very same id.
pub async fn create_combo(
    _auth: AdminAuth,
    State(state): State<AdminState>,
    body: String,
) -> Result<Response, AdminError> {
    let document = parse_body_object(&body)?;
    let model = combo_document_from_create(&document, &state.snapshot.load())?;

    let id = aisix_core::filesource::derive_id(KIND, &model.display_name);
    let snapshot = state.snapshot.load();
    if snapshot.models.name_conflicts(&model.display_name, None) {
        return Ok(conflict(format!(
            "a model named {:?} already exists",
            model.display_name
        )));
    }

    // A hint only — see `update_combo` for why the applied value is read
    // back after the commit instead.
    let revision = state.snapshot.version() + 1;
    let entry = ResourceEntry::new(id.clone(), model, revision as i64);

    // Last-writer-wins full replace, exactly as the provider-key writes
    // are. The id is derived from the display name, so a same-name race
    // contends for one row rather than creating two.
    state.snapshot.rcu(|current| {
        let next = (*current).clone();
        next.models.insert(entry.clone());
        next
    });
    let applied_version = state.snapshot.version();

    let applied = state.snapshot.load();
    persist_snapshot(&state, &applied)?;
    let entry = applied
        .models
        .get_by_id(&id)
        .map(|e| (*e).clone())
        .ok_or_else(|| {
            AdminError::Store("the created combo is missing from the snapshot".into())
        })?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": entry.id,
            "revision": entry.revision,
            "version": applied_version,
            "combo": combo_view(&entry.id, &entry.value),
        })),
    )
        .into_response())
}

/// `PATCH /admin/v1/combos/:id` — update one combo.
///
/// A patch is merged onto the **stored model document**, not onto the combo
/// view: the view carries the routing block and the name, while the stored
/// document may also hold fields a combo request never mentions (`timeout`,
/// `allowed_cidrs`, `rate_limit`, `cooldown`, …) that a resources-file write
/// put there. Merging onto the view would drop every one of them, so the
/// patch only rewrites what it names.
pub async fn update_combo(
    _auth: AdminAuth,
    State(state): State<AdminState>,
    AxumPath(id): AxumPath<String>,
    body: String,
) -> Result<Response, AdminError> {
    let patch = parse_body_object(&body)?;
    let snapshot = state.snapshot.load();

    let current = snapshot.models.get_by_id(&id).ok_or(AdminError::NotFound)?;
    if !is_combo(&current.value) {
        return Err(AdminError::BadRequest(not_a_combo(&current.value)));
    }

    let mut merged = serde_json::to_value(&current.value)
        .map_err(|e| AdminError::Store(format!("stored combo is unreadable: {e}")))?;
    let Value::Object(ref mut fields) = merged else {
        return Err(AdminError::Store(
            "stored combo does not serialise as an object".into(),
        ));
    };
    apply_patch(fields, &patch, &snapshot)?;
    let model = validate_combo_document(&merged, &snapshot)?;

    if snapshot
        .models
        .name_conflicts(&model.display_name, Some(&id))
    {
        return Ok(conflict(format!(
            "a model named {:?} already exists",
            model.display_name
        )));
    }

    let revision = state.snapshot.version() + 1;
    let entry = ResourceEntry::new(id.clone(), model, revision as i64);

    state.snapshot.rcu(|current| {
        let next = (*current).clone();
        next.models.insert(entry.clone());
        next
    });
    let applied_version = state.snapshot.version();

    let applied = state.snapshot.load();
    persist_snapshot(&state, &applied)?;
    let entry = applied
        .models
        .get_by_id(&id)
        .map(|e| (*e).clone())
        .ok_or(AdminError::NotFound)?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "id": entry.id,
            "revision": entry.revision,
            "version": applied_version,
            "combo": combo_view(&entry.id, &entry.value),
        })),
    )
        .into_response())
}

/// `DELETE /admin/v1/combos/:id` — remove one combo.
///
/// Refuses with 409 while anything still references it. A combo is a model,
/// so a routing target, an ensemble panel member or a semantic route naming
/// a deleted one keeps dispatching to a model that no longer exists — the
/// reference has to go first rather than silently orphaning a live group.
pub async fn delete_combo(
    _auth: AdminAuth,
    State(state): State<AdminState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, AdminError> {
    let snapshot = state.snapshot.load();
    let entry = snapshot.models.get_by_id(&id).ok_or(AdminError::NotFound)?;
    if !is_combo(&entry.value) {
        return Err(AdminError::BadRequest(not_a_combo(&entry.value)));
    }

    let dependents = dependents_of(&snapshot, &id, &entry.value.display_name);
    if !dependents.is_empty() {
        return Ok(conflict(format!(
            "combo {:?} is still referenced by {} ({}); remove the references first",
            entry.value.display_name,
            dependents.len(),
            dependents.join(", ")
        )));
    }

    state.snapshot.rcu(|current| {
        let next = (*current).clone();
        next.models.remove(&id);
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

// ── wire contract ─────────────────────────────────────────────────────

/// Whether a model is a combo: a virtual routing model. A direct, ensemble
/// or semantic model is a different kind and is not on this surface.
fn is_combo(model: &Model) -> bool {
    model.routing.is_some()
}

/// The combo view of a stored routing model.
///
/// Emits the `models` entries in the same shape the write path accepts, so
/// a `GET` response can be `PATCH`ed back unchanged.
fn combo_view(id: &str, model: &Model) -> Value {
    let routing = model.routing.as_ref();
    let models: Vec<Value> = routing
        .map(|r| r.targets.iter().map(combo_target_view).collect())
        .unwrap_or_default();
    let mut view = Map::new();
    view.insert("id".into(), Value::String(id.to_string()));
    view.insert("name".into(), Value::String(model.display_name.clone()));
    if let Some(routing) = routing {
        let strategy = serde_json::to_value(routing.strategy).unwrap_or(Value::Null);
        view.insert("strategy".into(), strategy);
    }
    view.insert("models".into(), Value::Array(models));
    Value::Object(view)
}

fn combo_target_view(target: &RoutingTarget) -> Value {
    let mut view = Map::new();
    view.insert("model".into(), Value::String(target.model.clone()));
    if let Some(weight) = target.weight {
        view.insert("weight".into(), json!(weight));
    }
    if let Some(priority) = target.priority {
        view.insert("priority".into(), json!(priority));
    }
    if let Some(tags) = &target.tags {
        if !tags.is_empty() {
            view.insert("tags".into(), json!(tags));
        }
    }
    Value::Object(view)
}

// ── write translation ────────────────────────────────────────────────

/// Translate a create body into the model document it describes.
fn combo_document_from_create(
    body: &Map<String, Value>,
    snapshot: &AisixSnapshot,
) -> Result<Model, AdminError> {
    reject_unknown_keys(body, COMBO_FIELDS, "")?;

    let Some(Value::String(name)) = body.get("name") else {
        return Err(AdminError::BadRequest(
            "`name` is required and must be a string".into(),
        ));
    };
    let name = read_name(&Value::String(name.clone()))?;

    let strategy = read_strategy(body.get("strategy"))?;
    let targets = read_targets(body.get("models"), snapshot)?;

    let document = json!({
        "display_name": name,
        "routing": { "strategy": strategy, "targets": targets },
    });
    validate_combo_document(&document, snapshot)
}

/// Read the combo name: a non-empty string, trimmed.
fn read_name(value: &Value) -> Result<String, AdminError> {
    let Some(name) = value.as_str() else {
        return Err(AdminError::BadRequest("`name` must be a string".into()));
    };
    let name = name.trim();
    if name.is_empty() {
        return Err(AdminError::BadRequest(
            "`name` must not be empty or whitespace".into(),
        ));
    }
    Ok(name.to_string())
}

/// Merge a patch onto a stored model document in place.
///
/// Only the fields the patch names are rewritten, so every model field a
/// combo request does not carry survives the update untouched.
fn apply_patch(
    stored: &mut Map<String, Value>,
    patch: &Map<String, Value>,
    snapshot: &AisixSnapshot,
) -> Result<(), AdminError> {
    reject_unknown_keys(patch, COMBO_FIELDS, "")?;

    for (field, value) in patch {
        match field.as_str() {
            "name" => {
                let name = read_name(value)?;
                stored.insert("display_name".into(), Value::String(name.to_string()));
            }
            "strategy" => {
                let strategy = read_strategy(Some(value))?;
                routing_object(stored)?.insert("strategy".into(), strategy);
            }
            "models" => {
                let targets = read_targets(Some(value), snapshot)?;
                routing_object(stored)?.insert("targets".into(), targets);
            }
            _ => unreachable!("reject_unknown_keys admitted the field"),
        }
    }
    Ok(())
}

/// Read and validate the `strategy` field, defaulting to the routing
/// model's own default when the field is absent.
fn read_strategy(value: Option<&Value>) -> Result<Value, AdminError> {
    let Some(value) = value else {
        return Ok(json!("failover"));
    };
    let Value::String(name) = value else {
        return Err(AdminError::BadRequest("`strategy` must be a string".into()));
    };
    // Parsed through the enum itself rather than against a hand-kept list,
    // so the accepted set is exactly the strategies this build implements.
    // The rejected value is echoed back capped: it is caller-supplied, and
    // this string lands in the API response verbatim.
    const MAX_ECHO_CHARS: usize = 64;
    serde_json::from_value::<RoutingStrategy>(value.clone()).map_err(|_| {
        let echo: String = name.chars().take(MAX_ECHO_CHARS).collect();
        let truncated = if name.chars().count() > MAX_ECHO_CHARS {
            format!("{echo}…")
        } else {
            echo
        };
        AdminError::BadRequest(format!(
            "{truncated:?} is not a routing strategy. Supported strategies: {}.",
            SUPPORTED_STRATEGIES.join(", ")
        ))
    })?;
    Ok(value.clone())
}

/// Read the `models` array into routing targets, checking each one names a
/// direct model that exists today.
fn read_targets(value: Option<&Value>, snapshot: &AisixSnapshot) -> Result<Value, AdminError> {
    let Some(Value::Array(entries)) = value else {
        return Err(AdminError::BadRequest(
            "`models` is required and must be an array of model entries".into(),
        ));
    };
    if entries.is_empty() {
        return Err(AdminError::BadRequest(
            "a combo requires at least one entry in `models`".into(),
        ));
    }

    let mut targets: Vec<Value> = Vec::with_capacity(entries.len());
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let target = read_target(entry, index, snapshot)?;
        let identity = target_identity(entry);
        if let Some(previous) = seen.insert(identity.clone(), index) {
            return Err(AdminError::BadRequest(format!(
                "`models[{index}]` and `models[{previous}]` both name {identity:?}; a combo \
                 lists each target once"
            )));
        }
        targets.push(target);
    }
    Ok(Value::Array(targets))
}

/// One entry of `models`. A bare string is read as a target's display name,
/// the shorthand a combo document may carry for an unannotated entry.
fn read_target(entry: &Value, index: usize, snapshot: &AisixSnapshot) -> Result<Value, AdminError> {
    let path = format!("models[{index}]");
    let object = match entry {
        Value::String(name) => {
            let mut map = Map::new();
            map.insert("model".into(), Value::String(name.clone()));
            map
        }
        Value::Object(map) => map.clone(),
        _ => {
            return Err(AdminError::BadRequest(format!(
                "`{path}` must be an object naming a model, or a model name string"
            )))
        }
    };
    reject_unknown_keys(&object, COMBO_MODEL_FIELDS, &path)?;

    let model = object
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty());

    let mut target = Map::new();
    target.insert(
        "model".into(),
        Value::String(
            model
                .ok_or_else(|| {
                    AdminError::BadRequest(format!(
                        "`{path}` must name a model with `model`, the model's display name"
                    ))
                })?
                .to_string(),
        ),
    );
    for field in ["weight", "priority", "tags"] {
        if let Some(value) = object.get(field) {
            target.insert(field.to_string(), value.clone());
        }
    }

    check_target_is_direct(model, snapshot, &path)?;
    Ok(Value::Object(target))
}

/// The name a target resolves to, for the duplicate check.
fn target_identity(entry: &Value) -> String {
    match entry {
        Value::Object(map) => map
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default()
            .to_string(),
        Value::String(name) => name.trim().to_string(),
        _ => String::new(),
    }
}

/// Fail a target that names no model, or one that names a virtual model.
///
/// A virtual target would nest routing groups; there is no cycle guard on
/// the dispatch path, so a group reachable from itself is refused here
/// rather than recursing on the first request that reaches it.
fn check_target_is_direct(
    model: Option<&str>,
    snapshot: &AisixSnapshot,
    path: &str,
) -> Result<(), AdminError> {
    let Some(entry) = model.and_then(|name| snapshot.models.get_by_name(name)) else {
        return Err(AdminError::BadRequest(format!(
            "`{path}` names a model that is not in the current configuration; a combo target must \
             be an existing direct model"
        )));
    };
    if !is_direct(&entry.value) {
        return Err(AdminError::BadRequest(format!(
            "`{path}` names {:?}, which is a virtual model; a combo target must be a direct model",
            entry.value.display_name
        )));
    }
    Ok(())
}

/// A model that dispatches to an upstream of its own, as opposed to one
/// that selects among other models.
fn is_direct(model: &Model) -> bool {
    model.routing.is_none() && model.ensemble.is_none() && model.semantic.is_none()
}

/// Borrow the stored `routing` block as an object, creating it when a patch
/// names a routing field on a document that has none.
fn routing_object(stored: &mut Map<String, Value>) -> Result<&mut Map<String, Value>, AdminError> {
    let entry = stored
        .entry("routing".to_string())
        .or_insert_with(|| json!({"targets": []}));
    entry.as_object_mut().ok_or_else(|| {
        AdminError::Store("stored combo carries a `routing` block that is not an object".into())
    })
}

/// Validate a translated model document and decode it.
fn validate_combo_document(
    document: &Value,
    snapshot: &AisixSnapshot,
) -> Result<Model, AdminError> {
    let model: Model = validate_model_document(document)?;
    // Re-read the targets off the decoded model: this is the one place the
    // final spelling is known, so the "must be a direct model" rule is
    // checked against what was stored rather than what was sent.
    if let Some(routing) = &model.routing {
        for (index, target) in routing.targets.iter().enumerate() {
            check_target_is_direct(
                (!target.model.is_empty()).then_some(target.model.as_str()),
                snapshot,
                &format!("models[{index}]"),
            )?;
        }
    }
    Ok(model)
}

/// Run the strict write contract, then decode. The message is capped for
/// the reason the other write paths cap theirs: it lands in the API
/// response verbatim, and a hostile document can otherwise pad it without
/// bound. Only the schema's own field path and message are surfaced — never
/// a file path or a backend address.
fn validate_model_document(document: &Value) -> Result<Model, AdminError> {
    const MAX_ERROR_CHARS: usize = 500;
    if let Err(err) = validate_model(document) {
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

/// Reject every key outside `allowed`, naming the first one found.
///
/// A field this gateway does not model is refused rather than dropped, so a
/// caller that sends one learns so from the response instead of from the
/// dashboard rendering a control that does nothing.
fn reject_unknown_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    prefix: &str,
) -> Result<(), AdminError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            return Err(AdminError::BadRequest(format!(
                "{path:?} is not part of the combo contract. A combo document carries \
                 `name`, `strategy` and `models`; a `models` entry carries `model`, `weight`, \
                 `priority` and `tags`."
            )));
        }
    }
    Ok(())
}

/// The display names of every resource still pointing at this combo, sorted
/// so the 409 body does not churn between identical calls.
fn dependents_of(snapshot: &AisixSnapshot, id: &str, name: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for entry in snapshot.models.entries() {
        let value = &entry.value;
        let points_at_combo =
            |target: &RoutingTarget| target.model_id.as_deref() == Some(id) || target.model == name;
        if let Some(routing) = &value.routing {
            if routing
                .targets
                .iter()
                .any(|target| points_at_combo(target) && value.display_name != name)
            {
                names.push(format!("combo {:?}", value.display_name));
                continue;
            }
        }
        if let Some(ensemble) = &value.ensemble {
            if ensemble
                .panel
                .iter()
                .any(|member| member.model_id.as_deref() == Some(id) || member.model == name)
            {
                names.push(format!("ensemble model {:?}", value.display_name));
            }
        }
        if let Some(semantic) = &value.semantic {
            if semantic
                .routes
                .iter()
                .any(|route| route.target_id.as_deref() == Some(id) || route.target == name)
            {
                names.push(format!("semantic model {:?}", value.display_name));
            }
        }
    }
    names.sort_unstable();
    names
}

/// Why an id that resolves to a model is still not a combo.
fn not_a_combo(model: &Model) -> String {
    format!(
        "model {:?} is not a combo; this surface addresses virtual routing models only",
        model.display_name
    )
}

// ── persistence ──────────────────────────────────────────────────────

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

/// Render the snapshot's models as a resources-file document and write it
/// to the configured file, atomically.
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
/// `AISIX_RESOURCES_PATH`, then `resources.yaml`. Same order the other write
/// paths use.
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

/// The resources-file document for `snapshot`'s combos, its sibling direct
/// models, and the provider keys they dispatch with.
///
/// JSON is emitted deliberately: it is a YAML 1.2 subset, so the file source
/// parses it unchanged and no emitter is needed here. The test module pins
/// the round-trip — a document this function produced must load back into
/// the same rows.
///
/// `provider_keys` rides along because the two collections are coupled by a
/// reference the file source validates: a direct model carries a
/// `provider_key_id`, and a file that declares the model without declaring
/// the key is rejected on load. Rendering `models` alone would therefore
/// produce a document that no reload accepts for any configuration holding a
/// direct model.
pub(super) fn render_resources_document(snapshot: &AisixSnapshot) -> Result<String, AdminError> {
    let models: Vec<Value> = snapshot
        .models
        .entries()
        .iter()
        .map(|entry| serde_json::to_value(&entry.value))
        .collect::<Result<_, _>>()
        .map_err(|e| AdminError::Store(format!("model is unserialisable: {e}")))?;
    let provider_keys: Vec<Value> = snapshot
        .provider_keys
        .entries()
        .iter()
        .map(|entry| serde_json::to_value(&entry.value))
        .collect::<Result<_, _>>()
        .map_err(|e| AdminError::Store(format!("provider key is unserialisable: {e}")))?;

    let mut document = Map::new();
    document.insert("_format_version".into(), json!("1"));
    document.insert(KIND.into(), Value::Array(models));
    document.insert(PROVIDER_KEYS_KIND.into(), Value::Array(provider_keys));
    let body = serde_json::to_string_pretty(&Value::Object(document))
        .map_err(|e| AdminError::Store(format!("resources document is unserialisable: {e}")))?;
    verify_loadable(&body)?;
    Ok(body)
}

/// Feed a document through the file source's own loader. A failure means
/// this handler is about to write a file no reload accepts — a 500, never a
/// silent success.
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
/// A per-combo write replaces the whole document, and this module renders
/// only the `models` and `provider_keys` collections: re-emitting the others
/// needs the id-to-name resugaring the `aisix export` document builder does,
/// and that lives in `aisix-server`. Rather than publish a second, drifting
/// exporter, a write into a file that also holds other collections is
/// refused with the reason, leaving the operator's file untouched.
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
             combo endpoints"
                .into(),
        ));
    };
    let carried = loaded.models.len() + loaded.provider_keys.len();
    let others = loaded.total_entries() - carried;
    if others > 0 {
        return Err(AdminError::Store(format!(
            "the configured resources file holds {others} resource(s) outside `{KIND}` and \
             `{PROVIDER_KEYS_KIND}`, which a per-combo write cannot re-emit; use \
             `POST /admin/v1/resources` to write the whole file"
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
                    tracing::warn!(path = %target.display(), error = %e, "parent dir fsync failed after combo persist");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "combos_handler_tests.rs"]
mod tests;
