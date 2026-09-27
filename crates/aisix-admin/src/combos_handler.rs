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
//! # Strategy names: two vocabularies, one stored value
//!
//! `strategy` accepts **either** the gateway's own six spellings
//! ([`SUPPORTED_STRATEGIES`]) **or** a name from the combo template a
//! dashboard offers its users ([`TEMPLATE_STRATEGIES`]). A template name is
//! translated to the strategy that implements it and the routing model
//! stores the gateway spelling, so `{"strategy": "priority"}` is accepted,
//! dispatched as `failover`, and reads back as `failover` — the response
//! reports what the combo *is*, not what it was asked for.
//!
//! Five template names are honoured, and only because each one names an
//! algorithm this gateway genuinely runs (the reasoning per name, and the
//! divergences, are on the table). `weighted` is the one that looks wrong
//! and is not: `round_robin` here is *smooth weighted* round-robin, and the
//! standalone `weighted` enum value was removed and folded into it on
//! purpose.
//!
//! The other fifteen template names are **refused by name**, not mapped:
//! `random`, `strict-random`, `p2c`, `least-used`, `headroom`,
//! `context-relay`, `context-optimized`, `cache-optimized`, `reset-aware`,
//! `reset-window`, `quota-weighted`, `auto`, `lkgp`, `fusion`, `pipeline`.
//! Every one of them is refused because the algorithm it names is one this
//! gateway does not run, and the nearest strategy that *does* run computes
//! something different — a randomized pick mapped onto a deterministic
//! picker, a cumulative request count onto an instantaneous in-flight
//! gauge, a context *transfer* onto a context *pin*. A caller who picked one
//! of these from a dashboard list would be told it was configured while a
//! different policy served their traffic, which is worse than a 400 that
//! names the value. [`REFUSED_TEMPLATE_STRATEGIES`] carries the per-name
//! reason.
//!
//! This is a data-plane half only. The paired control-plane change each
//! accepted template name implies — schema enum, Go model, etcd projection,
//! dashboard dropdown, en/zh i18n — is specified in `CP_COMBOS_PROJECT.md`;
//! the control-plane repository is not reachable from here, so none of it
//! ships with this change.
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

/// The gateway strategy spellings, named only so a rejection can list them.
/// The accepted set itself is the enum — a request is parsed through
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

/// The combo-template strategy names this gateway honours, and the strategy
/// each one is dispatched as.
///
/// A name lands here only when the routing model that answers to it does what
/// the template's own name promises. `weighted` is the case that looks
/// dishonest and is not: this gateway's `round_robin` is *smooth weighted*
/// round-robin (the nginx algorithm — `aisix-proxy/src/routing.rs::wrr_pick`),
/// and the separate `weighted` enum value was removed and folded into it on
/// purpose (AISIX-Cloud#1206; the removal is pinned by
/// `removed_weighted_strategy_and_sticky_flag_are_rejected` in
/// `aisix-core/src/models/routing.rs`). A name whose algorithm the gateway
/// does not implement is refused instead — see [`REFUSED_TEMPLATE_STRATEGIES`]
/// for that list and the reason each one is on it.
const TEMPLATE_STRATEGIES: &[(&str, RoutingStrategy)] = &[
    // "Prefer the higher priority, fall through on failure." `failover` starts
    // at the first target and only moves later on failure, and the routing
    // model partitions every target list into priority tiers first
    // (`partition_by_priority`), so a combo that sets `priority` per target
    // gets exactly this. Divergence: the tiering is not what `failover` alone
    // means — it is a property of the model, so a target list with no explicit
    // `priority` is a single tier and behaves as plain first-then-failover.
    ("priority", RoutingStrategy::Failover),
    // "Send a share of the traffic proportional to each target's weight." The
    // gateway's `round_robin` is smooth weighted round-robin, whose long-run
    // share is exactly that. Divergence, stated rather than hidden: the
    // template draws per request from `secureRandomFloat() * totalWeight`
    // (`open-sse/services/combo/targetSorters.ts::selectWeightedTarget`),
    // which is independent, while smooth WRR is a deterministic rotation. The
    // shares over time are the same; the per-request selection law is not, and
    // the template's `stickyWeightedLimit` knob has no equivalent here.
    ("weighted", RoutingStrategy::RoundRobin),
    // The same name for the same algorithm. The template's `stickyRoundRobinLimit`
    // is the one thing it adds, and this gateway spells stickiness as its own
    // strategy (`consistent_hash`) rather than a per-combo knob.
    ("round-robin", RoutingStrategy::RoundRobin),
    // The template's own branch for it preserves priority order and nothing
    // else (`open-sse/services/combo/applyStrategyOrdering.ts`, the
    // `fill-first` arm logs "preserving priority order" and leaves the list
    // untouched), so it is `failover` under a second name.
    ("fill-first", RoutingStrategy::Failover),
    // Cheapest resolved price first, ascending — the same rule the template
    // applies in `sortTargetsByCost`, against the same per-model price.
    ("cost-optimized", RoutingStrategy::LeastCost),
];

/// The template strategy names this gateway refuses, and why each one is a
/// refusal rather than a translation.
///
/// They are not omissions to be papered over with a nearby name. A
/// name-level mapping that changes which target serves a request is worse
/// than an honest 400, because the operator reads the dashboard, believes
/// they configured a policy, and gets a different one — the exact "configured
/// and does nothing" outcome this surface exists to prevent.
///
/// * **`random` / `strict-random` / `p2c`** are all *stochastic*: a shuffle, a
///   without-replacement deck, and a two-sample quality draw respectively.
///   Every strategy they could borrow here is deterministic — `round_robin`
///   rotates on a counter, `consistent_hash` pins a key to one target for as
///   long as it is healthy. Mapping a random pick onto a deterministic picker
///   is the dishonest swap in its purest form: the operator asked for
///   spreading traffic and gets stickiness, or vice versa.
/// * **`p2c`** is additionally not a load metric at all: the template scores
///   `success_rate + 1/log10(latency+10)` minus a breaker penalty
///   (`targetSorters.ts::getP2CTargetScore`), while `least_busy` ranks by
///   in-flight ÷ weight and `least_latency` by a latency EWMA. Neither is the
///   score p2c computes, and neither keeps the randomization that makes p2c
///   avoid herding on the global-minimum target.
/// * **`least-used`** counts requests *cumulatively, for the life of the
///   combo* (`sortTargetsByUsage` over `metrics.byTarget[].requests`). The
///   gateway tracks no such counter — `least_busy` reads the instantaneous
///   in-flight gauge (`ModelRuntimeStatusTracker::in_flight`). A target that
///   served a million requests an hour ago reads as idle, which is the
///   opposite of what the name claims.
/// * **`headroom`** is remaining *rate-limit* budget:
///   `1 − max(util_5h, util_7d)` over plan-window saturation
///   (`open-sse/services/combo/headroomRanking.ts`). `least_busy` measures
///   concurrent requests. "Most free capacity" and "fewest in flight" are
///   different signals, and only one of them is a queue depth.
/// * **`context-relay`** *transfers* a conversation across a failover: it
///   selects message history, summarizes it through a handoff model, and
///   injects the summary into the new target
///   (`open-sse/services/contextHandoff.ts`). `consistent_hash` sidesteps the
///   problem instead of solving it, by pinning the session so there is no
///   handoff — promising a relay and delivering a pin is a lie about the
///   mechanism, and the handoff config (`handoffModel`,
///   `handoffThreshold`, `maxMessagesForSummary`, `relayMode`) would be
///   accepted-and-ignored.
/// * **`reset-aware` / `reset-window` / `quota-weighted`** order by live quota
///   state per connection — reset timestamps, plan-window saturation, quota
///   share in flight (`open-sse/services/combo/quotaStrategies.ts`). The
///   gateway's targets are models, and it holds no per-connection quota
///   snapshot to order them by.
/// * **`auto`** is a 16-factor scorer that picks one of `rules`/`score`/
///   `cost`/`eco`/`latency`/`fast`/`sla-aware`/`sla`/`lkgp` per request
///   (`open-sse/services/autoCombo/`, `resolveAutoStrategy.ts`). It is a
///   strategy *chooser*, not a strategy; accepting it would mean accepting
///   nine more names behind it, or silently picking one.
/// * **`lkgp`** promotes the last-known-good *provider+connection*
///   (`getLKGP` in `@/lib/db/settings`). This gateway has no provider accounts
///   to remember a good one from — its targets are models, and "last known
///   good" is a fact about a credential this surface does not hold.
/// * **`context-optimized`** orders by the target's *context limit*,
///   largest first (`sortTargetsByContextSize`).
/// * **`cache-optimized`** pins a target by prompt-cache affinity so a
///   repeated prefix stays on one upstream (`promptCacheAffinity.ts`).
///   `consistent_hash` pins by the request's hash key, which is the wrong
///   key: a cache key is the prompt, a routing key is the caller's session.
/// * **`fusion`** fans out to a panel in parallel and has a *judge model*
///   synthesize one answer (`open-sse/services/fusion.ts`); it is the
///   ensemble shape, not a target-selection order.
/// * **`pipeline`** is a multi-step DAG where each step may name a different
///   model (`dispatchPrelude.ts:587`) — a request shape, not a strategy.
///
/// Every one of these is refused **by name** through [`read_strategy`], so the
/// caller is told which value was rejected and what is accepted instead.
const REFUSED_TEMPLATE_STRATEGIES: &[&str] = &[
    "cache-optimized",
    "context-optimized",
    "context-relay",
    "fusion",
    "headroom",
    "least-used",
    "lkgp",
    "pipeline",
    "p2c",
    "quota-weighted",
    "random",
    "reset-aware",
    "reset-window",
    "strict-random",
    "auto",
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
///
/// Two spellings are accepted, and they mean different things to the caller:
///
/// * the gateway's own ([`SUPPORTED_STRATEGIES`]) — what a stored routing
///   model carries, and what a `GET` response hands back, so a view read
///   from this surface patches straight back in;
/// * a combo-template name ([`TEMPLATE_STRATEGIES`]) — the vocabulary an
///   operator picks from in a dashboard. It is **translated on the way in**
///   and the routing model stores the gateway spelling, because the
///   template's name is not a strategy this gateway implements and the
///   persisted file has to load back through the file source, which only
///   knows the gateway's six.
///
/// So `{"strategy": "priority"}` is accepted, dispatched as `failover`, and
/// reads back as `failover`. The response is the stored truth; a caller
/// that needs the name it sent should remember it, because the combo view
/// reports what the combo *is*, not what it was asked for.
///
/// Anything else is refused by name — see [`REFUSED_TEMPLATE_STRATEGIES`]
/// for why each remaining template strategy is a refusal rather than a
/// translation.
fn read_strategy(value: Option<&Value>) -> Result<Value, AdminError> {
    let Some(value) = value else {
        return Ok(gateway_spelling(RoutingStrategy::default()));
    };
    let Value::String(name) = value else {
        return Err(AdminError::BadRequest("`strategy` must be a string".into()));
    };
    let strategy = match serde_json::from_value::<RoutingStrategy>(value.clone()) {
        Ok(strategy) => strategy,
        Err(_) => *TEMPLATE_STRATEGIES
            .iter()
            .find(|(template, _)| *template == name.as_str())
            .map(|(_, strategy)| strategy)
            .ok_or_else(|| refuse_strategy(name))?,
    };
    Ok(gateway_spelling(strategy))
}

/// The stored spelling of a strategy — the one the routing model and the
/// resources file both use. Infallible for a fieldless enum; the expect
/// names the invariant rather than papering over it, because the
/// alternative (`unwrap_or(Value::Null)`) would write a `null` strategy into
/// a model and fail later, somewhere that no longer knows why.
fn gateway_spelling(strategy: RoutingStrategy) -> Value {
    serde_json::to_value(strategy).expect("a fieldless enum always serialises")
}

/// The 400 for a strategy this gateway will not dispatch as.
///
/// Both halves of the truth are in it: what is accepted (with the template
/// names marked as translations, so a caller does not expect a `priority`
/// to read back as one), and what is deliberately not, so a caller who
/// picked a name from a longer list is told it is a refusal and not an
/// oversight. The rejected value is echoed back capped: it is caller-
/// supplied, and this string lands in the API response verbatim.
fn refuse_strategy(name: &str) -> AdminError {
    const MAX_ECHO_CHARS: usize = 64;
    let echo: String = name.chars().take(MAX_ECHO_CHARS).collect();
    let truncated = if name.chars().count() > MAX_ECHO_CHARS {
        format!("{echo}…")
    } else {
        echo
    };
    let templates = TEMPLATE_STRATEGIES
        .iter()
        .map(|(template, _)| *template)
        .collect::<Vec<_>>()
        .join(", ");
    let refused = REFUSED_TEMPLATE_STRATEGIES.join(", ");
    AdminError::BadRequest(format!(
        "{truncated:?} is not a routing strategy. Supported strategies: {}. \
         Template names accepted as translations of those: {templates}. \
         Not implemented, and refused rather than mapped onto a different one: {refused}.",
        SUPPORTED_STRATEGIES.join(", ")
    ))
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
