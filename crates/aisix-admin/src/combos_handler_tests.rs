//! Unit tests for [`crate::combos_handler`] — the combo write path.
//!
//! Driven through the handlers directly rather than through a router: the
//! router wiring is a one-line-per-route change in `build_router`, while
//! what these pin is the behaviour that wiring cannot supply — the strict
//! schema as the field gate, the fields this gateway refuses by name, the
//! 404/409 answers, the reference check, and the fact that the file this
//! handler leaves behind loads back through the file source.
//!
//! Two of these are written to be mutation-checked, because each one pins a
//! decision that is invisible in the happy path:
//!
//! - `a_combo_round_trips_through_its_own_get_view` fails the moment the
//!   view emits a field the write path rejects.
//! - `every_strategy_the_model_schema_publishes_is_accepted` fails the
//!   moment a strategy is added to the routing model without being listed
//!   in the rejection message.
//!
//! The strategy-vocabulary block is written the same way. It has two
//! vocabularies on the wire (the gateway's own six and the combo
//! template's twenty) and one stored value, and every way that can go
//! wrong is silent: a mapping pointed at the wrong strategy, a template
//! name stored verbatim into a file the loader refuses, a refused name
//! quietly accepted, a template name nobody classified. So
//! `the_two_strategy_vocabularies_partition_the_template_list` is a census —
//! it fails when a template strategy is neither honoured nor refused, or
//! both — and
//! `an_honoured_template_strategy_is_stored_as_the_strategy_that_implements_it`
//! drives each accepted name end to end through the persisted file.

use crate::auth::AdminAuth;
use crate::combos_handler::{
    create_combo, delete_combo, get_combo, list_combos, render_resources_document, update_combo,
    REFUSED_TEMPLATE_STRATEGIES, SUPPORTED_STRATEGIES, TEMPLATE_STRATEGIES,
};
use crate::error::AdminError;
use crate::state::AdminState;
use aisix_core::filesource::load_from_str;
use aisix_core::resource::ResourceEntry;
use aisix_core::snapshot::SnapshotHandle;
use aisix_core::{AdminConfig, AisixSnapshot, Model, RoutingStrategy};
use axum::body::to_bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::TempDir;

fn cfg() -> AdminConfig {
    AdminConfig {
        enabled: true,
        addr: "127.0.0.1:0".into(),
        admin_keys: vec!["admin-secret".into()],
        tls: None,
    }
}

/// An `AdminState` whose durable target is a file inside a fresh temp
/// directory, so no test can touch a real `resources.yaml`, pre-loaded with
/// the direct models a combo has to point at.
fn state_in(dir: &TempDir) -> AdminState {
    let handle = SnapshotHandle::new(AisixSnapshot::new());
    seed_direct_models(&handle);
    AdminState::new(
        handle,
        crate::store::InMemoryStore::new() as Arc<dyn crate::store::ConfigStore>,
        &cfg(),
    )
    .with_resources_file(Some(dir.path().join("resources.yaml")))
}

fn direct_model(display_name: &str) -> Model {
    serde_json::from_value(json!({
        "display_name": display_name,
        "provider": "openai",
        "model_name": "gpt-4o",
        "provider_key_id": provider_key_id(),
    }))
    .unwrap()
}

/// The provider key the seeded direct models dispatch with. A resources
/// file has to declare it beside them, so the snapshot carries it too and
/// the document this handler renders is one a reload accepts.
const PROVIDER_KEY: &str = "pk";

fn provider_key_id() -> String {
    aisix_core::filesource::derive_id("provider_keys", PROVIDER_KEY)
}

/// Two direct models, `alpha` and `beta`, for a combo to route across.
fn seed_direct_models(handle: &SnapshotHandle<AisixSnapshot>) {
    let snapshot = handle.load();
    let pk: aisix_core::ProviderKey =
        serde_json::from_value(json!({"display_name": PROVIDER_KEY, "api_key": "sk-test"}))
            .unwrap();
    snapshot
        .provider_keys
        .insert(ResourceEntry::new(provider_key_id(), pk, 1));
    for name in ["alpha", "beta"] {
        snapshot.models.insert(ResourceEntry::new(
            aisix_core::filesource::derive_id("models", name),
            direct_model(name),
            1,
        ));
    }
}

async fn body_json(resp: Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Run a handler and return `(status, body)` for both the response and the
/// error arm — the admin error type renders itself, so a `?`-propagated
/// failure is observable exactly like a returned response.
async fn settled(result: Result<Response, AdminError>) -> (StatusCode, Value) {
    let resp = match result {
        Ok(resp) => resp,
        Err(err) => err.into_response(),
    };
    let status = resp.status();
    (status, body_json(resp).await)
}

fn combo_body(name: &str) -> String {
    json!({
        "name": name,
        "strategy": "round_robin",
        "models": [{"model": "alpha", "weight": 3}, {"model": "beta"}],
    })
    .to_string()
}

async fn create(state: &AdminState, body: String) -> (StatusCode, Value) {
    settled(create_combo(AdminAuth, State(state.clone()), body).await).await
}

async fn patch(state: &AdminState, id: &str, body: String) -> (StatusCode, Value) {
    settled(
        update_combo(
            AdminAuth,
            State(state.clone()),
            AxumPath(id.to_string()),
            body,
        )
        .await,
    )
    .await
}

async fn remove(state: &AdminState, id: &str) -> (StatusCode, Value) {
    settled(delete_combo(AdminAuth, State(state.clone()), AxumPath(id.to_string())).await).await
}

// ── create ───────────────────────────────────────────────────────────

#[tokio::test]
async fn create_publishes_a_routing_model_and_answers_201() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(&state, combo_body("fast-coding")).await;
    assert_eq!(status, StatusCode::CREATED, "create failed: {body}");
    // The id is the file source's own derivation, so a reload reproduces
    // it — an id invented here would fork the two apart.
    let id = aisix_core::filesource::derive_id("models", "fast-coding");
    assert_eq!(body["id"], id.as_str());
    assert_eq!(body["combo"]["name"], "fast-coding");
    assert_eq!(body["combo"]["strategy"], "round_robin");

    // The published row is a real routing model, not a side table: it is
    // in the `models` collection dispatch resolves from, carrying the
    // targets the request asked for.
    let published = state.snapshot.load();
    let stored = published
        .models
        .get_by_id(&id)
        .expect("the combo must be visible to the serving snapshot");
    let routing = stored
        .value
        .routing
        .as_ref()
        .expect("a combo is a routing model");
    assert_eq!(routing.strategy, RoutingStrategy::RoundRobin);
    assert_eq!(routing.targets.len(), 2);
    assert_eq!(routing.targets[0].model, "alpha");
    assert_eq!(routing.targets[0].weight, Some(3));
    // The direct upstream fields stay absent: the model schema's oneOf
    // forbids a document carrying both `routing` and `provider`.
    assert!(stored.value.provider.is_none());
    assert!(stored.value.model_name.is_none());

    // The seeded direct models are untouched.
    assert_eq!(published.models.len(), 3);
}

#[tokio::test]
async fn create_defaults_the_strategy_to_failover() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(
        &state,
        json!({"name": "plain", "models": [{"model": "alpha"}]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["combo"]["strategy"], "failover");
}

#[tokio::test]
async fn a_target_naming_a_model_by_id_is_refused() {
    // The durable target of this surface is the declarative resources file,
    // which resolves a routing target by name and rejects `model_id`
    // outright — a control-plane reference style with no file equivalent.
    // Accepting it would validate here and leave a file no reload accepts.
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let beta_id = aisix_core::filesource::derive_id("models", "beta");

    let (status, body) = create(
        &state,
        json!({"name": "by-id", "models": [{"model_id": beta_id}]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(body["error_msg"].as_str().unwrap().contains("model_id"));
    assert_eq!(state.snapshot.load().models.len(), 2);
}

#[tokio::test]
async fn create_accepts_a_bare_model_name_string_as_a_target() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(
        &state,
        json!({"name": "shorthand", "models": ["alpha"]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["combo"]["models"][0]["model"], "alpha");
}

#[tokio::test]
async fn create_rejects_a_second_model_with_the_same_name() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    assert_eq!(
        create(&state, combo_body("dup")).await.0,
        StatusCode::CREATED
    );
    // The id is derived from the name, so a same-name create contends for
    // one row rather than adding a second.
    let (status, body) = create(&state, combo_body("dup")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error_msg"]
        .as_str()
        .unwrap()
        .contains("already exists"));
    // Two seeded direct models plus the one combo that got through.
    assert_eq!(state.snapshot.load().models.len(), 3);
}

// ── the fields this gateway does not model ───────────────────────────

/// The whole point of the surface: a combo document field with no home on a
/// routing model is refused BY NAME, not accepted and dropped. Each case is
/// checked individually so a regression names the field that came back.
#[tokio::test]
async fn combo_fields_outside_the_contract_are_rejected_by_name() {
    for field in [
        "description",
        "displayName",
        "config",
        "allowedProviders",
        "allowedModelFamilies",
        "system_message",
        "tool_filter_regex",
        "context_cache_protection",
        "context_length",
        "dimensions",
        "isActive",
        "isHidden",
    ] {
        let dir = TempDir::new().unwrap();
        let state = state_in(&dir);
        let mut document = json!({"name": "c", "models": [{"model": "alpha"}]});
        document
            .as_object_mut()
            .unwrap()
            .insert(field.to_string(), json!("x"));

        let (status, body) = create(&state, document.to_string()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{field} must be refused, not silently dropped"
        );
        let message = body["error_msg"].as_str().unwrap();
        assert!(
            message.contains(field),
            "the rejection must name {field}, got: {message}"
        );
        // Nothing was published: accepted-but-unread config reads on a
        // dashboard as "configured" and does nothing.
        assert_eq!(state.snapshot.load().models.len(), 2);
    }
}

#[tokio::test]
async fn combo_model_fields_outside_the_contract_are_rejected_by_name() {
    for field in [
        "label",
        "connectionId",
        "allowedConnectionIds",
        "prompt",
        "fallbackOnlyOnQuotaExhaustion",
        "kind",
    ] {
        let dir = TempDir::new().unwrap();
        let state = state_in(&dir);
        let mut entry = json!({"model": "alpha"});
        entry
            .as_object_mut()
            .unwrap()
            .insert(field.to_string(), json!("x"));

        let (status, body) =
            create(&state, json!({"name": "c", "models": [entry]}).to_string()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "models[0].{field} must be refused, not silently dropped"
        );
        assert!(
            body["error_msg"].as_str().unwrap().contains(field),
            "the rejection must name {field}"
        );
        assert_eq!(state.snapshot.load().models.len(), 2);
    }
}

#[tokio::test]
async fn a_combo_ref_step_is_refused_rather_than_nested() {
    // A virtual target would nest routing groups, and the dispatch path has
    // no cycle guard — so a group reachable from itself must not be storable.
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(
        &state,
        json!({
            "name": "nested",
            "models": [{"kind": "combo-ref", "comboName": "alpha"}],
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let message = body["error_msg"].as_str().unwrap();
    assert!(
        message.contains("kind") || message.contains("comboName"),
        "the refusal must name an offending field: {message}"
    );
    assert_eq!(state.snapshot.load().models.len(), 2);
}

// ── the two validation gates ─────────────────────────────────────────

#[tokio::test]
async fn create_rejects_a_target_that_is_not_a_direct_model() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    // Stand a routing model up directly in the snapshot, so a combo can aim
    // at it.
    let outer = aisix_core::filesource::derive_id("models", "outer");
    state.snapshot.load().models.insert(ResourceEntry::new(
        outer.clone(),
        serde_json::from_value(json!({
            "display_name": "outer",
            "routing": {"targets": [{"model": "alpha"}]},
        }))
        .unwrap(),
        1,
    ));

    let (status, body) = create(
        &state,
        json!({"name": "c", "models": [{"model": "outer"}]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error_msg"]
        .as_str()
        .unwrap()
        .contains("virtual model"));
    // The same rule by id.
    let (status, body) = create(
        &state,
        json!({"name": "c2", "models": [{"model": "outer"}]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert!(body["error_msg"]
        .as_str()
        .unwrap()
        .contains("virtual model"));
}

#[tokio::test]
async fn create_rejects_a_target_naming_no_model_at_all() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(
        &state,
        json!({"name": "c", "models": [{"model": "nope"}]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error_msg"]
        .as_str()
        .unwrap()
        .contains("not in the current configuration"));
}

#[tokio::test]
async fn create_rejects_a_body_with_no_name_or_no_models() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    for body in [
        json!({"models": [{"model": "alpha"}]}),
        json!({"name": "c"}),
        json!({"name": "c", "models": []}),
        json!({"name": "  ", "models": [{"model": "alpha"}]}),
        json!({"name": "c", "models": [{}]}),
    ] {
        let (status, _) = create(&state, body.to_string()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "body {body} must be refused"
        );
    }
    assert_eq!(state.snapshot.load().models.len(), 2);
}

#[tokio::test]
async fn create_rejects_a_duplicate_target() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(
        &state,
        json!({"name": "c", "models": [{"model": "alpha"}, {"model": "alpha"}]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error_msg"].as_str().unwrap().contains("once"));
}

#[tokio::test]
async fn create_rejects_an_unsupported_strategy() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(
        &state,
        json!({"name": "c", "strategy": "fusion", "models": [{"model": "alpha"}]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    // The message must both name what was refused and say what is allowed,
    // so a caller can correct the call without reading the source.
    let message = body["error_msg"].as_str().unwrap();
    assert!(message.contains("fusion"));
    for supported in SUPPORTED_STRATEGIES {
        assert!(
            message.contains(supported),
            "message omits {supported}: {message}"
        );
    }
}

// ── update ───────────────────────────────────────────────────────────

#[tokio::test]
async fn patch_merges_onto_the_stored_model_and_keeps_unrelated_fields() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let id = aisix_core::filesource::derive_id("models", "c");
    assert_eq!(create(&state, combo_body("c")).await.0, StatusCode::CREATED);

    // A resources-file write puts per-model fields on the same row that the
    // combo contract never names. A patch that rebuilt the row from the
    // combo view would drop every one of them.
    let mut decorated = state
        .snapshot
        .load()
        .models
        .get_by_id(&id)
        .unwrap()
        .value
        .clone();
    decorated.timeout = Some(42);
    decorated.rate_limit = serde_json::from_value(json!({"requests_per_minute": 10})).ok();
    state
        .snapshot
        .load()
        .models
        .insert(ResourceEntry::new(id.clone(), decorated, 1));

    let (status, body) = patch(&state, &id, json!({"strategy": "failover"}).to_string()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["combo"]["strategy"], "failover");

    let stored = state
        .snapshot
        .load()
        .models
        .get_by_id(&id)
        .unwrap()
        .value
        .clone();
    assert_eq!(stored.timeout, Some(42));
    assert!(stored.rate_limit.is_some());
    // And the untouched part of the contract survives too.
    assert_eq!(stored.routing.as_ref().unwrap().targets.len(), 2);
}

#[tokio::test]
async fn patch_renames_a_combo_and_rejects_a_collision() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let id = aisix_core::filesource::derive_id("models", "c");
    assert_eq!(create(&state, combo_body("c")).await.0, StatusCode::CREATED);
    assert_eq!(
        create(&state, combo_body("other")).await.0,
        StatusCode::CREATED
    );

    // `other` exists, so renaming onto it is a conflict, not a silent
    // takeover. `alpha` is a seeded direct model — also a conflict.
    for taken in ["other", "alpha"] {
        let (status, _) = patch(&state, &id, json!({"name": taken}).to_string()).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "rename onto {taken} must conflict"
        );
    }
    // Renaming onto itself is not a conflict.
    let (status, body) = patch(&state, &id, json!({"name": "c2"}).to_string()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["combo"]["name"], "c2");
}

#[tokio::test]
async fn patch_replaces_the_target_list_wholesale() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let id = aisix_core::filesource::derive_id("models", "c");
    assert_eq!(create(&state, combo_body("c")).await.0, StatusCode::CREATED);

    let (status, body) = patch(
        &state,
        &id,
        json!({"models": [{"model": "beta", "priority": 5, "tags": ["bulk"]}]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["combo"]["models"].as_array().unwrap().len(), 1);

    let routing = state
        .snapshot
        .load()
        .models
        .get_by_id(&id)
        .unwrap()
        .value
        .routing
        .clone()
        .unwrap();
    assert_eq!(routing.targets.len(), 1);
    assert_eq!(routing.targets[0].priority, Some(5));
    assert_eq!(
        routing.targets[0].tags.as_deref(),
        Some(&["bulk".to_string()][..])
    );
}

#[tokio::test]
async fn patch_of_an_unknown_id_is_404_and_leaves_the_row_alone() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    assert_eq!(create(&state, combo_body("c")).await.0, StatusCode::CREATED);

    let (status, _) = patch(&state, "no-such-id", json!({"name": "x"}).to_string()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(state.snapshot.load().models.get_by_name("c").is_some());
}

#[tokio::test]
async fn an_id_naming_a_direct_model_is_not_a_combo() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let alpha = aisix_core::filesource::derive_id("models", "alpha");

    // A 404 would read as "no such combo" and send a caller looking for a
    // typo; the row is there, it is simply the wrong kind of model.
    let (status, body) = patch(&state, &alpha, json!({"name": "x"}).to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error_msg"].as_str().unwrap().contains("not a combo"));

    let (status, _) = remove(&state, &alpha).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The direct model survives both attempts.
    assert!(state.snapshot.load().models.get_by_id(&alpha).is_some());
}

#[tokio::test]
async fn patch_rejects_a_field_outside_the_contract() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let id = aisix_core::filesource::derive_id("models", "c");
    assert_eq!(create(&state, combo_body("c")).await.0, StatusCode::CREATED);

    let (status, body) = patch(
        &state,
        &id,
        json!({"config": {"maxRetries": 2}}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error_msg"].as_str().unwrap().contains("config"));
}

// ── delete ───────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_removes_the_row_and_its_file() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let id = aisix_core::filesource::derive_id("models", "c");
    assert_eq!(create(&state, combo_body("c")).await.0, StatusCode::CREATED);

    let (status, body) = remove(&state, &id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "deleted");
    assert!(state.snapshot.load().models.get_by_id(&id).is_none());

    // And the seeded direct models are still there — only the combo went.
    assert_eq!(state.snapshot.load().models.len(), 2);
    let written = std::fs::read_to_string(dir.path().join("resources.yaml")).unwrap();
    let reloaded =
        load_from_str(&written, "test", 1, &|name: &str| std::env::var(name).ok()).unwrap();
    assert!(reloaded.models.get_by_name("c").is_none());
    assert!(reloaded.models.get_by_name("alpha").is_some());
}

#[tokio::test]
async fn delete_is_refused_while_another_combo_targets_it() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let inner = aisix_core::filesource::derive_id("models", "inner");
    assert_eq!(
        create(&state, combo_body("inner")).await.0,
        StatusCode::CREATED
    );

    // The write path refuses a virtual target, so the referring combo is
    // put in place the way a resources file would: directly in the
    // snapshot. The delete guard is what has to notice it.
    let outer = aisix_core::filesource::derive_id("models", "outer");
    let outer_model: Model = serde_json::from_value(json!({
        "display_name": "outer",
        "routing": {"strategy": "failover", "targets": [{"model": "inner"}]},
    }))
    .unwrap();
    state
        .snapshot
        .load()
        .models
        .insert(ResourceEntry::new(outer.clone(), outer_model, 1));

    let (status, body) = remove(&state, &inner).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error_msg"].as_str().unwrap().contains("outer"));
    assert!(state.snapshot.load().models.get_by_id(&inner).is_some());

    // Once the reference is gone the delete goes through.
    state.snapshot.load().models.remove(&outer);
    assert_eq!(remove(&state, &inner).await.0, StatusCode::OK);
}

#[tokio::test]
async fn delete_of_an_unknown_id_is_404() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    assert_eq!(remove(&state, "no-such-id").await.0, StatusCode::NOT_FOUND);
    // Nothing was written for a request that changed nothing.
    assert!(!dir.path().join("resources.yaml").exists());
}

// ── reads ────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_and_get_serve_only_combos() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    assert_eq!(
        create(&state, combo_body("zeta")).await.0,
        StatusCode::CREATED
    );
    assert_eq!(
        create(&state, combo_body("alpha-combo")).await.0,
        StatusCode::CREATED
    );

    let (status, body) = settled(
        list_combos(AdminAuth, State(state.clone()))
            .await
            .map(Json::into_response),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    // Both combos, in a stable order, and none of the direct models.
    assert_eq!(names, vec!["alpha-combo", "zeta"]);

    let id = aisix_core::filesource::derive_id("models", "zeta");
    let (status, body) = settled(
        get_combo(AdminAuth, State(state.clone()), AxumPath(id.clone()))
            .await
            .map(Json::into_response),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], id.as_str());
}

/// A `GET` response must be acceptable to the `PATCH` that follows it, or a
/// dashboard that round-trips a row cannot save it. This fails the moment
/// the view emits a field the write path rejects, or drops one the write
/// path needs.
#[tokio::test]
async fn a_combo_round_trips_through_its_own_get_view() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let id = aisix_core::filesource::derive_id("models", "rt");
    assert_eq!(
        create(
            &state,
            json!({
                "name": "rt",
                "strategy": "least_cost",
                "models": [
                    {"model": "alpha", "weight": 4, "priority": 1, "tags": ["cheap"]},
                    {"model": "beta", "tags": []}
                ],
            })
            .to_string(),
        )
        .await
        .0,
        StatusCode::CREATED
    );

    let (_, view) = settled(
        get_combo(AdminAuth, State(state.clone()), AxumPath(id.clone()))
            .await
            .map(Json::into_response),
    )
    .await;

    // Everything but the read-only identity is a legal patch body.
    let mut patch_body = view.clone();
    patch_body.as_object_mut().unwrap().remove("id");
    let (status, body) = patch(&state, &id, patch_body.to_string()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the view this surface emits must be accepted back: {body}"
    );

    // And the stored state is unchanged by the round trip.
    let (_, after) = settled(
        get_combo(AdminAuth, State(state.clone()), AxumPath(id))
            .await
            .map(Json::into_response),
    )
    .await;
    assert_eq!(after["models"], view["models"]);
    assert_eq!(after["strategy"], view["strategy"]);
}

/// The strategy list a rejection prints must be the strategy set the
/// routing model actually implements. Read out of the published model
/// schema, so adding a `RoutingStrategy` variant without listing it here
/// fails this rather than leaving a message that lies.
#[test]
fn every_strategy_the_model_schema_publishes_is_accepted() {
    let published = published_routing_strategies();

    let listed: std::collections::BTreeSet<String> = SUPPORTED_STRATEGIES
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        listed, published,
        "the strategy list in the rejection message has drifted from the routing model"
    );

    // And each one really parses, so the list is not merely equal to the
    // schema's but usable by the write path.
    for name in SUPPORTED_STRATEGIES {
        serde_json::from_value::<RoutingStrategy>(json!(name))
            .unwrap_or_else(|e| panic!("{name} is published but does not parse: {e}"));
    }
}

/// The six strategy spellings the routing model publishes, read out of the
/// model schema rather than restated — the same source the drift check
/// above uses, factored out so the alias table can be checked against it.
fn published_routing_strategies() -> std::collections::BTreeSet<String> {
    let schema = aisix_core::models::schema::resource_root_schema("model", true);
    schema["definitions"]["RoutingStrategy"]["oneOf"]
        .as_array()
        .expect("RoutingStrategy is a oneOf in the model schema")
        .iter()
        .filter_map(|branch| branch["enum"][0].as_str().map(str::to_string))
        .collect()
}

// ── strategy vocabularies ─────────────────────────────────────────────

/// The combo template's full strategy list, transcribed from
/// `omniroute/src/shared/constants/routingStrategies.ts` (`ROUTING_STRATEGY_VALUES`,
/// lines 1-22) on 2026-09-27. It is a literal here because the two repos
/// cannot read each other at build time; [`the_two_strategy_vocabularies_partition_the_template_list`]
/// is what keeps it honest, so a name the template adds fails this build
/// until it has been classified rather than being left unclassified by
/// omission.
///
/// Note the count is **20**, not the 19 the template's own `AGENTS.md` prose
/// lists: that prose omits `quota-weighted`, which the array does carry.
const TEMPLATE_STRATEGY_NAMES: &[&str] = &[
    "priority",
    "weighted",
    "round-robin",
    "context-relay",
    "fill-first",
    "p2c",
    "random",
    "least-used",
    "cost-optimized",
    "reset-aware",
    "reset-window",
    "headroom",
    "quota-weighted",
    "strict-random",
    "auto",
    "lkgp",
    "context-optimized",
    "cache-optimized",
    "fusion",
    "pipeline",
];

#[test]
fn the_two_strategy_vocabularies_partition_the_template_list() {
    let honoured: std::collections::BTreeSet<&str> =
        TEMPLATE_STRATEGIES.iter().map(|(name, _)| *name).collect();
    let refused: std::collections::BTreeSet<&str> =
        REFUSED_TEMPLATE_STRATEGIES.iter().copied().collect();
    let published = published_routing_strategies();

    // Every template name is accounted for, exactly once. A name in neither
    // set would be refused by accident (as an unparseable value) rather than
    // by decision; a name in both would be accepted *and* advertised as
    // refused, which is the worst of the two.
    let classified: std::collections::BTreeSet<&str> = honoured.union(&refused).copied().collect();
    let template: std::collections::BTreeSet<&str> =
        TEMPLATE_STRATEGY_NAMES.iter().copied().collect();
    assert_eq!(
        classified, template,
        "every template strategy must be either honoured or refused by name; \
         a name in neither is refused by accident, and a name in both is \
         accepted while advertised as unsupported"
    );
    // Named separately from the equality above, because it is the property
    // that matters most: a name in both sets would be accepted on the write
    // path while the message advertised it as unsupported. (The equality
    // implies it too — a name in both collapses the union below the template
    // set — but the property is worth stating in its own right rather than
    // leaving the reader to derive it.)
    assert!(
        honoured.is_disjoint(&refused),
        "a name must be either honoured or refused, never both: \
         honoured={honoured:?} refused={refused:?}"
    );

    // Each honoured name dispatches as a strategy the model really
    // publishes — an alias pointing at a variant that does not exist would
    // validate here and fail on the request path.
    for (name, strategy) in TEMPLATE_STRATEGIES {
        let spelling = serde_json::to_value(strategy).unwrap();
        assert!(
            published.contains(spelling.as_str().unwrap_or_default()),
            "{name} maps to {spelling}, which the model schema does not publish"
        );
    }

    // And a template name never shadows a gateway spelling, so every
    // accepted string has exactly one meaning: the enum arm always wins,
    // and a name that were also an enum value would translate only on one
    // code path.
    for (name, _) in TEMPLATE_STRATEGIES {
        assert!(
            !published.contains(*name),
            "{name} is both a template alias and a published gateway spelling"
        );
    }
}

/// The mapping, restated as a literal.
///
/// [`an_honoured_template_strategy_is_stored_as_the_strategy_that_implements_it`]
/// checks the table is *applied*; it reads the expected value out of the
/// table, so on its own it cannot notice a table that maps a name to the
/// wrong strategy. This is the anchor that can: it is a second, independent
/// statement of what each template name is justified as, and it disagrees
/// with the table loudly if either is edited carelessly. Each pair carries
/// the reason in the comment beside it — a mapping that has to be defended
/// in prose on both sides is a mapping worth this much ceremony.
#[test]
fn the_honoured_mapping_is_the_one_the_semantics_justify() {
    let justified: &[(&str, &str)] = &[
        // "prefer the higher priority, fall through on failure"
        ("priority", "failover"),
        // "a share proportional to each target's weight" — and this
        // gateway's round_robin is smooth *weighted* round-robin.
        ("weighted", "round_robin"),
        ("round-robin", "round_robin"),
        // "keep filling in priority order" — the template's own fill-first
        // branch preserves priority order and does nothing else.
        ("fill-first", "failover"),
        // "cheapest first", ranked by resolved price.
        ("cost-optimized", "least_cost"),
    ];
    let actual: std::collections::BTreeMap<&str, String> = TEMPLATE_STRATEGIES
        .iter()
        .map(|(name, strategy)| {
            (
                *name,
                serde_json::to_value(strategy)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect();

    let expected: std::collections::BTreeMap<&str, String> = justified
        .iter()
        .map(|(name, spelling)| (*name, (*spelling).to_string()))
        .collect();
    assert_eq!(
        actual, expected,
        "the honoured mapping has drifted from the one justified in \
         TEMPLATE_STRATEGIES and in this file's comments; re-derive it from the \
         template's own semantics before changing it"
    );
}

/// The published Admin API spec is the reference a caller writes against, so
/// its `Combo.strategy` enum has to be the set the endpoint really accepts —
/// gateway spellings plus the template names translated onto them. A spec
/// that lists only the six would send every template name into a `400` that
/// the same deployment's own docs say is valid.
#[test]
fn the_published_combo_strategy_enum_is_the_accepted_set() {
    let spec: Value =
        serde_json::from_str(crate::openapi::merged_openapi()).expect("the merged spec parses");
    let published: std::collections::BTreeSet<String> = spec["components"]["schemas"]["Combo"]
        ["properties"]["strategy"]["enum"]
        .as_array()
        .expect("Combo.strategy publishes an enum")
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    let expected: std::collections::BTreeSet<String> = SUPPORTED_STRATEGIES
        .iter()
        .map(|s| (*s).to_string())
        .chain(
            TEMPLATE_STRATEGIES
                .iter()
                .map(|(name, _)| (*name).to_string()),
        )
        .collect();
    assert_eq!(
        published, expected,
        "the published Combo.strategy enum has drifted from what the endpoint accepts"
    );
}

/// A patch has to work on both vocabularies, and the refused names on both
/// paths — the two handlers each call `read_strategy`, and a name accepted
/// by `POST` but refused by `PATCH` (or the reverse) is a half-shipped
/// surface that only shows up on the update a customer makes second.
#[tokio::test]
async fn both_vocabularies_behave_identically_on_create_and_patch() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let id = aisix_core::filesource::derive_id("models", "c");
    assert_eq!(create(&state, combo_body("c")).await.0, StatusCode::CREATED);

    for (template, strategy) in TEMPLATE_STRATEGIES {
        let (status, body) = patch(&state, &id, json!({"strategy": template}).to_string()).await;
        assert_eq!(status, StatusCode::OK, "{template} must patch: {body}");
        let expected = serde_json::to_value(strategy).unwrap();
        assert_eq!(body["combo"]["strategy"], expected);
    }
    for refused in REFUSED_TEMPLATE_STRATEGIES {
        let (status, body) = patch(&state, &id, json!({"strategy": refused}).to_string()).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{refused} must be refused on patch too: {body}"
        );
        assert!(body["error_msg"].as_str().unwrap().contains(refused));
    }
}

/// The whole point of the two vocabularies: each honoured template name is
/// accepted **and stored as the strategy that implements it**, and the
/// stored model reports the gateway spelling — never the template name,
/// which the resources file would refuse to load back.
#[tokio::test]
async fn an_honoured_template_strategy_is_stored_as_the_strategy_that_implements_it() {
    for (index, (template, strategy)) in TEMPLATE_STRATEGIES.iter().enumerate() {
        let dir = TempDir::new().unwrap();
        let state = state_in(&dir);
        let name = format!("combo-{index}");

        let (status, body) = create(
            &state,
            json!({
                "name": name,
                "strategy": template,
                "models": [{"model": "alpha", "weight": 3}, {"model": "beta"}],
            })
            .to_string(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{template} must be accepted: {body}"
        );

        // The stored model dispatches as the mapped strategy — this is the
        // assertion that fails if a mapping is ever pointed at the wrong
        // variant.
        let id = aisix_core::filesource::derive_id("models", &name);
        let snapshot = state.snapshot.load();
        let stored = snapshot
            .models
            .get_by_id(&id)
            .expect("the combo must be published");
        let routing = stored
            .value
            .routing
            .as_ref()
            .expect("a combo is a routing model");
        assert_eq!(
            routing.strategy, *strategy,
            "{template} must dispatch as {strategy:?}, not as {:?}",
            routing.strategy
        );

        // And the view reports the gateway spelling, so what the caller is
        // shown is what the combo actually is.
        let expected = serde_json::to_value(strategy).unwrap();
        assert_eq!(
            body["combo"]["strategy"], expected,
            "{template} must read back as its gateway spelling"
        );

        // The persisted file is loadable, which is what forces the
        // translation: a stored `strategy: "priority"` would not be.
        let persisted = std::fs::read_to_string(dir.path().join("resources.yaml")).unwrap();
        assert!(
            !persisted.contains(&format!("\"{template}\"")),
            "{template} must not reach the resources file: {persisted}"
        );
        load_from_str(&persisted, "test", 1, &|n: &str| std::env::var(n).ok())
            .unwrap_or_else(|e| panic!("the file carrying {template} must load: {e:?}"));
    }
}

/// The crux of the mapping, pinned on its own: `weighted` is honest here
/// *because* this gateway's `round_robin` is smooth weighted round-robin.
/// The property that makes it honest is the proxy's, and it is pinned there
/// (`wrr_distribution_matches_weights_exactly`, `wrr_interleaves_rather_than_bursting`
/// in `crates/aisix-proxy/src/routing.rs`); what this asserts is that
/// `weighted` reaches that strategy rather than a plain unweighted cycle.
#[tokio::test]
async fn weighted_is_dispatched_as_weighted_round_robin_not_a_plain_cycle() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(
        &state,
        json!({
            "name": "weighted-pool",
            "strategy": "weighted",
            "models": [{"model": "alpha", "weight": 7}, {"model": "beta", "weight": 3}],
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body: {body}");

    let stored = state
        .snapshot
        .load()
        .models
        .get_by_id(&aisix_core::filesource::derive_id(
            "models",
            "weighted-pool",
        ))
        .unwrap()
        .value
        .routing
        .as_ref()
        .unwrap()
        .clone();
    assert_eq!(stored.strategy, RoutingStrategy::RoundRobin);
    // The weights the operator set have to survive the translation, or the
    // strategy is weighted over a set of ones.
    assert_eq!(stored.targets[0].weight, Some(7));
    assert_eq!(stored.targets[1].weight, Some(3));
}

/// Every refused name still 400s **by name**, and creates nothing. The
/// message has to name the rejected value or a caller picking from a
/// longer dashboard list cannot tell which of their inputs was the problem.
#[tokio::test]
async fn every_refused_template_strategy_is_rejected_by_name() {
    for template in REFUSED_TEMPLATE_STRATEGIES {
        let dir = TempDir::new().unwrap();
        let state = state_in(&dir);

        let (status, body) = create(
            &state,
            json!({
                "name": "refused",
                "strategy": template,
                "models": [{"model": "alpha"}],
            })
            .to_string(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{template} must be refused, not silently accepted: {body}"
        );
        let message = body["error_msg"].as_str().unwrap();
        assert!(
            message.contains(template),
            "the refusal must name {template}: {message}"
        );
        // Nothing was written: a refusal that still created a model would
        // leave a combo the operator believes is configured.
        assert_eq!(
            state.snapshot.load().models.len(),
            2,
            "{template} was written"
        );
        assert!(
            !dir.path().join("resources.yaml").exists(),
            "{template} persisted"
        );
    }
}

/// The refusal message is the only place a caller learns what *is*
/// supported, so it has to carry both halves truthfully: the gateway
/// spellings, the template names accepted as translations, and the refused
/// names. A list that omits the refused ones leaves a caller who picked one
/// from a dashboard list with nothing to act on.
#[tokio::test]
async fn the_refusal_message_names_what_is_accepted_and_what_is_refused() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(
        &state,
        json!({"name": "c", "strategy": "fusion", "models": [{"model": "alpha"}]}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    let message = body["error_msg"].as_str().unwrap();
    for supported in SUPPORTED_STRATEGIES {
        assert!(message.contains(supported), "omits {supported}: {message}");
    }
    for (template, _) in TEMPLATE_STRATEGIES {
        assert!(message.contains(template), "omits {template}: {message}");
    }
    for refused in REFUSED_TEMPLATE_STRATEGIES {
        assert!(message.contains(refused), "omits {refused}: {message}");
    }
}

/// A template name has to work on the update path too — the two entrypoints
/// share `read_strategy`, and a name that only creates is a name an operator
/// cannot change a combo to.
#[tokio::test]
async fn a_patch_accepts_a_template_strategy_name() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let id = aisix_core::filesource::derive_id("models", "c");
    assert_eq!(create(&state, combo_body("c")).await.0, StatusCode::CREATED);

    let (status, body) = patch(&state, &id, json!({"strategy": "priority"}).to_string()).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    // The response reports the stored strategy, not the one that was sent.
    assert_eq!(body["combo"]["strategy"], "failover");
    let stored = state
        .snapshot
        .load()
        .models
        .get_by_id(&id)
        .unwrap()
        .value
        .routing
        .as_ref()
        .unwrap()
        .clone();
    assert_eq!(stored.strategy, RoutingStrategy::Failover);
}

// ── durable file ─────────────────────────────────────────────────────

#[tokio::test]
async fn the_rendered_document_loads_back_into_the_same_rows() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    assert_eq!(create(&state, combo_body("c")).await.0, StatusCode::CREATED);

    let body = render_resources_document(&state.snapshot.load()).unwrap();
    let reloaded = load_from_str(&body, "test", 1, &|name: &str| std::env::var(name).ok()).unwrap();
    let stored = reloaded
        .models
        .get_by_name("c")
        .expect("the rendered document must reproduce the row");
    assert_eq!(stored.value.routing.as_ref().unwrap().targets.len(), 2);
}

#[tokio::test]
async fn a_write_into_a_file_holding_other_resources_is_refused() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    // An operator's real resources file carries more than models and
    // provider keys; a per-combo write cannot re-emit the rest, so it must
    // refuse rather than truncate their file.
    let target = dir.path().join("resources.yaml");
    std::fs::write(
        &target,
        r#"{"_format_version":"1","models":[{"display_name":"alpha","provider":"openai","model_name":"gpt-4o","provider_key":"k"}],"provider_keys":[{"display_name":"k","api_key":"sk-x"}],"cache_policies":[{"name":"c1","backend":"memory","ttl_seconds":60}]}"#,
    )
    .unwrap();

    let (status, body) = create(&state, combo_body("c")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {body}");
    assert!(body["error_msg"]
        .as_str()
        .unwrap()
        .contains("per-combo write"));
    // The operator's file is untouched.
    let after = std::fs::read_to_string(&target).unwrap();
    assert!(after.contains("cache_policies"));
    assert!(!after.contains("\"c\""));
}
