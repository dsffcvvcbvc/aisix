//! Unit tests for [`crate::keys_handler`] — the provider-key write path.
//!
//! Driven through the handlers directly rather than through a router: the
//! router wiring is a one-line-per-route change in `build_router`, while
//! what these pin is the behaviour that wiring cannot supply — the strict
//! schema as the field gate, the 404/409 answers, the reference check,
//! and the fact that the file this handler leaves behind loads back
//! through the file source.

use crate::auth::AdminAuth;
use crate::error::AdminError;
use crate::keys_handler::{
    create_provider_key, delete_provider_key, list_preset_providers, render_resources_document,
    update_provider_key,
};
use crate::state::AdminState;
use aisix_core::filesource::load_from_str;
use aisix_core::resource::ResourceEntry;
use aisix_core::snapshot::SnapshotHandle;
use aisix_core::{AdminConfig, AisixSnapshot, Model, PassthroughRoute, ProviderKey};
use axum::body::to_bytes;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
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
/// directory, so no test can touch a real `resources.yaml`.
fn state_in(dir: &TempDir) -> AdminState {
    let handle = SnapshotHandle::new(AisixSnapshot::new());
    AdminState::new(
        handle,
        crate::store::InMemoryStore::new() as Arc<dyn crate::store::ConfigStore>,
        &cfg(),
    )
    .with_resources_file(Some(dir.path().join("resources.yaml")))
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

fn key_body(name: &str) -> String {
    json!({"display_name": name, "api_key": "sk-test", "provider": "openai"}).to_string()
}

async fn create(state: &AdminState, body: String) -> (StatusCode, Value) {
    settled(create_provider_key(AdminAuth, State(state.clone()), body).await).await
}

async fn patch(state: &AdminState, id: &str, body: String) -> (StatusCode, Value) {
    settled(
        update_provider_key(
            AdminAuth,
            State(state.clone()),
            AxumPath(id.to_string()),
            body,
        )
        .await,
    )
    .await
}

async fn delete(state: &AdminState, id: &str) -> (StatusCode, Value) {
    settled(delete_provider_key(AdminAuth, State(state.clone()), AxumPath(id.to_string())).await)
        .await
}

#[tokio::test]
async fn create_publishes_the_row_and_answers_201() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(&state, key_body("openai-prod")).await;
    assert_eq!(status, StatusCode::CREATED);
    // The id is the file source's own derivation, so a reload reproduces
    // it — an id invented here would fork the two apart.
    assert_eq!(
        body["id"],
        aisix_core::filesource::derive_id("provider_keys", "openai-prod").as_str()
    );
    assert_eq!(body["value"]["display_name"], "openai-prod");
    // Emission is under the canonical spelling, never the former one.
    assert_eq!(body["value"]["api_key"], "sk-test");
    assert!(body["value"].get("secret").is_none());

    let published = state.snapshot.load();
    let stored = published
        .provider_keys
        .get_by_name("openai-prod")
        .expect("the key must be visible to the serving snapshot");
    assert_eq!(stored.value.api_key, "sk-test");
    // The read endpoint sees the same row, by id.
    assert!(published
        .provider_keys
        .get_by_id(body["id"].as_str().unwrap())
        .is_some());
}

#[tokio::test]
async fn create_rejects_a_body_that_is_not_a_provider_key() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    // The strict schema requires exactly one of `api_key` / `secret`, so a
    // document carrying neither is refused.
    let (status, _) = create(&state, json!({"display_name": "no-credential"}).to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Nothing was published and nothing was written.
    assert!(state.snapshot.load().provider_keys.is_empty());
    assert!(!dir.path().join("resources.yaml").exists());

    // Carrying both is refused too: serde maps the alias onto the same
    // field, so the document is ambiguous rather than one of them winning.
    let (status, _) = create(
        &state,
        json!({"display_name": "both", "api_key": "a", "secret": "b"}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(state.snapshot.load().provider_keys.is_empty());
}

/// The surfaced message must point at the field the caller has to fix, or
/// the 400 is unactionable.
#[tokio::test]
async fn a_validation_failure_names_the_offending_field() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(
        &state,
        json!({"display_name": "", "api_key": "sk-test"}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["error_msg"].as_str().unwrap_or_default();
    assert!(message.contains("display_name"), "got: {message}");
}

#[tokio::test]
async fn create_rejects_a_body_that_is_not_json() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    for body in ["", "not json at all", "[1,2,3]", "\"a string\""] {
        let (status, _) = create(&state, body.to_string()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body:?}");
    }
    assert!(state.snapshot.load().provider_keys.is_empty());
}

/// The strict schema is closed, so a field the model has no place for is
/// refused rather than accepted-and-dropped. This is the check that keeps
/// a caller from believing it set something the gateway never reads.
#[tokio::test]
async fn create_rejects_a_field_the_model_has_no_place_for() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, body) = create(
        &state,
        json!({
            "display_name": "with-enabled",
            "api_key": "sk-test",
            "enabled": true,
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error_msg"]
            .as_str()
            .unwrap_or_default()
            .contains("enabled"),
        "the error must name the field: {body}"
    );
}

#[tokio::test]
async fn create_refuses_a_duplicate_display_name() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    assert_eq!(create(&state, key_body("dup")).await.0, StatusCode::CREATED);
    let (status, body) = create(&state, key_body("dup")).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error_msg"]
        .as_str()
        .unwrap_or_default()
        .contains("dup"));
    assert_eq!(state.snapshot.load().provider_keys.len(), 1);
}

#[tokio::test]
async fn patch_applies_only_the_fields_it_was_sent() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let (_, created) = create(&state, key_body("rotate-me")).await;
    let id = created["id"].as_str().unwrap().to_string();

    let (status, body) = patch(
        &state,
        &id,
        json!({"display_name": "renamed", "api_base": "https://proxy.example/v1"}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"]["display_name"], "renamed");
    assert_eq!(body["value"]["api_base"], "https://proxy.example/v1");
    // Untouched fields keep the value the create stored, including the
    // default the model filled in — a PATCH is a merge, not a replace.
    assert_eq!(body["value"]["api_key"], "sk-test");
    assert_eq!(body["value"]["provider"], "openai");
    assert_eq!(
        body["value"]["strip_headers"],
        json!(["authorization", "cookie", "set-cookie", "x-api-key"])
    );

    // The rename is visible to the name index, and the id is unchanged.
    let published = state.snapshot.load();
    assert!(published.provider_keys.get_by_name("renamed").is_some());
    assert!(published.provider_keys.get_by_name("rotate-me").is_none());
    assert!(published.provider_keys.get_by_id(&id).is_some());
}

/// `null` clears an `Option` field, which is the only way to drop an
/// `api_base` through a merge-shaped PATCH.
#[tokio::test]
async fn patch_clears_an_option_field_with_null() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let (_, created) = create(
        &state,
        json!({
            "display_name": "with-base",
            "api_key": "sk-test",
            "api_base": "https://a.example/v1",
        })
        .to_string(),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();

    let (status, body) = patch(&state, &id, json!({"api_base": null}).to_string()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["value"].get("api_base").is_none(),
        "got: {}",
        body["value"]
    );
    assert_eq!(body["value"]["display_name"], "with-base");
}

#[tokio::test]
async fn patch_rejects_a_field_the_model_has_no_place_for() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let (_, created) = create(&state, key_body("no-enabled")).await;
    let id = created["id"].as_str().unwrap().to_string();

    let (status, _) = patch(&state, &id, json!({"enabled": false}).to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The rejected patch left the row alone.
    let stored = state
        .snapshot
        .load()
        .provider_keys
        .get_by_id(&id)
        .unwrap()
        .clone();
    assert_eq!(stored.value.display_name, "no-enabled");
}

#[tokio::test]
async fn patch_404_for_an_unknown_id() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, _) = patch(
        &state,
        "no-such-id",
        json!({"display_name": "x"}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A missing row is not a reason to create one.
    assert!(state.snapshot.load().provider_keys.is_empty());
}

#[tokio::test]
async fn patch_refuses_a_rename_onto_another_keys_name() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let (_, first) = create(&state, key_body("first")).await;
    let (_, second) = create(&state, key_body("second")).await;

    let (status, _) = patch(
        &state,
        second["id"].as_str().unwrap(),
        json!({"display_name": "first"}).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let published = state.snapshot.load();
    assert!(published
        .provider_keys
        .get_by_id(first["id"].as_str().unwrap())
        .is_some());
    assert_eq!(published.provider_keys.len(), 2);
}

#[tokio::test]
async fn delete_removes_the_row_and_answers_200() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let (_, created) = create(&state, key_body("doomed")).await;
    let id = created["id"].as_str().unwrap().to_string();

    let (status, body) = delete(&state, &id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "deleted");
    assert_eq!(body["id"], id.as_str());

    let published = state.snapshot.load();
    assert!(published.provider_keys.is_empty());
    // Both indices are cleared — a dangling name entry would resolve a
    // deleted row.
    assert!(published.provider_keys.get_by_id(&id).is_none());
    assert!(published.provider_keys.get_by_name("doomed").is_none());
}

#[tokio::test]
async fn delete_404_for_an_unknown_id() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);

    let (status, _) = delete(&state, "no-such-id").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_409_while_a_model_still_references_the_key() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let (_, created) = create(&state, key_body("shared")).await;
    let id = created["id"].as_str().unwrap().to_string();

    // A model naming the key, exactly as the loader would have stored it.
    let model: Model = serde_json::from_value(json!({
        "display_name": "my-gpt4",
        "provider": "openai",
        "model_name": "gpt-4o",
        "provider_key_id": id,
    }))
    .unwrap();
    state
        .snapshot
        .load()
        .models
        .insert(ResourceEntry::new("m-1", model, 1));

    let (status, body) = delete(&state, &id).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let message = body["error_msg"].as_str().unwrap_or_default();
    // The message names the blocker, so the operator knows what to remove.
    assert!(message.contains("my-gpt4"), "got: {message}");
    // Refused means untouched: the key is still there to keep dispatching.
    assert!(state.snapshot.load().provider_keys.get_by_id(&id).is_some());
}

#[tokio::test]
async fn delete_409_while_a_passthrough_route_still_references_the_key() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let (_, created) = create(&state, key_body("shared-by-route")).await;
    let id = created["id"].as_str().unwrap().to_string();

    let route: PassthroughRoute = serde_json::from_value(json!({
        "display_name": "vendor",
        "path_prefix": "/v1/vendor",
        "target_url": "https://vendor.example/v1",
        "provider_key_id": id,
    }))
    .unwrap();
    state
        .snapshot
        .load()
        .passthrough_routes
        .insert(ResourceEntry::new("pr-1", route, 1));

    let (status, body) = delete(&state, &id).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        body["error_msg"]
            .as_str()
            .unwrap_or_default()
            .contains("vendor"),
        "got: {body}"
    );
}

/// The delete clears once the reference is gone — the 409 is about the
/// current state, not a permanent block.
#[tokio::test]
async fn delete_succeeds_once_the_referencing_model_is_removed() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let (_, created) = create(&state, key_body("shared")).await;
    let id = created["id"].as_str().unwrap().to_string();

    let model: Model = serde_json::from_value(json!({
        "display_name": "my-gpt4",
        "provider": "openai",
        "model_name": "gpt-4o",
        "provider_key_id": id,
    }))
    .unwrap();
    let snapshot = state.snapshot.load();
    snapshot.models.insert(ResourceEntry::new("m-1", model, 1));
    assert_eq!(delete(&state, &id).await.0, StatusCode::CONFLICT);

    state.snapshot.load().models.remove("m-1");
    assert_eq!(delete(&state, &id).await.0, StatusCode::OK);
    assert!(state.snapshot.load().provider_keys.is_empty());
}

#[tokio::test]
async fn create_writes_the_configured_file_and_it_loads_back() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let target = dir.path().join("resources.yaml");

    assert_eq!(
        create(&state, key_body("persisted")).await.0,
        StatusCode::CREATED
    );
    assert!(target.exists(), "the write must land on resources_file");

    // The real proof: the file source's own loader reads the file this
    // handler wrote and yields the same row under the same id.
    let reloaded = aisix_core::filesource::load_resources_file(&target, 2).unwrap();
    let entry = reloaded
        .provider_keys
        .get_by_name("persisted")
        .expect("the persisted row must reload");
    assert_eq!(entry.value.api_key, "sk-test");
    assert_eq!(
        entry.id,
        aisix_core::filesource::derive_id("provider_keys", "persisted")
    );
    // The document is a whole file, not a bare row: the mandatory format
    // version is what makes the next reload accept it at all.
    let text = std::fs::read_to_string(&target).unwrap();
    assert!(text.contains("_format_version"), "got: {text}");
}

#[tokio::test]
async fn a_second_create_appends_to_the_same_file() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let target = dir.path().join("resources.yaml");

    assert_eq!(create(&state, key_body("one")).await.0, StatusCode::CREATED);
    assert_eq!(create(&state, key_body("two")).await.0, StatusCode::CREATED);

    let reloaded = aisix_core::filesource::load_resources_file(&target, 2).unwrap();
    assert_eq!(reloaded.provider_keys.len(), 2);
    assert!(reloaded.provider_keys.get_by_name("one").is_some());
    assert!(reloaded.provider_keys.get_by_name("two").is_some());
}

/// A patch and a delete must both reach the file — a write that only
/// landed in memory is a write the next reload silently undoes.
#[tokio::test]
async fn patch_and_delete_reach_the_file() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let target = dir.path().join("resources.yaml");

    let (_, keep) = create(&state, key_body("keep")).await;
    let (_, drop) = create(&state, key_body("drop")).await;

    assert_eq!(
        patch(
            &state,
            keep["id"].as_str().unwrap(),
            json!({"api_key": "sk-rotated"}).to_string()
        )
        .await
        .0,
        StatusCode::OK
    );
    let reloaded = aisix_core::filesource::load_resources_file(&target, 2).unwrap();
    assert_eq!(
        reloaded
            .provider_keys
            .get_by_name("keep")
            .unwrap()
            .value
            .api_key,
        "sk-rotated"
    );

    assert_eq!(
        delete(&state, drop["id"].as_str().unwrap()).await.0,
        StatusCode::OK
    );
    let reloaded = aisix_core::filesource::load_resources_file(&target, 3).unwrap();
    assert!(reloaded.provider_keys.get_by_name("drop").is_none());
    assert!(reloaded.provider_keys.get_by_name("keep").is_some());
}

/// The persist renders only the `provider_keys` collection, so a write
/// into a file that also declares models is refused rather than dropping
/// the operator's models on the floor.
#[tokio::test]
async fn a_write_into_a_file_holding_other_resources_is_refused_and_leaves_it_alone() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("resources.yaml");
    let operator_file = r#"{
      "_format_version": "1",
      "provider_keys": [{"display_name": "existing", "api_key": "sk-existing"}],
      "models": [{"display_name": "my-gpt4", "provider": "openai", "model_name": "gpt-4o",
                  "provider_key_id": "existing"}]
    }"#;
    std::fs::write(&target, operator_file).unwrap();

    let handle = SnapshotHandle::new(AisixSnapshot::new());
    let state = AdminState::new(
        handle,
        crate::store::InMemoryStore::new() as Arc<dyn crate::store::ConfigStore>,
        &cfg(),
    )
    .with_resources_file(Some(target.clone()));

    let (status, body) = create(&state, key_body("new-key")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let message = body["error_msg"].as_str().unwrap_or_default();
    assert!(
        message.contains("resources"),
        "the reason must be actionable: {message}"
    );
    // The file is byte-identical: a refused write loses nothing.
    assert_eq!(std::fs::read_to_string(&target).unwrap(), operator_file);
}

/// A file the source cannot load is not one this handler may overwrite
/// either — the operator has to see their own error first.
#[tokio::test]
async fn a_write_into_an_unloadable_file_is_refused() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("resources.yaml");
    let broken = "_format_version: \"1\"\nprovider_keys: not-a-list\n";
    std::fs::write(&target, broken).unwrap();

    let handle = SnapshotHandle::new(AisixSnapshot::new());
    let state = AdminState::new(
        handle,
        crate::store::InMemoryStore::new() as Arc<dyn crate::store::ConfigStore>,
        &cfg(),
    )
    .with_resources_file(Some(target.clone()));

    let (status, _) = create(&state, key_body("new-key")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), broken);
}

/// A 500 must not carry a filesystem path or an OS error string out to the
/// caller — the same posture `status_models_store_failure` takes on the
/// unauthenticated listener.
#[tokio::test]
async fn the_refusal_message_carries_no_internal_path() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("resources.yaml");
    std::fs::write(
        &target,
        r#"{"_format_version":"1","models":[{"display_name":"m","provider":"openai",
            "model_name":"g","provider_key_id":"x"}]}"#,
    )
    .unwrap();

    let handle = SnapshotHandle::new(AisixSnapshot::new());
    let state = AdminState::new(
        handle,
        crate::store::InMemoryStore::new() as Arc<dyn crate::store::ConfigStore>,
        &cfg(),
    )
    .with_resources_file(Some(target.clone()));

    let (_, body) = create(&state, key_body("k")).await;
    let message = body["error_msg"].as_str().unwrap_or_default();
    assert!(
        !message.contains(dir.path().to_str().unwrap()),
        "leaked: {message}"
    );
    assert!(!message.contains(".tmp"), "leaked: {message}");
    // Only the admin envelope — no OpenAI-style `error` object.
    assert!(body.get("error").is_none());
}

#[tokio::test]
async fn the_rendered_document_survives_the_file_source_round_trip() {
    // Pins the "JSON is a YAML 1.2 subset" claim the persist relies on,
    // independently of the handler: a document this module produces must
    // load through the same parser the reload uses.
    let snapshot = AisixSnapshot::new();
    for name in ["alpha", "beta"] {
        let key: ProviderKey =
            serde_json::from_value(json!({"display_name": name, "api_key": format!("sk-{name}")}))
                .unwrap();
        snapshot
            .provider_keys
            .insert(ResourceEntry::new(derive_id_for(name), key, 1));
    }
    let body = render_resources_document(&snapshot).unwrap();

    let env_lookup = |name: &str| std::env::var(name).ok();
    let loaded = load_from_str(&body, "test", 1, &env_lookup).unwrap();
    assert_eq!(loaded.provider_keys.len(), 2);
    assert_eq!(
        loaded
            .provider_keys
            .get_by_name("alpha")
            .unwrap()
            .value
            .api_key,
        "sk-alpha"
    );
    assert_eq!(
        loaded
            .provider_keys
            .get_by_name("beta")
            .unwrap()
            .value
            .api_key,
        "sk-beta"
    );
}

/// A key with every optional block set still round-trips: the renderer
/// must not drop a nested shape on the way to disk.
#[tokio::test]
async fn a_fully_populated_key_survives_the_round_trip() {
    let snapshot = AisixSnapshot::new();
    let key: ProviderKey = serde_json::from_value(json!({
        "display_name": "full",
        "api_key": "sk-full",
        "api_base": "https://vendor.example/v1",
        "project": "my-cloud-project",
        "provider": "deepseek",
        "adapter": "anthropic",
        "apis": {"messages": {"base": "https://vendor.example/anthropic"}},
        "telemetry_tags": {"kind": "catalog", "featured": true, "branded_provider": "deepseek"},
        "request": {"default_headers": {"X-Foo": "bar"}},
        "response": {"stream_done_marker": "required"},
        "strip_headers": ["x-aisix-trace"],
        "tls": {"verify": false},
        "resolve_addresses": ["10.1.2.3"],
    }))
    .unwrap();
    snapshot
        .provider_keys
        .insert(ResourceEntry::new(derive_id_for("full"), key.clone(), 1));

    let body = render_resources_document(&snapshot).unwrap();
    let env_lookup = |name: &str| std::env::var(name).ok();
    let loaded = load_from_str(&body, "test", 1, &env_lookup).unwrap();
    let back = loaded.provider_keys.get_by_name("full").unwrap();
    assert_eq!(&back.value, &key);
}

#[tokio::test]
async fn a_patch_that_renames_a_key_keeps_its_id() {
    let dir = TempDir::new().unwrap();
    let state = state_in(&dir);
    let (_, created) = create(&state, key_body("before")).await;
    let id = created["id"].as_str().unwrap().to_string();

    let (status, body) = patch(&state, &id, json!({"display_name": "after"}).to_string()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], id.as_str());
    assert_eq!(body["value"]["display_name"], "after");
    // Reachable by the id the caller already holds — a rename must not
    // force the dashboard to re-resolve the row.
    assert!(state.snapshot.load().provider_keys.get_by_id(&id).is_some());
}

fn derive_id_for(identity: &str) -> String {
    aisix_core::filesource::derive_id("provider_keys", identity)
}

#[tokio::test]
async fn preset_providers_serve_the_embedded_catalog_as_an_array() {
    let (status, body) = settled(
        list_preset_providers(AdminAuth)
            .await
            .map(IntoResponse::into_response),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().expect("the response must be an array");
    // The whole catalog, in the catalog's own order — this endpoint is a
    // read, so a row missing here is a row the dashboard cannot offer.
    assert_eq!(rows.len(), aisix_provider_openai::PRESET_PROVIDER_COUNT);
    assert!(rows.len() > 100, "a stub list would pass the shape check");

    // Spot the projection on a known entry rather than only the shape: an
    // array of `{}` would satisfy every assertion above.
    let openai = rows
        .iter()
        .find(|row| row["id"] == "openai")
        .expect("the catalog carries openai");
    assert_eq!(openai["display_name"], "OpenAI");
    assert_eq!(
        openai["base_url"],
        "https://api.openai.com/v1/chat/completions"
    );
    assert_eq!(openai["auth"], json!({"type": "bearer"}));
    assert_eq!(openai["headers"], json!([]));

    // And on entries that are not the default shape, so the non-bearer arm
    // is reached rather than dead — and a header name (never a value) is
    // what it carries.
    let header_auth: Vec<_> = rows
        .iter()
        .filter(|row| row["auth"]["type"] == "api_key_header")
        .collect();
    assert!(
        !header_auth.is_empty(),
        "the catalog has non-bearer vendors"
    );
    for row in header_auth {
        assert!(
            !row["auth"]["header"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
            "an api_key_header preset must name the header: {row}"
        );
    }
    let uc = rows
        .iter()
        .find(|row| row["id"] == "uc-direct")
        .expect("the catalog carries uc-direct");
    assert_eq!(
        uc["auth"],
        json!({"type": "api_key_header", "header": "x-api-key"})
    );

    // `maritalk`'s registry value `key` is an Authorization SCHEME, so it
    // must not be published as a header name. A client that read
    // `{"type":"api_key_header","header":"key"}` literally would put the
    // secret in a header the vendor never reads, and would have no way to
    // tell from the payload that `key` means something else.
    let maritalk = rows
        .iter()
        .find(|row| row["id"] == "maritalk")
        .expect("the catalog carries maritalk");
    assert_eq!(
        maritalk["auth"],
        json!({"type": "authorization_scheme", "scheme": "Key"})
    );
    let scheme_rows: Vec<_> = rows
        .iter()
        .filter(|row| row["auth"]["type"] == "authorization_scheme")
        .collect();
    assert!(
        !scheme_rows.is_empty(),
        "the non-Bearer Authorization-scheme arm is reached, not dead"
    );
    for row in scheme_rows {
        assert!(
            !row["auth"]["scheme"].as_str().unwrap_or_default().is_empty(),
            "an authorization_scheme preset must name the scheme: {row}"
        );
    }

    // A vendor that needs static headers projects them as name/value pairs.
    let with_headers = rows
        .iter()
        .find(|row| !row["headers"].as_array().unwrap().is_empty())
        .expect("the catalog carries vendors with required static headers");
    let first_header = &with_headers["headers"][0];
    assert!(first_header["name"].is_string());
    assert!(first_header["value"].is_string());
}

/// Asserted on the projection's FIELD names, not on the rendered text: a
/// vendor id legitimately contains the substring "token"
/// (`tokenrouter`), so a text scan would either false-positive here or
/// have to be weakened into meaninglessness. What must not exist is a
/// field that holds a credential.
#[tokio::test]
async fn the_preset_projection_carries_no_credential_field() {
    let (_, body) = settled(
        list_preset_providers(AdminAuth)
            .await
            .map(IntoResponse::into_response),
    )
    .await;

    for row in body.as_array().expect("an array") {
        let mut fields: Vec<&str> = row
            .as_object()
            .expect("a preset is an object")
            .keys()
            .map(String::as_str)
            .collect();
        // `serde_json::Map` iterates in sorted order here (no
        // `preserve_order`), so compare the set, not a sequence.
        fields.sort_unstable();
        assert_eq!(
            fields,
            ["auth", "base_url", "display_name", "headers", "id"],
            "{row}"
        );
        let mut auth_fields: Vec<&str> = row["auth"]
            .as_object()
            .expect("auth is an object")
            .keys()
            .map(String::as_str)
            .collect();
        auth_fields.sort_unstable();
        assert!(
            auth_fields == ["type"]
                || auth_fields == ["header", "type"]
                || auth_fields == ["scheme", "type"],
            "auth carries a shape, never a credential: {row}"
        );
    }
}
