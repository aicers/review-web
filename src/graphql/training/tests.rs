//! Resolver tests of the training definitions, model runs, and the model
//! lifecycle mutations.

use review_database::{
    EngineDetectorRef, EngineDocumentRefs, EngineDocumentWrite, ModelInstance, NodeUpdate,
    RunState, SamplingInterval, Store, TrainingDefinitionUpdate, types::ModelScores,
};
use serde_json::{Value, json};

use super::*;
use crate::graphql::{
    Role, TestSchema,
    model_test_support::{TestModel, data, insert_definition, insert_indicator, single_error},
    run_test_support::{
        Relay, RelayAnswer, RelayCall, insert_data_store_node, insert_engine_instance,
        insert_log_collector_node, insert_named_data_store_node, insert_sensor_node, relay_schema,
    },
    sampling_test_support::{
        PolicyShape, SENSOR_KEY, generator_config, insert_assigned_policy,
        insert_generator_node_with, insert_policy, sensor_name, timeseries_definition,
    },
};

const A: u32 = 1;
const B: u32 = 2;
const ENGINE_KEY: &str = "001.reconverge";
const STORE_HOST: &str = "store.example.com";
const STORE_B_HOST: &str = "store-b.example.com";
/// The address Data Store `STORE_HOST` publishes on.
const OWN_ADDRESS: &str = "10.0.0.5:38371";
/// The address Data Store `STORE_B_HOST` publishes on.
const OWN_ADDRESS_B: &str = "10.0.0.6:38371";
/// An address that is none of a Data Store's own.
const OVERRIDE: &str = "192.0.2.1:9999";

struct Fixture {
    schema: TestSchema,
    relay: Relay,
    engine_a: ModelInstance,
    engine_a2: ModelInstance,
    engine_b: ModelInstance,
    sensor_a: String,
    sensor_a2: String,
    sensor_b: String,
    logs_a: String,
    logs_b: String,
    server_name: String,
    server_name_b: String,
}

impl Fixture {
    fn store(&self) -> std::sync::RwLockReadGuard<'_, Store> {
        self.schema.store()
    }

    async fn sys(&self, query: &str) -> async_graphql::Response {
        self.schema.execute_as_system_admin(query).await
    }

    async fn sec(&self, query: &str, customers: &[u32]) -> async_graphql::Response {
        self.schema
            .execute_as_scoped_user(query, Role::SecurityAdministrator, Some(customers.to_vec()))
            .await
    }

    /// Returns a definition of customer A reading `sources` from the Data
    /// Store at `address`, with `extra` top-level lines.
    fn definition(&self, sources: &[&str], address: &str, extra: &str) -> String {
        definition_text(sources, &self.server_name, address, extra)
    }

    /// Inserts the definition `name` on `instance` as a System Administrator.
    async fn define(&self, instance: &ModelInstance, name: &str, definition: &str) {
        let res = self.sys(&insert(instance, name, definition)).await;
        assert_eq!(data(res), json!({ "insertTrainingDefinition": name }));
    }

    /// Trains the definition `name` and returns the run id.
    async fn train(&self, name: &str) -> RunId {
        let res = self.sys(&train(name)).await;
        run_id(&data(res)["trainModel"])
    }

    /// Trains the definition `name` to completion and returns the run id.
    async fn train_to_completion(&self, name: &str, instance: &ModelInstance) -> RunId {
        let run_id = self.train(name).await;
        complete(&self.store(), run_id, instance, name);
        run_id
    }

    fn run_state(&self, run_id: RunId) -> Option<RunState> {
        self.store().model_run(run_id).unwrap().map(|run| run.state)
    }
}

async fn fixture() -> Fixture {
    let (schema, relay) = relay_schema().await;
    relay.resolve(STORE_HOST, 1, &["10.0.0.5"]);
    relay.resolve(STORE_B_HOST, 1, &["10.0.0.6"]);
    let (engines, sensors, logs, server_names) = {
        let store = schema.store();
        (
            [
                insert_engine_instance(&store, A, "engine-a.example.com", ENGINE_KEY),
                insert_engine_instance(&store, A, "engine-a2.example.com", ENGINE_KEY),
                insert_engine_instance(&store, B, "engine-b.example.com", ENGINE_KEY),
            ],
            [
                insert_sensor_node(&store, A, "sensor-a.example.com"),
                insert_sensor_node(&store, A, "sensor-a2.example.com"),
                insert_sensor_node(&store, B, "sensor-b.example.com"),
            ],
            [
                insert_log_collector_node(&store, A, "logs-a.example.com"),
                insert_log_collector_node(&store, B, "logs-b.example.com"),
            ],
            [
                insert_data_store_node(&store, A, STORE_HOST),
                insert_data_store_node(&store, B, STORE_B_HOST),
            ],
        )
    };
    let [engine_a, engine_a2, engine_b] = engines;
    let [sensor_a, sensor_a2, sensor_b] = sensors;
    let [logs_a, logs_b] = logs;
    let [server_name, server_name_b] = server_names;
    Fixture {
        schema,
        relay,
        engine_a,
        engine_a2,
        engine_b,
        sensor_a,
        sensor_a2,
        sensor_b,
        logs_a,
        logs_b,
        server_name,
        server_name_b,
    }
}

fn definition_text(sources: &[&str], server_name: &str, address: &str, extra: &str) -> String {
    format!(
        r#"event_kind = "http"
method = "multidimension"
sources = {sources}
window_start = "2026-10-14T00:00:00Z"
window_end = "2026-10-21T00:00:00Z"
{extra}

[data_store]
address = "{address}"
server_name = "{server_name}"

[csv]
format = [{{ data_type = "utf8", weight = 1.0 }}]
"#,
        sources = serde_json::to_string(sources).unwrap(),
    )
}

/// Returns `text` as a GraphQL string literal.
fn gql(text: &str) -> String {
    serde_json::to_string(text).unwrap()
}

fn insert(instance: &ModelInstance, name: &str, definition: &str) -> String {
    format!(
        "mutation {{ insertTrainingDefinition(nodeId: \"{}\", agentKey: {}, name: {}, \
         definition: {}) }}",
        instance.node_id,
        gql(&instance.agent_key),
        gql(name),
        gql(definition)
    )
}

fn update(name: &str, definition: &str) -> String {
    format!(
        "mutation {{ updateTrainingDefinition(name: {}, definition: {}) }}",
        gql(name),
        gql(definition)
    )
}

fn remove_definition(name: &str) -> String {
    format!(
        "mutation {{ removeTrainingDefinition(name: {}) }}",
        gql(name)
    )
}

fn train(name: &str) -> String {
    format!("mutation {{ trainModel(name: {}) }}", gql(name))
}

fn cancel(run_id: &str) -> String {
    format!("mutation {{ cancelModelRun(runId: {}) }}", gql(run_id))
}

/// Returns a `cloneModel` of `source` into `target` on `instance` reading
/// `sources` from `server_name` at `address`; `tokens` is the
/// `suspiciousTokens` argument as written, or nothing.
fn clone(
    source: &str,
    target: &str,
    instance: &ModelInstance,
    (server_name, address): (&str, &str),
    sources: &[&str],
    tokens: &str,
) -> String {
    format!(
        "mutation {{ cloneModel(source: {}, targetName: {}, nodeId: \"{}\", agentKey: {}, \
         dataStore: {{ address: {}, serverName: {} }}, sources: {}{tokens}) }}",
        gql(source),
        gql(target),
        instance.node_id,
        gql(&instance.agent_key),
        gql(address),
        gql(server_name),
        serde_json::to_string(sources).unwrap(),
    )
}

fn remove_model(name: &str) -> String {
    format!("mutation {{ removeModel(name: {}) }}", gql(name))
}

fn assign(name: &str, instance: &ModelInstance) -> String {
    format!(
        "mutation {{ assignModel(name: {}, nodeId: \"{}\", agentKey: {}) }}",
        gql(name),
        instance.node_id,
        gql(&instance.agent_key)
    )
}

fn run_id(value: &Value) -> RunId {
    value
        .as_str()
        .expect("a run id is a string")
        .parse()
        .expect("a run id is a u32")
}

fn lookup_key(instance: &ModelInstance, hostname: &str) -> String {
    format!("{}.{hostname}", instance.agent_key)
}

/// Accepts the model upload of the run `run_id` that `instance` performs,
/// creating or replacing the multidimension model `name`.
fn complete(store: &Store, run_id: RunId, instance: &ModelInstance, name: &str) {
    complete_as(store, run_id, instance, name, ("Multifield", "http"));
}

/// Accepts the model upload of the run `run_id` that `instance` performs,
/// creating or replacing the model `name` of the record kind and event kind
/// `kinds`.
fn complete_as(
    store: &Store,
    run_id: RunId,
    instance: &ModelInstance,
    name: &str,
    (kind, event_kind): (&str, &str),
) {
    store
        .complete_run(
            run_id,
            instance,
            review_database::Model {
                id: 0,
                name: name.to_string(),
                version: 1,
                kind: kind.to_string(),
                serialized_classifier: vec![1, 2, 3],
                max_event_id_num: 25,
                event_kind: event_kind.to_string(),
                classification_id: 0,
                batch_info: vec![],
                scores: ModelScores::new(),
            },
        )
        .expect("complete the run");
}

/// Returns the code, `field` and `value` of the single refusal of `res`.
fn refused(res: &async_graphql::Response) -> (String, String, String) {
    let (_, extensions) = single_error(res);
    let text = |key: &str| match &extensions[key] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    (text("code"), text("field"), text("value"))
}

fn code(res: &async_graphql::Response) -> String {
    refused(res).0
}

fn forbidden(res: &async_graphql::Response) {
    let (message, _) = single_error(res);
    assert_eq!(message, "Forbidden", "{res:?}");
}

/// Reads the stored definition `name`.
fn stored(store: &Store, name: &str) -> Option<review_database::TrainingDefinition> {
    store.training_definition(name).unwrap()
}

/// Stores the text of the definition `name` directly, bypassing validation.
fn store_text(store: &Store, name: &str, text: &str) {
    let document = TrainingDocument::parse(text).expect("a parsable text");
    store
        .update_training_definition(
            name,
            TrainingDefinitionUpdate {
                method: document.method.into(),
                event_kind: document.event_kind.clone(),
                sources: document.sources.clone(),
                indicator: document.suspicious_tokens.clone(),
                definition: text.to_string(),
            },
        )
        .expect("update the stored definition");
}

/// Creates the model `name` of customer A on `instance` with no definition.
fn model_on(store: &Store, name: &str, customer_id: u32, instance: &ModelInstance) -> u32 {
    TestModel {
        instance: instance.clone(),
        ..TestModel::new(name, customer_id)
    }
    .replace(store)
}

/// Records that `instance`'s applied document names `model` under detector
/// `applied_id` and its pending document under `pending_id`.
fn name_in_documents(
    store: &Store,
    instance: &ModelInstance,
    model: &str,
    applied_id: i32,
    pending_id: Option<i32>,
) {
    let detector = |id| EngineDocumentRefs {
        detectors: vec![EngineDetectorRef {
            id,
            model: model.to_string(),
            sources: vec![],
            indicator: None,
        }],
    };
    let mut map = store.node_map();
    let (node, _, _) = map
        .get_by_id(instance.node_id)
        .expect("read engine node")
        .expect("engine node exists");
    let update = NodeUpdate::from(node);
    let document = EngineDocumentWrite {
        agent_key: instance.agent_key.clone(),
        applied: Some(detector(applied_id)),
        pending: pending_id.map(detector),
    };
    map.update_with_engine_documents(instance.node_id, &update, &update, &[document])
        .expect("write engine document references");
}

/// Removes the agent row of `instance` and detaches its records, leaving its
/// models and definitions with no instance.
fn uninstall(store: &Store, instance: &ModelInstance) {
    store
        .agents_map()
        .delete(instance.node_id, &instance.agent_key)
        .expect("delete the agent row");
    store
        .detach_engine_instance(instance, "removed")
        .expect("detach the instance");
}

/// Returns the models as a System Administrator reads their name, state and
/// instance.
async fn model_states(f: &Fixture) -> Value {
    let res = f
        .sys("{ models { edges { node { name state instance { nodeId } } } } }")
        .await;
    data(res)["models"]["edges"].clone()
}

/// Returns the state of the training definition `name`.
async fn definition_state(f: &Fixture, name: &str) -> Value {
    let res = f
        .sys(&format!(
            "{{ trainingDefinition(name: {}) {{ state }} }}",
            gql(name)
        ))
        .await;
    data(res)["trainingDefinition"]["state"].clone()
}

// ---------------------------------------------------------------------------
// insertTrainingDefinition and updateTrainingDefinition

#[tokio::test]
async fn insert_stores_the_parsed_fields_and_the_text() {
    let f = fixture().await;
    let model_id = model_on(&f.store(), "host", A, &f.engine_a);
    insert_indicator(&f.store(), "ind-a", model_id);
    let text = f.definition(
        &[&f.sensor_a, &f.logs_a],
        OWN_ADDRESS,
        "suspicious_tokens = \"ind-a\"",
    );
    let res = f.sec(&insert(&f.engine_a, "def", &text), &[A]).await;
    assert_eq!(data(res), json!({ "insertTrainingDefinition": "def" }));

    let definition = stored(&f.store(), "def").expect("stored");
    assert_eq!(definition.customer_id, A);
    assert_eq!(definition.instance.as_ref(), Some(&f.engine_a));
    assert_eq!(
        definition.method,
        review_database::ModelMethod::Multidimension
    );
    assert_eq!(definition.event_kind, "http");
    assert_eq!(definition.sources, [f.sensor_a.clone(), f.logs_a.clone()]);
    assert_eq!(definition.indicator.as_deref(), Some("ind-a"));
    assert_eq!(definition.definition, text);

    let res = f
        .sec(
            "{ trainingDefinition(name: \"def\") { name customerId instance { nodeId agentKey } \
             method eventKind sources suspiciousTokens definition state model { name } \
             activeRun { id } lastRun { id } } }",
            &[A],
        )
        .await;
    assert_eq!(
        data(res),
        json!({ "trainingDefinition": {
            "name": "def",
            "customerId": A.to_string(),
            "instance": { "nodeId": f.engine_a.node_id.to_string(), "agentKey": ENGINE_KEY },
            "method": "MULTIDIMENSION",
            "eventKind": "http",
            "sources": [f.sensor_a, f.logs_a],
            "suspiciousTokens": "ind-a",
            "definition": text,
            "state": "NEVER_TRAINED",
            "model": null,
            "activeRun": null,
            "lastRun": null,
        }})
    );
}

#[tokio::test]
async fn update_stores_the_parsed_fields_and_the_text() {
    let f = fixture().await;
    f.define(
        &f.engine_a,
        "def",
        &f.definition(&[&f.sensor_a], OWN_ADDRESS, ""),
    )
    .await;
    let model_id = model_on(&f.store(), "host", A, &f.engine_a);
    insert_indicator(&f.store(), "ind-a", model_id);
    let text = definition_text(&[&f.logs_a], &f.server_name, OWN_ADDRESS, "")
        .replace("event_kind = \"http\"", "event_kind = \"conn\"")
        .replace(
            "window_end = \"2026-10-21T00:00:00Z\"",
            "window_end = \"2026-10-21T00:00:00Z\"\nsuspicious_tokens = \"ind-a\"",
        );
    let res = f.sec(&update("def", &text), &[A]).await;
    assert_eq!(data(res), json!({ "updateTrainingDefinition": "def" }));

    let definition = stored(&f.store(), "def").expect("stored");
    assert_eq!(definition.event_kind, "conn");
    assert_eq!(definition.sources, std::slice::from_ref(&f.logs_a));
    assert_eq!(definition.indicator.as_deref(), Some("ind-a"));
    assert_eq!(definition.definition, text);
}

#[tokio::test]
async fn validation_refusals_carry_their_codes() {
    let f = fixture().await;
    let res = f
        .sec(&insert(&f.engine_a, "def", "method = \"prefix\""), &[A])
        .await;
    assert_eq!(code(&res), "INVALID_DOCUMENT");
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "name = \"def\"");
    let res = f.sec(&insert(&f.engine_a, "def", &text), &[A]).await;
    assert_eq!(
        refused(&res),
        ("UNKNOWN_FIELD".into(), "name".into(), "name".into())
    );
    let text = f
        .definition(&[&f.sensor_a], OWN_ADDRESS, "")
        .replace("multidimension", "timeseries");
    let res = f.sec(&insert(&f.engine_a, "def", &text), &[A]).await;
    assert_eq!(
        refused(&res),
        ("FIELD_NOT_ALLOWED".into(), "csv".into(), String::new())
    );
    assert!(stored(&f.store(), "def").is_none());
}

/// Moves node `node_id` to customer `customer_id`, keeping its hostname.
fn move_to_customer(store: &Store, node_id: u32, customer_id: u32) {
    let mut map = store.node_map();
    let (node, _, _) = map.get_by_id(node_id).unwrap().unwrap();
    let old = NodeUpdate::from(node.clone());
    let mut new = NodeUpdate::from(node);
    for profile in [&mut new.profile, &mut new.profile_draft]
        .into_iter()
        .flatten()
    {
        profile.customer_id = customer_id;
    }
    map.update(node_id, &old, &new).unwrap();
}

#[tokio::test]
async fn a_timeseries_definition_reads_assigned_policies_and_shows_their_delivery() {
    let f = fixture().await;
    let generator = |hostname: &str| {
        insert_generator_node_with(
            &f.store(),
            hostname,
            A,
            Some(generator_config(&f.server_name)),
        )
    };
    let online = generator("gen-1.example.com");
    let offline = generator("gen-2.example.com");
    let moved = generator("gen-3.example.com");
    let (p_online, p_offline, p_withheld, p_unassigned) = {
        let store = f.store();
        let policy = |name: &str, generator: &ModelInstance| {
            insert_assigned_policy(&store, name, A, generator, PolicyShape::default())
        };
        let ids = (
            policy("online", &online),
            policy("offline", &offline),
            policy("withheld", &moved),
            insert_policy(&store, "unassigned", A, &sensor_name("gen-1.example.com")),
        );
        move_to_customer(&store, moved.node_id, B);
        ids
    };
    f.relay.set_online("gen-1.example.com", &[&online]);
    // The host of the offline generator is connected, but not the generator.
    let sensor = ModelInstance {
        node_id: offline.node_id,
        agent_key: SENSOR_KEY.to_string(),
    };
    f.relay.set_online("gen-2.example.com", &[&sensor]);
    // A withheld policy's generator being online does not matter.
    f.relay.set_online("gen-3.example.com", &[&moved]);

    let text = timeseries_definition(&[p_online, p_offline], &f.server_name, OWN_ADDRESS, "");
    let res = f.sec(&insert(&f.engine_a, "series", &text), &[A]).await;
    assert_eq!(data(res), json!({ "insertTrainingDefinition": "series" }));
    let stored = stored(&f.store(), "series").expect("stored");
    assert_eq!(stored.method, review_database::ModelMethod::Timeseries);
    assert_eq!(stored.event_kind, "timeseries");

    let res = f
        .sec(
            r#"{ trainingDefinition(name: "series") { sourceDelivery { source delivery } } }"#,
            &[A],
        )
        .await;
    assert_eq!(
        data(res),
        json!({ "trainingDefinition": { "sourceDelivery": [
            { "source": p_online.to_string(), "delivery": "ASSIGNEE_ONLINE" },
            { "source": p_offline.to_string(), "delivery": "ASSIGNEE_OFFLINE" },
        ] } })
    );

    for (id, delivery) in [
        (p_unassigned, "UNASSIGNED"),
        (p_withheld, "WITHHELD"),
        (p_offline, "ASSIGNEE_OFFLINE"),
        (p_online, "ASSIGNEE_ONLINE"),
    ] {
        let res = f
            .sec(
                &format!(r#"{{ samplingPolicy(id: "{id}") {{ delivery }} }}"#),
                &[A],
            )
            .await;
        assert_eq!(
            data(res),
            json!({ "samplingPolicy": { "delivery": delivery } }),
            "{id}"
        );
    }

    // A source of another method is not a policy, even when it names one.
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    f.define(&f.engine_a, "multi", &text).await;
    let res = f
        .sec(
            r#"{ trainingDefinition(name: "multi") { sourceDelivery { source delivery } } }"#,
            &[A],
        )
        .await;
    assert_eq!(
        data(res),
        json!({ "trainingDefinition": { "sourceDelivery": [
            { "source": f.sensor_a, "delivery": null },
        ] } })
    );
}

#[tokio::test]
async fn a_timeseries_definition_is_refused_for_an_unassigned_policy_or_a_sensor() {
    let f = fixture().await;
    let generator = insert_generator_node_with(
        &f.store(),
        "gen-1.example.com",
        A,
        Some(generator_config(&f.server_name)),
    );
    let (assigned, unassigned) = {
        let store = f.store();
        (
            insert_assigned_policy(&store, "assigned", A, &generator, PolicyShape::default()),
            insert_policy(&store, "unassigned", A, &sensor_name("gen-1.example.com")),
        )
    };
    let text = timeseries_definition(&[assigned, unassigned], &f.server_name, OWN_ADDRESS, "");
    let res = f.sec(&insert(&f.engine_a, "series", &text), &[A]).await;
    assert_eq!(
        refused(&res),
        (
            "SOURCE_NOT_ALLOWED".into(),
            "sources[1]".into(),
            unassigned.to_string()
        )
    );
    let text = timeseries_definition(&[assigned], &f.server_name, OWN_ADDRESS, "")
        .replace(&format!("\"{assigned}\""), &format!("{:?}", f.sensor_a));
    let res = f.sec(&insert(&f.engine_a, "series", &text), &[A]).await;
    assert_eq!(code(&res), "SOURCE_NOT_ALLOWED");
    assert!(stored(&f.store(), "series").is_none());
}

#[tokio::test]
async fn a_timeseries_model_keeps_its_shape_through_update_retrain_and_clone() {
    let f = fixture().await;
    let generator = insert_generator_node_with(
        &f.store(),
        "gen-1.example.com",
        A,
        Some(generator_config(&f.server_name)),
    );
    let (quarter, quarter_2, hourly) = {
        let store = f.store();
        let policy = |name: &str, shape: PolicyShape| {
            insert_assigned_policy(&store, name, A, &generator, shape)
        };
        (
            policy("quarter", PolicyShape::default()),
            policy("quarter-2", PolicyShape::default()),
            policy(
                "hourly",
                PolicyShape {
                    interval: SamplingInterval::OneHour,
                    ..PolicyShape::default()
                },
            ),
        )
    };
    let text = |sources: &[u32]| timeseries_definition(sources, &f.server_name, OWN_ADDRESS, "");
    let differs = |source: u32| {
        (
            "SOURCES_INCOMPATIBLE".to_string(),
            "sources[0]".to_string(),
            source.to_string(),
        )
    };

    // Before the model exists, the definition may change its shape.
    f.define(&f.engine_a, "series", &text(&[hourly])).await;
    let res = f.sec(&update("series", &text(&[quarter])), &[A]).await;
    assert!(res.errors.is_empty(), "{res:?}");
    let run_id = f.train("series").await;
    complete_as(
        &f.store(),
        run_id,
        &f.engine_a,
        "series",
        (TIMESERIES_KIND, "timeseries"),
    );
    let model = model_by_name(&f.store(), "series").unwrap().unwrap();
    assert_eq!(model.kind, TIMESERIES_KIND);
    assert_eq!(model.trained_sources, [quarter.to_string()]);
    name_in_documents(&f.store(), &f.engine_a, "series", 7, Some(8));

    // Once it exists, its detectors read the shape it was trained on, so
    // neither an update nor a retrain may change it.
    let res = f.sec(&update("series", &text(&[hourly])), &[A]).await;
    assert_eq!(refused(&res), differs(hourly));
    assert_eq!(
        stored(&f.store(), "series").unwrap().sources,
        [quarter.to_string()]
    );
    store_text(&f.store(), "series", &text(&[hourly]));
    let res = f.sys(&train("series")).await;
    assert_eq!(refused(&res), differs(hourly));
    assert_eq!(f.store().model_runs("series").unwrap().len(), 1);
    // Another policy of the same shape is accepted.
    let res = f.sec(&update("series", &text(&[quarter_2])), &[A]).await;
    assert!(res.errors.is_empty(), "{res:?}");

    // A clone keeps the classifier, and so the shape.
    let copy = |target: &str, source: u32| {
        clone(
            "series",
            target,
            &f.engine_a2,
            (&f.server_name, OWN_ADDRESS),
            &[&source.to_string()],
            "",
        )
    };
    let res = f.sec(&copy("copy", hourly), &[A]).await;
    assert_eq!(refused(&res), differs(hourly));
    assert!(stored(&f.store(), "copy").is_none());
    let res = f.sec(&copy("copy", quarter_2), &[A]).await;
    assert!(res.errors.is_empty(), "{res:?}");
}

#[tokio::test]
async fn a_timeseries_model_of_unknown_shape_cannot_be_cloned() {
    let f = fixture().await;
    let generator = insert_generator_node_with(
        &f.store(),
        "gen-1.example.com",
        A,
        Some(generator_config(&f.server_name)),
    );
    let quarter =
        insert_assigned_policy(&f.store(), "quarter", A, &generator, PolicyShape::default());
    let text = timeseries_definition(&[quarter], &f.server_name, OWN_ADDRESS, "");
    // A model trained before its sources were recorded.
    f.store()
        .replace_model(
            review_database::Model {
                id: 0,
                name: "legacy".to_string(),
                version: 1,
                kind: TIMESERIES_KIND.to_string(),
                serialized_classifier: vec![1, 2, 3],
                max_event_id_num: 25,
                event_kind: "timeseries".to_string(),
                classification_id: 0,
                batch_info: vec![],
                scores: ModelScores::new(),
            },
            review_database::ModelOwner {
                customer_id: A,
                instance: f.engine_a.clone(),
            },
            chrono::Utc::now(),
            review_database::TrainedWith {
                run_id: 1,
                definition: text,
                sources: Vec::new(),
            },
        )
        .unwrap();
    let res = f
        .sec(
            &clone(
                "legacy",
                "copy",
                &f.engine_a2,
                (&f.server_name, OWN_ADDRESS),
                &[&quarter.to_string()],
                "",
            ),
            &[A],
        )
        .await;
    assert_eq!(
        refused(&res),
        (
            "SOURCES_INCOMPATIBLE".into(),
            "sources[0]".into(),
            quarter.to_string()
        )
    );
    assert!(stored(&f.store(), "copy").is_none());
}

#[tokio::test]
async fn sources_must_be_of_the_instance_customer() {
    let f = fixture().await;
    for source in [
        &f.sensor_b,
        &f.logs_b,
        &"piglet.unknown.example.com".to_string(),
    ] {
        let text = f.definition(&[&f.sensor_a, source], OWN_ADDRESS, "");
        let res = f.sys(&insert(&f.engine_a, "def", &text)).await;
        assert_eq!(
            refused(&res),
            (
                "SOURCE_NOT_ALLOWED".into(),
                "sources[1]".into(),
                source.clone()
            )
        );
    }
    // A Log Collector source is the source of its own customer.
    let text = f.definition(&[&f.logs_b], OWN_ADDRESS, "");
    f.define(&f.engine_b, "logs-b", &text).await;
    let text = f.definition(&[&f.logs_a], OWN_ADDRESS, "");
    f.define(&f.engine_a, "logs-a", &text).await;
    // A source repeated is refused before any is looked up.
    let text = f.definition(&[&f.sensor_a, &f.sensor_a], OWN_ADDRESS, "");
    let res = f.sys(&insert(&f.engine_a, "dup", &text)).await;
    assert_eq!(code(&res), "DUPLICATE_ENTRY");
    let text = f.definition(&[], OWN_ADDRESS, "");
    let res = f.sys(&insert(&f.engine_a, "empty", &text)).await;
    assert_eq!(code(&res), "INVALID_DOCUMENT");
}

#[tokio::test]
async fn the_data_store_must_be_installed() {
    let f = fixture().await;
    for server_name in [
        "001.giganto.missing.example.com",
        "not-a-store",
        "002.giganto.store.example.com",
    ] {
        let text = definition_text(&[&f.sensor_a], server_name, OWN_ADDRESS, "");
        let res = f.sys(&insert(&f.engine_a, "def", &text)).await;
        assert_eq!(
            refused(&res),
            (
                "DATA_STORE_NOT_INSTALLED".into(),
                "data_store.server_name".into(),
                server_name.into()
            )
        );
    }
}

#[tokio::test]
async fn a_listed_data_store_with_no_hostname_is_not_installed() {
    let f = fixture().await;
    // A node whose applied hostname is empty lists its Data Store as
    // `001.giganto.`, a name that does not parse.
    let server_name = insert_named_data_store_node(&f.store(), A, "nameless.example.com", "");
    assert_eq!(server_name, "001.giganto.");
    let not_installed = (
        "DATA_STORE_NOT_INSTALLED".to_string(),
        "data_store.server_name".to_string(),
        server_name.clone(),
    );

    // A System Administrator's address override does not exempt the name.
    let text = definition_text(&[&f.sensor_a], &server_name, OVERRIDE, "");
    let res = f.sys(&insert(&f.engine_a, "def", &text)).await;
    assert_eq!(refused(&res), not_installed);

    // Nor does a kept pair, on update or on training.
    let own = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    f.define(&f.engine_a, "def", &own).await;
    store_text(&f.store(), "def", &text);
    let res = f.sec(&update("def", &text), &[A]).await;
    assert_eq!(refused(&res), not_installed);
    let res = f.sys(&train("def")).await;
    assert_eq!(refused(&res), not_installed);
    assert_eq!(f.store().model_runs("def").unwrap().len(), 0);
}

#[tokio::test]
async fn only_a_system_administrator_overrides_the_address() {
    let f = fixture().await;
    let own = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    let res = f.sec(&insert(&f.engine_a, "own", &own), &[A]).await;
    assert_eq!(data(res), json!({ "insertTrainingDefinition": "own" }));

    // Another Data Store's address is an override too.
    for address in [OVERRIDE, OWN_ADDRESS_B, "10.0.0.5:1"] {
        let text = f.definition(&[&f.sensor_a], address, "");
        let res = f.sec(&insert(&f.engine_a, "override", &text), &[A]).await;
        assert_eq!(
            refused(&res),
            (
                "ADDRESS_OVERRIDE_FORBIDDEN".into(),
                "data_store.address".into(),
                address.into()
            )
        );
    }
    let text = f.definition(&[&f.sensor_a], OVERRIDE, "");
    f.define(&f.engine_a, "override", &text).await;

    // A Security Administrator keeps the stored override unchanged.
    let kept = f.definition(&[&f.sensor_a2], OVERRIDE, "eps = 3.0");
    let res = f.sec(&update("override", &kept), &[A]).await;
    assert_eq!(data(res), json!({ "updateTrainingDefinition": "override" }));
    // But cannot move it, nor set one on another definition.
    let moved = f.definition(&[&f.sensor_a2], "192.0.2.1:9998", "");
    let res = f.sec(&update("override", &moved), &[A]).await;
    assert_eq!(code(&res), "ADDRESS_OVERRIDE_FORBIDDEN");
    let res = f.sec(&update("own", &kept), &[A]).await;
    assert_eq!(code(&res), "ADDRESS_OVERRIDE_FORBIDDEN");
}

#[tokio::test]
async fn an_address_is_an_override_when_the_endpoint_lookup_fails() {
    let (schema, _relay) = relay_schema().await;
    let (engine, sensor, server_name) = {
        let store = schema.store();
        (
            insert_engine_instance(&store, A, "engine-a.example.com", ENGINE_KEY),
            insert_sensor_node(&store, A, "sensor-a.example.com"),
            insert_data_store_node(&store, A, STORE_HOST),
        )
    };
    // The relay resolves no Data Store.
    let text = definition_text(&[&sensor], &server_name, OWN_ADDRESS, "");
    let res = schema
        .execute_as_scoped_user(
            &insert(&engine, "def", &text),
            Role::SecurityAdministrator,
            Some(vec![A]),
        )
        .await;
    assert_eq!(code(&res), "ADDRESS_OVERRIDE_FORBIDDEN");
    let res = schema
        .execute_as_system_admin(&insert(&engine, "def", &text))
        .await;
    assert_eq!(data(res), json!({ "insertTrainingDefinition": "def" }));
}

#[tokio::test]
async fn the_indicator_must_be_of_the_instance_customer() {
    let f = fixture().await;
    let model_a = model_on(&f.store(), "host-a", A, &f.engine_a);
    let model_b = model_on(&f.store(), "host-b", B, &f.engine_b);
    insert_indicator(&f.store(), "ind-a", model_a);
    insert_indicator(&f.store(), "ind-b", model_b);
    for indicator in ["ind-b", "missing"] {
        let text = f.definition(
            &[&f.sensor_a],
            OWN_ADDRESS,
            &format!("suspicious_tokens = \"{indicator}\""),
        );
        let res = f.sys(&insert(&f.engine_a, "def", &text)).await;
        assert_eq!(
            refused(&res),
            (
                "INDICATOR_NOT_ALLOWED".into(),
                "suspicious_tokens".into(),
                indicator.into()
            )
        );
    }
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "suspicious_tokens = \"ind-a\"");
    f.define(&f.engine_a, "def", &text).await;
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "suspicious_tokens = \"ind-b\"");
    let res = f.sys(&update("def", &text)).await;
    assert_eq!(code(&res), "INDICATOR_NOT_ALLOWED");
}

#[tokio::test]
async fn insert_refusals_of_the_store_and_the_instance() {
    let f = fixture().await;
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    f.define(&f.engine_a, "taken", &text).await;
    let res = f.sys(&insert(&f.engine_a, "taken", &text)).await;
    assert_eq!(
        refused(&res),
        ("NAME_TAKEN".into(), "name".into(), "taken".into())
    );
    let res = f.sys(&insert(&f.engine_a, "", &text)).await;
    assert_eq!(code(&res), "NAME_INVALID");

    let sensor_node = ModelInstance {
        node_id: f.engine_a.node_id,
        agent_key: "001.piglet".to_string(),
    };
    let res = f.sys(&insert(&sensor_node, "def", &text)).await;
    assert_eq!(
        refused(&res),
        (
            "INSTANCE_NOT_ELIGIBLE".into(),
            "agentKey".into(),
            "001.piglet".into()
        )
    );
    let missing = ModelInstance {
        node_id: 999,
        agent_key: ENGINE_KEY.to_string(),
    };
    let res = f.sys(&insert(&missing, "def", &text)).await;
    assert_eq!(code(&res), "INSTANCE_NOT_ELIGIBLE");
}

#[tokio::test]
async fn insert_refuses_an_instance_without_an_applied_hostname_or_profile() {
    let f = fixture().await;
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    let node_id = f.engine_a.node_id;
    let edit_profile = |edit: &dyn Fn(&mut NodeUpdate)| {
        let store = f.store();
        let mut map = store.node_map();
        let (node, _, _) = map
            .get_by_id(node_id)
            .expect("read engine node")
            .expect("engine node exists");
        let old = NodeUpdate::from(node.clone());
        let mut new = NodeUpdate::from(node);
        edit(&mut new);
        map.update(node_id, &old, &new)
            .expect("edit the applied profile");
    };

    edit_profile(&|new| {
        new.profile.as_mut().expect("applied profile").hostname = String::new();
    });
    let res = f.sys(&insert(&f.engine_a, "def", &text)).await;
    assert_eq!(
        refused(&res),
        (
            "INSTANCE_NOT_ELIGIBLE".into(),
            "nodeId".into(),
            node_id.to_string()
        )
    );

    edit_profile(&|new| new.profile = None);
    let res = f.sys(&insert(&f.engine_a, "def", &text)).await;
    assert_eq!(
        refused(&res),
        (
            "INSTANCE_NOT_ELIGIBLE".into(),
            "nodeId".into(),
            node_id.to_string()
        )
    );
    assert!(stored(&f.store(), "def").is_none(), "nothing is stored");
}

#[tokio::test]
async fn update_refusals_of_the_store() {
    let f = fixture().await;
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    let res = f.sys(&update("missing", &text)).await;
    assert_eq!(
        refused(&res),
        ("NOT_FOUND".into(), "name".into(), "missing".into())
    );

    f.define(&f.engine_a, "def", &text).await;
    let run_id = f.train("def").await;
    let res = f.sys(&update("def", &text)).await;
    assert_eq!(
        refused(&res),
        ("RUN_IN_PROGRESS".into(), "name".into(), run_id.to_string())
    );
    complete(&f.store(), run_id, &f.engine_a, "def");

    let conn = text.replace("event_kind = \"http\"", "event_kind = \"conn\"");
    let res = f.sys(&update("def", &conn)).await;
    assert_eq!(
        refused(&res),
        ("FIELD_FIXED".into(), "event_kind".into(), "conn".into())
    );
    let (_, extensions) = single_error(&res);
    assert_eq!(extensions["definition"], "def");
}

#[tokio::test]
async fn update_judges_the_kept_pair_against_the_definition_read_under_the_lock() {
    let f = fixture().await;
    let stored_text = f.definition(&[&f.sensor_a], OVERRIDE, "");
    f.define(&f.engine_a, "def", &stored_text).await;
    let pause = f.relay.pause_next_lookup();

    let request = f.definition(&[&f.sensor_a], OVERRIDE, "eps = 3.0");
    let query = update("def", &request);
    let (res, ()) = tokio::join!(f.sec(&query, &[A]), async {
        pause.entered.notified().await;
        let moved = f.definition(&[&f.sensor_a], "192.0.2.1:9998", "");
        store_text(&f.store(), "def", &moved);
        pause.release.notify_one();
    });
    assert_eq!(code(&res), "ADDRESS_OVERRIDE_FORBIDDEN");
}

#[tokio::test]
async fn remove_definition_and_its_refusals() {
    let f = fixture().await;
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    f.define(&f.engine_a, "free", &text).await;
    let res = f.sec(&remove_definition("free"), &[A]).await;
    assert_eq!(data(res), json!({ "removeTrainingDefinition": "free" }));
    assert!(stored(&f.store(), "free").is_none());
    let res = f.sys(&remove_definition("free")).await;
    assert_eq!(code(&res), "NOT_FOUND");

    f.define(&f.engine_a, "def", &text).await;
    let run_id = f.train("def").await;
    let res = f.sys(&remove_definition("def")).await;
    assert_eq!(
        refused(&res),
        ("RUN_IN_PROGRESS".into(), "name".into(), run_id.to_string())
    );
    complete(&f.store(), run_id, &f.engine_a, "def");
    let res = f.sys(&remove_definition("def")).await;
    assert_eq!(
        refused(&res),
        ("MODEL_IN_USE".into(), "name".into(), "def".into())
    );
    let (_, extensions) = single_error(&res);
    assert_eq!(extensions["definition"], "def");
}

// ---------------------------------------------------------------------------
// trainModel

#[tokio::test]
async fn train_relays_the_definition_and_returns_the_run_id() {
    let f = fixture().await;
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    f.define(&f.engine_a, "def", &text).await;
    let res = f.sec(&train("def"), &[A]).await;
    let id = run_id(&data(res)["trainModel"]);
    assert_eq!(
        f.relay.calls(),
        [RelayCall::Train {
            agent_lookup_key: lookup_key(&f.engine_a, "engine-a.example.com"),
            run_id: id,
            model: "def".to_string(),
            definition: text,
        }]
    );
    assert_eq!(f.run_state(id), Some(RunState::Requested));

    let res = f.sys(&train("def")).await;
    assert_eq!(
        refused(&res),
        ("RUN_IN_PROGRESS".into(), "name".into(), id.to_string())
    );
    assert_eq!(f.relay.calls().len(), 1);

    let res = f.sys(&train("missing")).await;
    assert_eq!(code(&res), "NOT_FOUND");

    f.define(
        &f.engine_a2,
        "stopped",
        &f.definition(&[&f.sensor_a], OWN_ADDRESS, ""),
    )
    .await;
    f.store()
        .set_engine_instance_stopped(&f.engine_a2, true)
        .expect("stop the instance");
    let res = f.sys(&train("stopped")).await;
    assert_eq!(
        refused(&res),
        (
            "INSTANCE_STOPPED".into(),
            "agentKey".into(),
            ENGINE_KEY.into()
        )
    );
    assert_eq!(f.store().model_runs("stopped").unwrap().len(), 0);
}

#[tokio::test]
async fn a_relay_error_fails_the_training_run() {
    for ends_runs in [false, true] {
        let f = fixture().await;
        if ends_runs {
            f.relay.end_failed_runs();
        }
        let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
        f.define(&f.engine_a, "def", &text).await;

        f.relay
            .answer_with(RelayAnswer::Refused("no disk space".to_string()));
        let res = f.sys(&train("def")).await;
        assert_eq!(
            refused(&res),
            (
                "ENGINE_REFUSED".into(),
                "name".into(),
                "no disk space".into()
            )
        );
        let runs = f.store().model_runs("def").unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].state, RunState::Failed);
        if !ends_runs {
            assert_eq!(runs[0].reason.as_deref(), Some(INSTANCE_UNREACHABLE));
        }

        f.relay.answer_with(RelayAnswer::Unreachable);
        let res = f.sys(&train("def")).await;
        assert_eq!(
            refused(&res),
            (
                "INSTANCE_UNREACHABLE".into(),
                "name".into(),
                lookup_key(&f.engine_a, "engine-a.example.com")
            )
        );
        let runs = f.store().model_runs("def").unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[1].state, RunState::Failed);
        let res = f
            .sys("{ trainingDefinition(name: \"def\") { state lastRun { state reason } } }")
            .await;
        assert_eq!(data(res)["trainingDefinition"]["state"], "TRAINING_FAILED");
    }
}

#[tokio::test]
async fn the_default_relay_leaves_the_run_failed() {
    let schema = TestSchema::new().await;
    let (engine, sensor, server_name) = {
        let store = schema.store();
        (
            insert_engine_instance(&store, A, "engine-a.example.com", ENGINE_KEY),
            insert_sensor_node(&store, A, "sensor-a.example.com"),
            insert_data_store_node(&store, A, STORE_HOST),
        )
    };
    let text = definition_text(&[&sensor], &server_name, OWN_ADDRESS, "");
    let res = schema
        .execute_as_system_admin(&insert(&engine, "def", &text))
        .await;
    assert!(res.errors.is_empty(), "{res:?}");
    let res = schema.execute_as_system_admin(&train("def")).await;
    assert_eq!(code(&res), "INSTANCE_UNREACHABLE");
    let runs = schema.store().model_runs("def").unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].state, RunState::Failed);
    assert_eq!(runs[0].reason.as_deref(), Some(INSTANCE_UNREACHABLE));
}

#[tokio::test]
async fn the_default_clone_and_cancel_relays_clean_up_the_run() {
    let schema = TestSchema::new().await;
    let (engine, target, sensor, server_name) = {
        let store = schema.store();
        (
            insert_engine_instance(&store, A, "engine-a.example.com", ENGINE_KEY),
            insert_engine_instance(&store, A, "engine-a2.example.com", ENGINE_KEY),
            insert_sensor_node(&store, A, "sensor-a.example.com"),
            insert_data_store_node(&store, A, STORE_HOST),
        )
    };
    let text = definition_text(&[&sensor], &server_name, OWN_ADDRESS, "");
    data(
        schema
            .execute_as_system_admin(&insert(&engine, "src", &text))
            .await,
    );
    let id = schema.store().start_training_run("src").unwrap().run.id;
    let res = schema
        .execute_as_system_admin(&cancel(&id.to_string()))
        .await;
    assert_eq!(
        refused(&res),
        (
            "INSTANCE_UNREACHABLE".into(),
            "runId".into(),
            lookup_key(&engine, "engine-a.example.com")
        )
    );
    let run = schema.store().model_run(id).unwrap().unwrap();
    assert_eq!(run.state, RunState::Failed);
    assert_eq!(run.reason.as_deref(), Some(INSTANCE_UNREACHABLE));

    let id = schema.store().start_training_run("src").unwrap().run.id;
    complete(&schema.store(), id, &engine, "src");
    let res = schema
        .execute_as_system_admin(&clone(
            "src",
            "dst",
            &target,
            (&server_name, OWN_ADDRESS),
            &[&sensor],
            "",
        ))
        .await;
    assert_eq!(
        refused(&res),
        (
            "INSTANCE_UNREACHABLE".into(),
            "source".into(),
            lookup_key(&engine, "engine-a.example.com")
        )
    );
    assert!(stored(&schema.store(), "dst").is_none());
    assert_eq!(schema.store().model_runs("dst").unwrap(), []);
    assert!(schema.store().active_run("src").unwrap().is_none());
}

#[tokio::test]
async fn train_applies_the_source_and_data_store_rules_to_the_stored_definition() {
    let f = fixture().await;
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    f.define(&f.engine_a, "def", &text).await;

    store_text(
        &f.store(),
        "def",
        &f.definition(&[&f.sensor_b], OWN_ADDRESS, ""),
    );
    let res = f.sys(&train("def")).await;
    assert_eq!(
        refused(&res),
        (
            "SOURCE_NOT_ALLOWED".into(),
            "sources[0]".into(),
            f.sensor_b.clone()
        )
    );
    let missing = definition_text(
        &[&f.sensor_a],
        "001.giganto.gone.example.com",
        OWN_ADDRESS,
        "",
    );
    store_text(&f.store(), "def", &missing);
    let res = f.sys(&train("def")).await;
    assert_eq!(code(&res), "DATA_STORE_NOT_INSTALLED");
    assert_eq!(f.store().model_runs("def").unwrap().len(), 0);
    assert_eq!(f.relay.calls(), Vec::new());

    // The stored override pair is kept, so no address is looked up.
    store_text(
        &f.store(),
        "def",
        &f.definition(&[&f.sensor_a], OVERRIDE, ""),
    );
    let res = f.sec(&train("def"), &[A]).await;
    assert!(res.errors.is_empty(), "{res:?}");
}

#[tokio::test]
async fn train_refuses_a_stored_definition_that_does_not_parse() {
    let f = fixture().await;
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    f.define(&f.engine_a, "def", &text).await;

    // A key outside the schema, stored bypassing validation, is reported as
    // a stored text that does not parse rather than as `UNKNOWN_FIELD`.
    let document = TrainingDocument::parse(&text).unwrap();
    f.store()
        .update_training_definition(
            "def",
            TrainingDefinitionUpdate {
                method: document.method.into(),
                event_kind: document.event_kind.clone(),
                sources: document.sources.clone(),
                indicator: None,
                definition: format!("unknown_key = 1\n{text}"),
            },
        )
        .unwrap();
    let res = f.sys(&train("def")).await;
    assert_eq!(
        refused(&res),
        ("INVALID_DOCUMENT".into(), "name".into(), "def".into())
    );
    assert_eq!(f.store().model_runs("def").unwrap().len(), 0);
    assert_eq!(f.relay.calls(), Vec::new());
}

#[tokio::test]
async fn train_relays_the_text_read_under_the_lock() {
    let f = fixture().await;
    f.define(
        &f.engine_a,
        "def",
        &f.definition(&[&f.sensor_a], OWN_ADDRESS, "eps = 5.0"),
    )
    .await;
    let changed = f.definition(&[&f.sensor_a2], OWN_ADDRESS, "eps = 2.0");

    let guard = f.schema.hold_engine_config_lock().await;
    let query = train("def");
    let (res, ()) = tokio::join!(f.sys(&query), async {
        while f.schema.engine_config_lock_users() < 2 {
            tokio::task::yield_now().await;
        }
        assert_eq!(f.store().model_runs("def").unwrap().len(), 0);
        store_text(&f.store(), "def", &changed);
        drop(guard);
    });
    let id = run_id(&data(res)["trainModel"]);
    assert!(matches!(
        &f.relay.calls()[..],
        [RelayCall::Train { definition, .. }] if *definition == changed
    ));
    complete(&f.store(), id, &f.engine_a, "def");
    let res = f
        .sys("{ models { edges { node { name trainedDefinition trainedRunId } } } }")
        .await;
    assert_eq!(
        data(res)["models"]["edges"][0]["node"],
        json!({ "name": "def", "trainedDefinition": changed, "trainedRunId": id.to_string() })
    );

    // A source of another customer stored meanwhile refuses the run.
    let guard = f.schema.hold_engine_config_lock().await;
    let (res, ()) = tokio::join!(f.sys(&query), async {
        while f.schema.engine_config_lock_users() < 2 {
            tokio::task::yield_now().await;
        }
        store_text(
            &f.store(),
            "def",
            &f.definition(&[&f.sensor_b], OWN_ADDRESS, ""),
        );
        drop(guard);
    });
    assert_eq!(code(&res), "SOURCE_NOT_ALLOWED");
    assert_eq!(f.store().model_runs("def").unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// cancelModelRun

#[tokio::test]
async fn cancel_relays_to_the_instance_performing_the_run() {
    let f = fixture().await;
    f.define(
        &f.engine_a,
        "def",
        &f.definition(&[&f.sensor_a], OWN_ADDRESS, ""),
    )
    .await;
    let id = f.train("def").await;
    let res = f.sec(&cancel(&id.to_string()), &[A]).await;
    assert_eq!(data(res), json!({ "cancelModelRun": id.to_string() }));
    assert_eq!(
        f.relay.calls().last(),
        Some(&RelayCall::Cancel {
            agent_lookup_key: lookup_key(&f.engine_a, "engine-a.example.com"),
            run_id: id,
        })
    );
    assert_eq!(f.run_state(id), Some(RunState::Requested));

    f.relay
        .answer_with(RelayAnswer::Refused("already done".to_string()));
    let res = f.sys(&cancel(&id.to_string())).await;
    assert_eq!(
        refused(&res),
        (
            "ENGINE_REFUSED".into(),
            "runId".into(),
            "already done".into()
        )
    );
    assert_eq!(f.run_state(id), Some(RunState::Failed));

    let res = f.sys(&cancel(&id.to_string())).await;
    assert_eq!(
        refused(&res),
        ("RUN_NOT_ACTIVE".into(), "runId".into(), id.to_string())
    );
    for missing in ["999", "abc", "-1"] {
        let res = f.sys(&cancel(missing)).await;
        assert_eq!(
            refused(&res),
            ("NOT_FOUND".into(), "runId".into(), missing.into())
        );
    }
}

#[tokio::test]
async fn a_node_without_an_applied_hostname_is_not_relayed_to() {
    let f = fixture().await;
    f.define(
        &f.engine_a,
        "def",
        &f.definition(&[&f.sensor_a], OWN_ADDRESS, ""),
    )
    .await;
    let id = f.train("def").await;
    {
        let store = f.store();
        let mut map = store.node_map();
        let (node, _, _) = map
            .get_by_id(f.engine_a.node_id)
            .expect("read engine node")
            .expect("engine node exists");
        let old = NodeUpdate::from(node.clone());
        let mut new = NodeUpdate::from(node);
        new.profile.as_mut().expect("applied profile").hostname = String::new();
        map.update(f.engine_a.node_id, &old, &new)
            .expect("clear the applied hostname");
    }
    let calls = f.relay.calls().len();

    let res = f.sec(&cancel(&id.to_string()), &[A]).await;
    assert_eq!(
        refused(&res),
        (
            "INSTANCE_UNREACHABLE".into(),
            "runId".into(),
            id.to_string()
        )
    );
    assert_eq!(f.relay.calls().len(), calls, "no relay is made");
    assert_eq!(f.run_state(id), Some(RunState::Failed));

    let res = f.sec(&train("def"), &[A]).await;
    assert_eq!(code(&res), "INSTANCE_NOT_ELIGIBLE");
    assert_eq!(f.store().model_runs("def").unwrap().len(), 1, "no run");
    assert_eq!(f.relay.calls().len(), calls, "no relay is made");
}

#[tokio::test]
async fn an_undelivered_cancel_of_a_clone_removes_it_with_its_target() {
    let f = fixture().await;
    f.define(
        &f.engine_a,
        "src",
        &f.definition(&[&f.sensor_a], OWN_ADDRESS, ""),
    )
    .await;
    f.train_to_completion("src", &f.engine_a).await;
    let res = f
        .sys(&clone(
            "src",
            "dst",
            &f.engine_a2,
            (&f.server_name, OWN_ADDRESS),
            &[&f.sensor_a2],
            "",
        ))
        .await;
    let id = run_id(&data(res)["cloneModel"]);

    f.relay.answer_with(RelayAnswer::Unreachable);
    let res = f.sec(&cancel(&id.to_string()), &[A]).await;
    assert_eq!(
        refused(&res),
        (
            "INSTANCE_UNREACHABLE".into(),
            "runId".into(),
            lookup_key(&f.engine_a, "engine-a.example.com")
        )
    );
    assert_eq!(
        f.relay.calls().last(),
        Some(&RelayCall::Cancel {
            agent_lookup_key: lookup_key(&f.engine_a, "engine-a.example.com"),
            run_id: id,
        })
    );
    assert_eq!(f.run_state(id), None);
    assert!(stored(&f.store(), "dst").is_none());
}

// ---------------------------------------------------------------------------
// cloneModel

#[tokio::test]
async fn a_clone_relay_error_frees_the_target_name() {
    for ends_runs in [false, true] {
        for answer in [
            RelayAnswer::Refused("no disk space".into()),
            RelayAnswer::Unreachable,
        ] {
            let f = fixture().await;
            if ends_runs {
                f.relay.end_failed_runs();
            }
            f.define(
                &f.engine_a,
                "src",
                &f.definition(&[&f.sensor_a], OWN_ADDRESS, ""),
            )
            .await;
            let trained_run = f.train_to_completion("src", &f.engine_a).await;
            let request = clone(
                "src",
                "dst",
                &f.engine_a2,
                (&f.server_name, OWN_ADDRESS),
                &[&f.sensor_a2],
                "",
            );
            f.relay.answer_with(answer.clone());
            let res = f.sec(&request, &[A]).await;
            let expected = match answer {
                RelayAnswer::Refused(reason) => ("ENGINE_REFUSED", reason),
                RelayAnswer::Unreachable => (
                    "INSTANCE_UNREACHABLE",
                    lookup_key(&f.engine_a, "engine-a.example.com"),
                ),
                RelayAnswer::Accepted => unreachable!("only errors are tested"),
            };
            assert_eq!(
                refused(&res),
                (expected.0.into(), "source".into(), expected.1)
            );
            let calls = f.relay.calls();
            let Some(RelayCall::Clone {
                run_id: failed_run_id,
                ..
            }) = calls.last()
            else {
                panic!("clone was not relayed: {calls:?}");
            };
            assert_eq!(f.run_state(*failed_run_id), None);
            assert!(stored(&f.store(), "dst").is_none());
            assert_eq!(f.store().model_runs("dst").unwrap(), []);
            assert!(f.store().active_run("src").unwrap().is_none());
            let source = model_by_name(&f.store(), "src").unwrap().unwrap();
            assert_eq!(source.trained_run_id, trained_run);

            f.relay.answer_with(RelayAnswer::Accepted);
            let retried_run = run_id(&data(f.sec(&request, &[A]).await)["cloneModel"]);
            assert_ne!(retried_run, *failed_run_id);
            assert_eq!(f.run_state(retried_run), Some(RunState::Requested));
            assert!(stored(&f.store(), "dst").is_some());
        }
    }
}

#[tokio::test]
async fn a_same_customer_clone_is_relayed_and_shown_on_its_source() {
    let f = fixture().await;
    let model_id = model_on(&f.store(), "host", A, &f.engine_a2);
    insert_indicator(&f.store(), "ind-a", model_id);
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "suspicious_tokens = \"ind-a\"");
    f.define(&f.engine_a, "src", &text).await;
    f.train_to_completion("src", &f.engine_a).await;

    let res = f
        .sec(
            &clone(
                "src",
                "dst",
                &f.engine_a2,
                (&f.server_name, OWN_ADDRESS),
                &[&f.sensor_a2],
                "",
            ),
            &[A],
        )
        .await;
    let id = run_id(&data(res)["cloneModel"]);
    assert_eq!(
        f.relay.calls().last(),
        Some(&RelayCall::Clone {
            agent_lookup_key: lookup_key(&f.engine_a, "engine-a.example.com"),
            run_id: id,
            source: "src".to_string(),
            target_name: "dst".to_string(),
            strip_events: false,
        })
    );
    let target = stored(&f.store(), "dst").expect("the target is reserved");
    assert_eq!(target.customer_id, A);
    assert_eq!(target.instance.as_ref(), Some(&f.engine_a2));
    assert_eq!(target.sources, std::slice::from_ref(&f.sensor_a2));
    // Left out, the indicator is kept within a customer.
    assert_eq!(target.indicator.as_deref(), Some("ind-a"));

    let expected = json!({ "id": id.to_string(), "kind": "CLONE", "model": "dst", "source": "src", "state": "REQUESTED" });
    let res = f
        .sec(
            "{ models { edges { node { name activeRun { id kind model source state } } } } \
             modelRuns(model: \"src\") { id kind model source state } }",
            &[A],
        )
        .await;
    let response = data(res);
    let src = response["models"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| edge["node"]["name"] == "src")
        .expect("the source is listed")
        .clone();
    assert_eq!(src["node"]["activeRun"], expected);
    assert_eq!(
        response["modelRuns"].as_array().unwrap().last(),
        Some(&expected)
    );

    let res = f
        .sec(
            "{ trainingDefinition(name: \"dst\") { state lastRun { source } } }",
            &[A],
        )
        .await;
    assert_eq!(
        data(res),
        json!({ "trainingDefinition": { "state": "CLONING", "lastRun": { "source": "src" } } })
    );
}

#[tokio::test]
async fn a_cross_customer_clone_is_reserved_to_a_system_administrator() {
    let f = fixture().await;
    let model_a = model_on(&f.store(), "host-a", A, &f.engine_a2);
    let model_b = model_on(&f.store(), "host-b", B, &f.engine_b);
    insert_indicator(&f.store(), "ind-a", model_a);
    insert_indicator(&f.store(), "ind-b", model_b);
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "suspicious_tokens = \"ind-a\"");
    f.define(&f.engine_a, "src", &text).await;
    f.train_to_completion("src", &f.engine_a).await;

    let query = |target: &str, tokens: &str| {
        clone(
            "src",
            target,
            &f.engine_b,
            (&f.server_name_b, OWN_ADDRESS_B),
            &[&f.sensor_b],
            tokens,
        )
    };
    let res = f.sec(&query("dst", ""), &[A, B]).await;
    assert_eq!(code(&res), "CROSS_CUSTOMER_FORBIDDEN");
    assert!(stored(&f.store(), "dst").is_none());

    // Left out, the indicator is cleared across customers.
    let res = f.sys(&query("dst", "")).await;
    let id = run_id(&data(res)["cloneModel"]);
    assert!(matches!(
        f.relay.calls().last(),
        Some(RelayCall::Clone { strip_events: true, run_id, .. }) if *run_id == id
    ));
    let target = stored(&f.store(), "dst").expect("reserved");
    assert_eq!(target.customer_id, B);
    assert_eq!(target.indicator, None);
    complete(&f.store(), id, &f.engine_a, "dst");

    // An indicator of the source's customer is not the target's.
    let res = f
        .sys(&query("dst-2", ", suspiciousTokens: \"ind-a\""))
        .await;
    assert_eq!(code(&res), "INDICATOR_NOT_ALLOWED");
    let res = f
        .sys(&query("dst-2", ", suspiciousTokens: \"ind-b\""))
        .await;
    let id = run_id(&data(res)["cloneModel"]);
    assert_eq!(
        stored(&f.store(), "dst-2")
            .expect("reserved")
            .indicator
            .as_deref(),
        Some("ind-b")
    );
    complete(&f.store(), id, &f.engine_a, "dst-2");
    let res = f.sys(&query("dst-3", ", suspiciousTokens: null")).await;
    assert!(res.errors.is_empty(), "{res:?}");
    assert_eq!(
        stored(&f.store(), "dst-3").expect("reserved").indicator,
        None
    );
}

#[tokio::test]
async fn a_cross_customer_clone_carries_nothing_of_the_source_but_the_settings() {
    let f = fixture().await;
    let model_a = model_on(&f.store(), "host-a", A, &f.engine_a2);
    insert_indicator(&f.store(), "ind-a", model_a);
    let text = format!(
        "# trained on {} for customer A\n{}",
        f.sensor_a,
        f.definition(
            &[&f.sensor_a],
            OWN_ADDRESS,
            "suspicious_tokens = \"ind-a\" # the A indicator"
        )
    );
    f.define(&f.engine_a, "src", &text).await;
    f.train_to_completion("src", &f.engine_a).await;

    let res = f
        .sys(&clone(
            "src",
            "dst",
            &f.engine_b,
            (&f.server_name_b, OWN_ADDRESS_B),
            &[&f.sensor_b],
            "",
        ))
        .await;
    assert!(res.errors.is_empty(), "{res:?}");
    let target = stored(&f.store(), "dst").expect("reserved").definition;
    for absent in [
        "#",
        f.sensor_a.as_str(),
        STORE_HOST,
        "10.0.0.5",
        "ind-a",
        "customer A",
    ] {
        assert!(!target.contains(absent), "{absent} in {target}");
    }
    let document = TrainingDocument::parse(&target).unwrap();
    assert_eq!(document.sources, std::slice::from_ref(&f.sensor_b));
    assert_eq!(document.data_store.server_name, f.server_name_b);
}

#[tokio::test]
async fn clone_refusals() {
    let f = fixture().await;
    f.define(
        &f.engine_a,
        "src",
        &f.definition(&[&f.sensor_a], OWN_ADDRESS, ""),
    )
    .await;
    f.train_to_completion("src", &f.engine_a).await;
    let base = |source: &str, target: &str, address: &str, sources: &[&str]| {
        clone(
            source,
            target,
            &f.engine_a2,
            (&f.server_name, address),
            sources,
            "",
        )
    };

    let res = f.sys(&base("src", "dst", "10.0.0.5", &[&f.sensor_a])).await;
    assert_eq!(
        refused(&res),
        (
            "INVALID_DOCUMENT".into(),
            "data_store.address".into(),
            "10.0.0.5".into()
        )
    );
    let res = f
        .sys(&base("missing", "dst", OWN_ADDRESS, &[&f.sensor_a]))
        .await;
    assert_eq!(
        refused(&res),
        ("NOT_FOUND".into(), "source".into(), "missing".into())
    );
    let res = f
        .sys(&base("src", "src", OWN_ADDRESS, &[&f.sensor_a]))
        .await;
    assert_eq!(
        refused(&res),
        ("NAME_TAKEN".into(), "targetName".into(), "src".into())
    );
    let res = f
        .sec(&base("src", "dst", OVERRIDE, &[&f.sensor_a]), &[A])
        .await;
    assert_eq!(code(&res), "ADDRESS_OVERRIDE_FORBIDDEN");
    let res = f
        .sys(&base("src", "dst", OWN_ADDRESS, &[&f.sensor_b]))
        .await;
    assert_eq!(code(&res), "SOURCE_NOT_ALLOWED");
    let res = f.sys(&base("src", "dst", OWN_ADDRESS, &[])).await;
    assert_eq!(code(&res), "INVALID_DOCUMENT");

    // The source's own trained pair is kept for a Security Administrator.
    store_text(
        &f.store(),
        "src",
        &f.definition(&[&f.sensor_a], OVERRIDE, ""),
    );
    let id = f.train("src").await;
    complete(&f.store(), id, &f.engine_a, "src");
    let res = f
        .sec(&base("src", "dst", OVERRIDE, &[&f.sensor_a2]), &[A])
        .await;
    assert!(res.errors.is_empty(), "{res:?}");
    // The source's instance now performs the clone.
    let res = f
        .sys(&base("src", "dst-2", OWN_ADDRESS, &[&f.sensor_a2]))
        .await;
    assert_eq!(code(&res), "RUN_IN_PROGRESS");
}

#[tokio::test]
async fn a_clone_is_built_from_the_snapshot_read_under_the_lock() {
    let f = fixture().await;
    f.define(
        &f.engine_a,
        "src",
        &f.definition(&[&f.sensor_a], OWN_ADDRESS, "eps = 5.0"),
    )
    .await;
    f.train_to_completion("src", &f.engine_a).await;
    store_text(
        &f.store(),
        "src",
        &f.definition(&[&f.sensor_a], OWN_ADDRESS, "eps = 2.0"),
    );

    let guard = f.schema.hold_engine_config_lock().await;
    let query = clone(
        "src",
        "dst",
        &f.engine_a2,
        (&f.server_name, OWN_ADDRESS),
        &[&f.sensor_a2],
        "",
    );
    let (res, retrained) = tokio::join!(f.sys(&query), async {
        while f.schema.engine_config_lock_users() < 2 {
            tokio::task::yield_now().await;
        }
        let run = f.store().start_training_run("src").unwrap().run;
        complete(&f.store(), run.id, &f.engine_a, "src");
        drop(guard);
        run.id
    });
    assert!(res.errors.is_empty(), "{res:?}");
    let target = TrainingDocument::parse(&stored(&f.store(), "dst").unwrap().definition).unwrap();
    assert_eq!(target.eps, Some(2.0));
    let source = model_by_name(&f.store(), "src").unwrap().unwrap();
    assert_eq!(source.trained_run_id, retrained);
}

#[test]
fn a_retrained_source_maps_to_run_in_progress() {
    let error = store_refusal(
        anyhow::Error::new(TrainingError::SourceRetrained {
            source: "src".to_string(),
            expected: 1,
            current: 2,
        }),
        StoreWrite::StartClone,
        None,
    );
    let extensions = serde_json::to_value(error.extensions.unwrap()).unwrap();
    assert_eq!(extensions["code"], "RUN_IN_PROGRESS");
    assert_eq!(extensions["field"], "source");
    assert_eq!(extensions["value"], "src");
}

// One case per refusal the mapping names.
#[allow(clippy::too_many_lines)]
#[test]
fn store_refusals_map_to_their_codes() {
    let instance = ModelInstance {
        node_id: 3,
        agent_key: ENGINE_KEY.to_string(),
    };
    let cases = [
        (
            TrainingError::DefinitionNotFound { name: "d".into() },
            StoreWrite::StartTraining,
            "NOT_FOUND",
        ),
        (
            TrainingError::ModelNotFound { name: "m".into() },
            StoreWrite::DeleteModel,
            "NOT_FOUND",
        ),
        (
            TrainingError::RunNotFound { run_id: 1 },
            StoreWrite::StartTraining,
            "NOT_FOUND",
        ),
        (
            TrainingError::NameTaken { name: "d".into() },
            StoreWrite::InsertDefinition,
            "NAME_TAKEN",
        ),
        (
            TrainingError::InvalidName {
                name: "d".into(),
                reason: "r".into(),
            },
            StoreWrite::StartClone,
            "NAME_INVALID",
        ),
        (
            TrainingError::InstanceNotEligible {
                node_id: 3,
                agent_key: ENGINE_KEY.into(),
            },
            StoreWrite::StartTraining,
            "INSTANCE_NOT_ELIGIBLE",
        ),
        (
            TrainingError::NoAppliedProfile { node_id: 3 },
            StoreWrite::InsertDefinition,
            "INSTANCE_NOT_ELIGIBLE",
        ),
        (
            TrainingError::NoInstance { name: "d".into() },
            StoreWrite::StartTraining,
            "INSTANCE_NOT_ELIGIBLE",
        ),
        (
            TrainingError::CustomerMismatch {
                node_id: 3,
                node_customer_id: 1,
                customer_id: 2,
            },
            StoreWrite::StartClone,
            "INSTANCE_NOT_ELIGIBLE",
        ),
        (
            TrainingError::CustomerMismatch {
                node_id: 3,
                node_customer_id: 1,
                customer_id: 2,
            },
            StoreWrite::AssignModel,
            "ASSIGN_REFUSED",
        ),
        (
            TrainingError::InstanceStopped {
                node_id: 3,
                agent_key: ENGINE_KEY.into(),
            },
            StoreWrite::StartTraining,
            "INSTANCE_STOPPED",
        ),
        (
            TrainingError::RunInProgress { run_id: 4 },
            StoreWrite::UpdateDefinition,
            "RUN_IN_PROGRESS",
        ),
        (
            TrainingError::RunInProgress { run_id: 4 },
            StoreWrite::DeleteModel,
            "MODEL_IN_USE",
        ),
        (
            TrainingError::IndicatorNotFound {
                indicator: "i".into(),
            },
            StoreWrite::UpdateDefinition,
            "INDICATOR_NOT_ALLOWED",
        ),
        (
            TrainingError::MethodMismatch {
                name: "d".into(),
                expected: review_database::ModelMethod::Prefix,
                actual: "Multifield".into(),
            },
            StoreWrite::StartClone,
            "INVALID_DOCUMENT",
        ),
        (
            TrainingError::EventKindMismatch {
                name: "d".into(),
                expected: "http".into(),
                actual: "conn".into(),
            },
            StoreWrite::StartClone,
            "INVALID_DOCUMENT",
        ),
        (
            TrainingError::RunNotActive {
                run_id: 4,
                state: RunState::Failed,
            },
            StoreWrite::StartTraining,
            "RUN_NOT_ACTIVE",
        ),
        (
            TrainingError::HasModel { name: "d".into() },
            StoreWrite::RemoveDefinition,
            "MODEL_IN_USE",
        ),
        (
            TrainingError::ModelHasInstance {
                name: "m".into(),
                instance: instance.clone(),
            },
            StoreWrite::AssignModel,
            "ASSIGN_REFUSED",
        ),
    ];
    for (error, write, expected) in cases {
        let refusal = store_refusal(anyhow::Error::new(error.clone()), write, None);
        let extensions = serde_json::to_value(refusal.extensions.unwrap()).unwrap();
        assert_eq!(extensions["code"], expected, "{error:?}");
    }
    let refusal = store_refusal(
        anyhow::anyhow!("disk failure"),
        StoreWrite::DeleteModel,
        None,
    );
    assert!(refusal.extensions.is_none());
    assert_eq!(refusal.message, "disk failure");
}

// ---------------------------------------------------------------------------
// Run visibility

#[tokio::test]
async fn a_cross_customer_clone_run_is_hidden_from_the_source_customer() {
    let f = fixture().await;
    f.define(
        &f.engine_a,
        "src",
        &f.definition(&[&f.sensor_a], OWN_ADDRESS, ""),
    )
    .await;
    let trained = f.train_to_completion("src", &f.engine_a).await;
    let res = f
        .sys(&clone(
            "src",
            "dst",
            &f.engine_b,
            (&f.server_name_b, OWN_ADDRESS_B),
            &[&f.sensor_b],
            "",
        ))
        .await;
    let id = run_id(&data(res)["cloneModel"]);

    let query = "{ models { edges { node { name activeRun { id source } \
                 definition { activeRun { id } lastRun { id model } } } } } \
                 trainingDefinition(name: \"src\") { activeRun { id } lastRun { id model } } \
                 modelRuns(model: \"src\") { id model source } }";
    let res = f.sec(query, &[A]).await;
    let response = data(res);
    let node = &response["models"]["edges"][0]["node"];
    assert_eq!(node["name"], "src");
    assert_eq!(node["activeRun"], Value::Null);
    assert_eq!(node["definition"]["activeRun"], Value::Null);
    let last_run = json!({ "id": trained.to_string(), "model": "src" });
    assert_eq!(node["definition"]["lastRun"], last_run);
    assert_eq!(
        response["trainingDefinition"],
        json!({ "activeRun": null, "lastRun": last_run })
    );
    assert_eq!(
        response["modelRuns"],
        json!([{ "id": trained.to_string(), "model": "src", "source": null }])
    );
    assert!(!response.to_string().contains("dst"), "{response}");

    let res = f.sys(query).await;
    let response = data(res);
    let clone_run = json!({ "id": id.to_string(), "source": "src" });
    let src = response["models"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| edge["node"]["name"] == "src")
        .unwrap()
        .clone();
    assert_eq!(src["node"]["activeRun"], clone_run);
    assert_eq!(
        response["trainingDefinition"]["activeRun"]["id"],
        id.to_string()
    );
    assert_eq!(
        response["modelRuns"][1],
        json!({ "id": id.to_string(), "model": "dst", "source": "src" })
    );

    // The target's customer sees the run, but not its source.
    let res = f
        .sec(
            "{ trainingDefinition(name: \"dst\") { activeRun { id source } lastRun { source } } \
             modelRuns(model: \"dst\") { id source } }",
            &[B],
        )
        .await;
    assert_eq!(
        data(res),
        json!({
            "trainingDefinition": {
                "activeRun": { "id": id.to_string(), "source": null },
                "lastRun": { "source": null },
            },
            "modelRuns": [{ "id": id.to_string(), "source": null }],
        })
    );
}

// ---------------------------------------------------------------------------
// The definition snapshot

#[tokio::test]
async fn the_trained_definition_is_a_snapshot() {
    let f = fixture().await;
    let first = f.definition(&[&f.sensor_a], OWN_ADDRESS, "eps = 5.0");
    f.define(&f.engine_a, "snap", &first).await;
    let first_run = f.train_to_completion("snap", &f.engine_a).await;
    let second = f.definition(&[&f.sensor_a2], OWN_ADDRESS, "eps = 2.0");
    let res = f.sec(&update("snap", &second), &[A]).await;
    assert!(res.errors.is_empty(), "{res:?}");

    // (a) The model keeps what trained it; the definition is the next one.
    let read = "{ models { edges { node { name state trainedDefinition trainedRunId \
                trainingSources definition { definition } \
                previousTrainingResult { trainedDefinition trainedRunId } } } } }";
    let res = f.sec(read, &[A]).await;
    assert_eq!(
        data(res)["models"]["edges"][0]["node"],
        json!({
            "name": "snap",
            "state": "READY",
            "trainedDefinition": first,
            "trainedRunId": first_run.to_string(),
            "trainingSources": [f.sensor_a],
            "definition": { "definition": second },
            "previousTrainingResult": null,
        })
    );

    // (b) A clone starts from the trained definition.
    let res = f
        .sec(
            &clone(
                "snap",
                "snap-clone",
                &f.engine_a2,
                (&f.server_name, OWN_ADDRESS),
                &[&f.logs_a],
                "",
            ),
            &[A],
        )
        .await;
    let clone_run = run_id(&data(res)["cloneModel"]);
    let res = f
        .sec(
            "{ trainingDefinition(name: \"snap-clone\") { definition } }",
            &[A],
        )
        .await;
    let cloned = data(res)["trainingDefinition"]["definition"]
        .as_str()
        .unwrap()
        .to_string();
    let cloned = TrainingDocument::parse(&cloned).unwrap();
    let expected = TrainingDocument {
        sources: vec![f.logs_a.clone()],
        ..TrainingDocument::parse(&first).unwrap()
    };
    assert_eq!(cloned, expected);
    assert_eq!(cloned.eps, Some(5.0));
    complete(&f.store(), clone_run, &f.engine_a, "snap-clone");

    // (c) A retrain makes the edited definition the trained one.
    let second_run = f.train_to_completion("snap", &f.engine_a).await;
    let res = f.sec(read, &[A]).await;
    let response = data(res);
    let node = response["models"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| edge["node"]["name"] == "snap")
        .unwrap()["node"]
        .clone();
    assert_eq!(node["trainedDefinition"], second);
    assert_eq!(node["trainedRunId"], second_run.to_string());
    assert_eq!(node["trainingSources"], json!([f.sensor_a2]));
    assert_eq!(
        node["previousTrainingResult"],
        json!({ "trainedDefinition": first, "trainedRunId": first_run.to_string() })
    );

    // Another customer reads none of it.
    let res = f.sec(read, &[B]).await;
    assert_eq!(data(res)["models"]["edges"], json!([]));
    for query in [
        "{ trainingDefinition(name: \"snap\") { definition } }",
        "{ modelRuns(model: \"snap\") { id } }",
    ] {
        forbidden(&f.sec(query, &[B]).await);
    }
}

// ---------------------------------------------------------------------------
// removeModel and assignModel

#[tokio::test]
async fn remove_model_returns_the_guard_refusal_or_deletes() {
    let f = fixture().await;
    let used = model_on(&f.store(), "used", A, &f.engine_a);
    name_in_documents(&f.store(), &f.engine_a, "used", 7, None);
    let res = f.sec(&remove_model("used"), &[A]).await;
    assert_eq!(
        refused(&res),
        ("MODEL_IN_USE".into(), "name".into(), "used".into())
    );
    let (_, extensions) = single_error(&res);
    assert_eq!(extensions["detectorId"], 7);
    assert_eq!(extensions["nodeId"], f.engine_a.node_id.to_string());
    assert_eq!(extensions["agentKey"], ENGINE_KEY);

    insert_indicator(&f.store(), "ind", used);
    let unused = model_on(&f.store(), "indicated", A, &f.engine_a2);
    insert_indicator(&f.store(), "held", unused);
    insert_definition(&f.store(), "other", A, &f.engine_a2, "held");
    let res = f.sys(&remove_model("indicated")).await;
    assert_eq!(
        refused(&res),
        ("MODEL_IN_USE".into(), "name".into(), "held".into())
    );
    let (_, extensions) = single_error(&res);
    assert_eq!(extensions["definition"], "other");

    f.define(
        &f.engine_b,
        "busy",
        &f.definition(&[&f.sensor_b], OWN_ADDRESS, ""),
    )
    .await;
    f.train_to_completion("busy", &f.engine_b).await;
    let id = f.train("busy").await;
    let res = f.sys(&remove_model("busy")).await;
    assert_eq!(
        refused(&res),
        ("MODEL_IN_USE".into(), "name".into(), id.to_string())
    );

    let free = model_on(&f.store(), "free", A, &f.engine_a2);
    let res = f.sec(&remove_model("free"), &[A]).await;
    assert_eq!(data(res), json!({ "removeModel": "free" }));
    assert!(f.store().model_map().get_by_id(free).unwrap().is_none());
    let res = f.sys(&remove_model("free")).await;
    assert_eq!(
        refused(&res),
        ("NOT_FOUND".into(), "name".into(), "free".into())
    );
}

#[tokio::test]
async fn assign_model_gives_a_model_with_no_instance_an_instance() {
    let f = fixture().await;
    let id = model_on(&f.store(), "orphan", A, &f.engine_a);
    model_on(&f.store(), "owned", A, &f.engine_a2);
    uninstall(&f.store(), &f.engine_a);
    assert_eq!(
        model_states(&f).await[0]["node"],
        json!({ "name": "orphan", "state": "NO_INSTANCE", "instance": null })
    );

    let res = f.sys(&assign("owned", &f.engine_a2)).await;
    assert_eq!(code(&res), "ASSIGN_REFUSED");
    let res = f.sys(&assign("orphan", &f.engine_b)).await;
    assert_eq!(code(&res), "ASSIGN_REFUSED");
    let res = f.sys(&assign("orphan", &f.engine_a)).await;
    assert_eq!(code(&res), "INSTANCE_NOT_ELIGIBLE");
    let res = f.sys(&assign("missing", &f.engine_a2)).await;
    assert_eq!(code(&res), "NOT_FOUND");

    let res = f.sec(&assign("orphan", &f.engine_a2), &[A]).await;
    assert_eq!(data(res), json!({ "assignModel": "orphan" }));
    let model = f.store().model_map().get_by_id(id).unwrap().unwrap();
    assert_eq!(model.instance.as_ref(), Some(&f.engine_a2));
    assert_eq!(
        model_states(&f).await[0]["node"],
        json!({
            "name": "orphan",
            "state": "READY",
            "instance": { "nodeId": f.engine_a2.node_id.to_string() },
        })
    );
}

// ---------------------------------------------------------------------------
// States and reads

#[tokio::test]
async fn model_and_definition_reads_reflect_the_store() {
    let f = fixture().await;
    model_on(&f.store(), "doc", A, &f.engine_a);
    name_in_documents(&f.store(), &f.engine_a, "doc", 1, Some(2));
    let res = f
        .sys(
            "{ models { edges { node { name state activeRun { id } definition { name } \
             detectors { nodeId agentKey detectorId applied pending } } } } }",
        )
        .await;
    let node_id = f.engine_a.node_id.to_string();
    assert_eq!(
        data(res)["models"]["edges"][0]["node"],
        json!({
            "name": "doc",
            "state": "READY",
            "activeRun": null,
            "definition": null,
            "detectors": [
                { "nodeId": node_id, "agentKey": ENGINE_KEY, "detectorId": "1", "applied": true, "pending": false },
                { "nodeId": node_id, "agentKey": ENGINE_KEY, "detectorId": "2", "applied": false, "pending": true },
            ],
        })
    );

    f.define(
        &f.engine_a2,
        "def",
        &f.definition(&[&f.sensor_a], OWN_ADDRESS, ""),
    )
    .await;
    assert_eq!(definition_state(&f, "def").await, "NEVER_TRAINED");
    let id = f.train("def").await;
    assert_eq!(definition_state(&f, "def").await, "TRAINING");
    complete(&f.store(), id, &f.engine_a2, "def");
    assert_eq!(definition_state(&f, "def").await, "READY");
    let id = f.train("def").await;
    let res = f
        .sys("{ models { edges { node { name state activeRun { id kind model state } } } } }")
        .await;
    let response = data(res);
    let node = response["models"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|edge| edge["node"]["name"] == "def")
        .unwrap()["node"]
        .clone();
    assert_eq!(
        node,
        json!({
            "name": "def",
            "state": "TRAINING",
            "activeRun": { "id": id.to_string(), "kind": "TRAIN", "model": "def", "state": "REQUESTED" },
        })
    );
    uninstall(&f.store(), &f.engine_a2);
    assert_eq!(definition_state(&f, "def").await, "NO_INSTANCE");
}

// ---------------------------------------------------------------------------
// Customer scope

#[tokio::test]
async fn a_security_administrator_of_another_customer_is_refused() {
    let f = fixture().await;
    let text_a = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    f.define(&f.engine_a2, "def-a", &text_a).await;
    f.define(&f.engine_a, "src-a", &text_a).await;
    f.train_to_completion("src-a", &f.engine_a).await;
    let run_a = f.train("def-a").await;
    let res = f
        .sys(&clone(
            "src-a",
            "clone-a",
            &f.engine_a2,
            (&f.server_name, OWN_ADDRESS),
            &[&f.sensor_a2],
            "",
        ))
        .await;
    let clone_run_a = run_id(&data(res)["cloneModel"]);
    let text_b = f.definition(&[&f.sensor_b], OWN_ADDRESS, "");
    f.define(&f.engine_b, "src-b", &text_b).await;
    f.train_to_completion("src-b", &f.engine_b).await;
    model_on(&f.store(), "orphan-b", B, &f.engine_b);
    let calls = f.relay.calls().len();

    let res = f.sec("{ trainingDefinitions { name } }", &[B]).await;
    assert_eq!(
        data(res),
        json!({ "trainingDefinitions": [{ "name": "src-b" }] })
    );
    let res = f.sec("{ trainingDefinitions { name } }", &[A]).await;
    assert_eq!(
        data(res),
        json!({ "trainingDefinitions": [
            { "name": "clone-a" }, { "name": "def-a" }, { "name": "src-a" },
        ] })
    );
    let res = f
        .sec("{ trainingDefinition(name: \"missing\") { name } }", &[B])
        .await;
    assert_eq!(data(res), json!({ "trainingDefinition": null }));
    let res = f
        .sec("{ modelRuns(model: \"missing\") { id } }", &[B])
        .await;
    assert_eq!(code(&res), "NOT_FOUND");

    let text_b_on_a = f.definition(&[&f.sensor_b], OWN_ADDRESS, "");
    for query in [
        "{ trainingDefinition(name: \"def-a\") { name } }".to_string(),
        "{ modelRuns(model: \"def-a\") { id } }".to_string(),
        "{ modelRuns(model: \"src-a\") { id } }".to_string(),
        insert(&f.engine_a, "forged", &text_b_on_a),
        update("def-a", &text_b_on_a),
        remove_definition("def-a"),
        train("src-a"),
        cancel(&run_a.to_string()),
        cancel(&clone_run_a.to_string()),
        clone(
            "src-a",
            "forged",
            &f.engine_b,
            (&f.server_name_b, OWN_ADDRESS_B),
            &[&f.sensor_b],
            "",
        ),
        clone(
            "src-b",
            "forged",
            &f.engine_a,
            (&f.server_name, OWN_ADDRESS),
            &[&f.sensor_a],
            "",
        ),
        remove_model("src-a"),
        assign("src-a", &f.engine_b),
        assign("orphan-b", &f.engine_a),
    ] {
        let res = f.sec(&query, &[B]).await;
        forbidden(&res);
    }
    assert_eq!(f.relay.calls().len(), calls);
    assert!(stored(&f.store(), "forged").is_none());
    assert_eq!(f.run_state(run_a), Some(RunState::Requested));
    assert_eq!(f.run_state(clone_run_a), Some(RunState::Requested));
    assert!(model_by_name(&f.store(), "src-a").unwrap().is_some());
    assert_eq!(
        stored(&f.store(), "def-a").unwrap().definition,
        text_a,
        "the update wrote nothing"
    );
}

// ---------------------------------------------------------------------------
// The engine configuration lock

#[tokio::test]
async fn writers_wait_for_the_engine_config_lock() {
    let f = fixture().await;
    let text = f.definition(&[&f.sensor_a], OWN_ADDRESS, "");
    f.define(&f.engine_a, "src", &text).await;
    f.train_to_completion("src", &f.engine_a).await;
    f.define(&f.engine_a2, "upd", &text).await;
    f.define(&f.engine_a2, "trn", &text).await;
    model_on(&f.store(), "doomed", A, &f.engine_a2);
    let removed =
        insert_engine_instance(&f.store(), A, "engine-gone.example.com", "002.reconverge");
    model_on(&f.store(), "orphan", A, &removed);
    uninstall(&f.store(), &removed);

    let snapshot = |f: &Fixture| {
        let store = f.store();
        (
            store.training_definitions().unwrap(),
            store.model_runs("src").unwrap(),
            store.model_runs("trn").unwrap(),
            model_by_name(&store, "doomed").unwrap().is_some(),
            model_by_name(&store, "orphan").unwrap().unwrap().instance,
        )
    };
    let edited = f.definition(&[&f.sensor_a2], OWN_ADDRESS, "eps = 4.0");
    let queries = [
        insert(&f.engine_a2, "new", &text),
        update("upd", &edited),
        train("trn"),
        clone(
            "src",
            "copy",
            &f.engine_a2,
            (&f.server_name, OWN_ADDRESS),
            &[&f.sensor_a2],
            "",
        ),
        remove_model("doomed"),
        assign("orphan", &f.engine_a2),
    ];
    for query in &queries {
        let before = snapshot(&f);
        let guard = f.schema.hold_engine_config_lock().await;
        let (res, ()) = tokio::join!(f.sys(query), async {
            while f.schema.engine_config_lock_users() < 2 {
                tokio::task::yield_now().await;
            }
            assert_eq!(snapshot(&f), before, "{query}");
            drop(guard);
        });
        assert!(res.errors.is_empty(), "{query}: {res:?}");
        assert_ne!(snapshot(&f), before, "{query}");
        assert_eq!(f.schema.engine_config_lock_users(), 0);
    }
}
