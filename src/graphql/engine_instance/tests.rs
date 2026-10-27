//! Resolver tests of run once, engine start and stop, and the engine instance
//! read.

use chrono::{DateTime, Utc};
use review_database::{
    AgentKind, DetectorSourceStatus, EngineDetectorRef, EngineDocumentRefs, EngineDocumentWrite,
    ModelInstance, NodeUpdate, Store,
};
use serde_json::{Value, json};

use crate::graphql::{
    Role, TestSchema,
    model_test_support::{TestModel, data, single_error},
    run_test_support::{
        Relay, RelayAnswer, RelayCall, insert_agent_node, insert_data_store_node,
        insert_engine_instance, insert_sensor_node, relay_schema,
    },
    sampling_test_support::{
        PolicyShape, generator_config, insert_assigned_policy, insert_generator_node_with,
    },
};

const A: u32 = 1;
const B: u32 = 2;
const ENGINE_KEY: &str = "001.reconverge";
const ENGINE_A_HOST: &str = "engine-a.example.com";
const ENGINE_B_HOST: &str = "engine-b.example.com";
const STORE_HOST: &str = "store.example.com";
/// The address Data Store `STORE_HOST` publishes on.
const OWN_ADDRESS: &str = "10.0.0.5:38371";

struct Fixture {
    schema: TestSchema,
    relay: Relay,
    engine_a: ModelInstance,
    engine_b: ModelInstance,
    sensor_a: String,
    server_name: String,
}

impl Fixture {
    fn store(&self) -> std::sync::RwLockReadGuard<'_, Store> {
        self.schema.store()
    }

    async fn sys(&self, query: &str) -> async_graphql::Response {
        self.schema.execute_as_system_admin(query).await
    }

    async fn as_role(&self, query: &str, role: Role, customers: &[u32]) -> async_graphql::Response {
        self.schema
            .execute_as_scoped_user(query, role, Some(customers.to_vec()))
            .await
    }

    async fn sec(&self, query: &str, customers: &[u32]) -> async_graphql::Response {
        self.as_role(query, Role::SecurityAdministrator, customers)
            .await
    }

    /// Returns the stored state and detector statuses of `instance`.
    fn records(
        &self,
        instance: &ModelInstance,
    ) -> (
        review_database::EngineInstanceState,
        Vec<(i32, review_database::DetectorStatus)>,
    ) {
        let store = self.store();
        (
            store.engine_instance_state(instance).unwrap(),
            store.detector_statuses(instance).unwrap(),
        )
    }

    fn node(&self, node_id: u32) -> review_database::Node {
        self.store()
            .node_map()
            .get_by_id(node_id)
            .expect("read node")
            .expect("node exists")
            .0
    }

    /// Replaces the profiles of node `node_id` through a plain node update.
    fn set_profiles(
        &self,
        node_id: u32,
        profile: Option<review_database::NodeProfile>,
        draft: Option<review_database::NodeProfile>,
    ) {
        let old = NodeUpdate::from(self.node(node_id));
        let mut new = NodeUpdate::from(self.node(node_id));
        new.profile = profile;
        new.profile_draft = draft;
        self.store()
            .node_map()
            .update(node_id, &old, &new)
            .expect("update profiles");
    }
}

async fn fixture() -> Fixture {
    let (schema, relay) = relay_schema().await;
    relay.resolve(STORE_HOST, 1, &["10.0.0.5"]);
    let store = schema.store();
    let engine_a = insert_engine_instance(&store, A, ENGINE_A_HOST, ENGINE_KEY);
    let engine_b = insert_engine_instance(&store, B, ENGINE_B_HOST, ENGINE_KEY);
    let sensor_a = insert_sensor_node(&store, A, "sensor-a.example.com");
    let server_name = insert_data_store_node(&store, A, STORE_HOST);
    for (instance, customer_id, prefix) in [(&engine_a, A, "a"), (&engine_b, B, "b")] {
        for n in 1..=3 {
            TestModel {
                instance: instance.clone(),
                ..TestModel::new(&format!("model-{prefix}{n}"), customer_id)
            }
            .replace(&store);
        }
    }
    drop(store);
    Fixture {
        schema,
        relay,
        engine_a,
        engine_b,
        sensor_a,
        server_name,
    }
}

/// Records the applied and pending references of `instance`, each detector
/// `(id, model)`.
fn write_refs(
    store: &Store,
    instance: &ModelInstance,
    applied: &[(i32, &str)],
    pending: &[(i32, &str)],
) {
    let refs = |detectors: &[(i32, &str)]| EngineDocumentRefs {
        detectors: detectors
            .iter()
            .map(|&(id, model)| EngineDetectorRef {
                id,
                model: model.to_string(),
                sources: vec![],
                indicator: None,
            })
            .collect(),
    };
    let mut map = store.node_map();
    let (node, _, _) = map
        .get_by_id(instance.node_id)
        .expect("read engine node")
        .expect("engine node exists");
    let update = NodeUpdate::from(node);
    let document = EngineDocumentWrite {
        agent_key: instance.agent_key.clone(),
        applied: Some(refs(applied)),
        pending: Some(refs(pending)),
    };
    map.update_with_engine_documents(instance.node_id, &update, &update, &[document])
        .expect("write engine document references");
}

fn time(text: &str) -> DateTime<Utc> {
    text.parse().expect("an RFC 3339 time")
}

/// Returns a status of a detector that has finished a round.
fn finished_status() -> review_database::DetectorStatus {
    review_database::DetectorStatus {
        state: review_database::DetectorState::Running,
        finished_at: Some(time("2026-10-21T00:05:00Z")),
        outcome: Some(review_database::RoundOutcome::Failed),
        reason: Some("source failed".to_string()),
        events: 12_345_678_901,
        sources: vec![
            DetectorSourceStatus {
                source: "piglet.a.example.com".to_string(),
                state: review_database::SourceState::Served,
                reason: None,
            },
            DetectorSourceStatus {
                source: "piglet.b.example.com".to_string(),
                state: review_database::SourceState::ServedByNoNode,
                reason: None,
            },
            DetectorSourceStatus {
                source: "reproduce.c.example.com".to_string(),
                state: review_database::SourceState::Failed,
                reason: Some("read failed".to_string()),
            },
        ],
        reported_at: time("2026-10-21T00:05:01Z"),
    }
}

/// Returns a status of a detector that has not finished a round yet.
fn first_status(state: review_database::DetectorState) -> review_database::DetectorStatus {
    review_database::DetectorStatus {
        state,
        finished_at: None,
        outcome: None,
        reason: None,
        events: 0,
        sources: vec![],
        reported_at: time("2026-10-21T00:00:01Z"),
    }
}

fn run_once(instance: &ModelInstance, detector_id: &str) -> String {
    format!(
        "mutation {{ runDetectorOnce(nodeId: \"{}\", agentKey: \"{}\", detectorId: \"{detector_id}\") }}",
        instance.node_id, instance.agent_key
    )
}

fn start(instance: &ModelInstance) -> String {
    format!(
        "mutation {{ startEngineInstance(nodeId: \"{}\", agentKey: \"{}\") }}",
        instance.node_id, instance.agent_key
    )
}

fn stop(instance: &ModelInstance) -> String {
    format!(
        "mutation {{ stopEngineInstance(nodeId: \"{}\", agentKey: \"{}\") }}",
        instance.node_id, instance.agent_key
    )
}

fn read(instance: &ModelInstance) -> String {
    format!(
        "{{ engineInstance(nodeId: \"{}\", agentKey: \"{}\") {{ nodeId agentKey stopped \
         detectors {{ detectorId state finishedAt outcome reason events \
         sources {{ source state reason }} reportedAt }} }} }}",
        instance.node_id, instance.agent_key
    )
}

/// Returns every operation on `instance`, the mutations with the detector id
/// 1, and the field of `data` that holds each one's result.
fn operations(instance: &ModelInstance) -> [(String, &'static str); 4] {
    [
        (run_once(instance, "1"), "runDetectorOnce"),
        (start(instance), "startEngineInstance"),
        (stop(instance), "stopEngineInstance"),
        (read(instance), "engineInstance"),
    ]
}

fn lookup_key(instance: &ModelInstance, hostname: &str) -> String {
    format!("{}.{hostname}", instance.agent_key)
}

/// Returns the extensions of the single refusal of `res`.
fn extensions(res: &async_graphql::Response) -> Value {
    single_error(res).1
}

/// Returns the code, `field` and `value` of the single refusal of `res`.
fn refused(res: &async_graphql::Response) -> (String, String, String) {
    let extensions = extensions(res);
    let text = |key: &str| match &extensions[key] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    (text("code"), text("field"), text("value"))
}

fn forbidden(res: &async_graphql::Response) {
    let (message, extensions) = single_error(res);
    assert_eq!(message, "Forbidden", "{res:?}");
    assert!(extensions.get("code").is_none(), "{res:?}");
}

// ---------------------------------------------------------------------------
// Start and stop

#[tokio::test]
async fn start_and_stop_relay_the_instance_and_write_nothing() {
    let f = fixture().await;
    {
        let store = f.store();
        write_refs(&store, &f.engine_a, &[(1, "model-a1")], &[(2, "model-a2")]);
        store
            .set_detector_status(&f.engine_a, 1, &finished_status())
            .unwrap();
    }
    let before = f.records(&f.engine_a);

    let res = f.sec(&stop(&f.engine_a), &[A]).await;
    assert_eq!(data(res), json!({ "stopEngineInstance": true }));
    let res = f.sec(&start(&f.engine_a), &[A]).await;
    assert_eq!(data(res), json!({ "startEngineInstance": true }));
    assert_eq!(
        f.relay.calls(),
        [
            RelayCall::StopEngineInstance {
                node_id: f.engine_a.node_id,
                agent_key: ENGINE_KEY.to_string(),
            },
            RelayCall::StartEngineInstance {
                node_id: f.engine_a.node_id,
                agent_key: ENGINE_KEY.to_string(),
            },
        ]
    );
    assert_eq!(f.records(&f.engine_a), before, "nothing is written");

    // A stopped instance is started and stopped all the same: review-web
    // reads no stopped state for either.
    f.store()
        .set_engine_instance_stopped(&f.engine_a, true)
        .unwrap();
    let before = f.records(&f.engine_a);
    let res = f.sys(&start(&f.engine_a)).await;
    assert_eq!(data(res), json!({ "startEngineInstance": true }));
    let res = f.sys(&stop(&f.engine_a)).await;
    assert_eq!(data(res), json!({ "stopEngineInstance": true }));
    assert_eq!(f.records(&f.engine_a), before, "nothing is written");
}

#[tokio::test]
async fn a_failed_start_or_stop_returns_the_backend_error_text() {
    let f = fixture().await;
    write_refs(&f.store(), &f.engine_a, &[(1, "model-a1")], &[]);
    let before = f.records(&f.engine_a);

    for (answer, message) in [
        (RelayAnswer::Unreachable, "no live connection"),
        (
            RelayAnswer::Refused("unit is enabled and running".to_string()),
            "the engine refused the request: unit is enabled and running",
        ),
    ] {
        f.relay.answer_with(answer);
        for query in [start(&f.engine_a), stop(&f.engine_a)] {
            let res = f.sec(&query, &[A]).await;
            assert_eq!(single_error(&res).0, message, "{query}");
            assert_eq!(
                refused(&res),
                (
                    "INSTANCE_UNREACHABLE".into(),
                    "agentKey".into(),
                    ENGINE_KEY.into()
                ),
                "{query}"
            );
        }
    }
    assert_eq!(f.relay.calls().len(), 4);
    assert_eq!(f.records(&f.engine_a), before, "nothing is written");
}

// ---------------------------------------------------------------------------
// Run once

#[tokio::test]
async fn run_once_relays_a_detector_of_the_applied_document() {
    let f = fixture().await;
    write_refs(
        &f.store(),
        &f.engine_a,
        &[(1, "model-a1"), (-7, "model-a2")],
        &[],
    );
    let before = f.records(&f.engine_a);

    let res = f.sec(&run_once(&f.engine_a, "1"), &[A]).await;
    assert_eq!(data(res), json!({ "runDetectorOnce": true }));
    let res = f.sys(&run_once(&f.engine_a, "-7")).await;
    assert_eq!(data(res), json!({ "runDetectorOnce": true }));
    let key = lookup_key(&f.engine_a, ENGINE_A_HOST);
    assert_eq!(
        f.relay.calls(),
        [
            RelayCall::RunDetectorOnce {
                agent_lookup_key: key.clone(),
                detector_id: 1,
            },
            RelayCall::RunDetectorOnce {
                agent_lookup_key: key,
                detector_id: -7,
            },
        ]
    );
    assert_eq!(f.records(&f.engine_a), before, "nothing is written");
}

#[tokio::test]
async fn run_once_relays_a_disabled_detector() {
    let f = fixture().await;
    let document = format!(
        r#"
[[detectors]]
id = 7
enabled = false
model = "model-a1"
sources = ["{sensor}"]
period = "5m"
start = "2026-10-21T00:00:00Z"
batch_size = 500000

[detectors.data_store]
address = "{OWN_ADDRESS}"
server_name = "{server_name}"
"#,
        sensor = f.sensor_a,
        server_name = f.server_name,
    );
    // Seeds the draft through the agent row, then applies the node.
    let node = f.node(f.engine_a.node_id);
    let old = node.agents[0].clone();
    let mut new = old.clone();
    new.draft = Some(document.clone().try_into().expect("valid TOML"));
    f.store().agents_map().update(&old, &new).unwrap();
    let profile = node.profile.as_ref().expect("applied profile");
    let profile_input = format!(
        "{{ customerId: \"{}\", description: \"\", hostname: \"{}\" }}",
        profile.customer_id, profile.hostname
    );
    let apply = format!(
        "mutation {{ applyNode(id: \"{id}\", node: {{ name: \"{name}\", nameDraft: \"{name}\", \
         profile: {profile_input}, profileDraft: {profile_input}, agents: [{{ kind: \
         UNSUPERVISED, key: \"{ENGINE_KEY}\", status: ENABLED, config: null, draft: {draft} }}], \
         externalServices: [] }}) }}",
        id = node.id,
        name = node.name,
        draft = serde_json::to_string(&document).unwrap(),
    );
    data(f.sec(&apply, &[A]).await);
    assert_eq!(
        f.records(&f.engine_a).0.applied.detectors[0].id,
        7,
        "the disabled detector is applied"
    );

    let res = f.sec(&run_once(&f.engine_a, "7"), &[A]).await;
    assert_eq!(data(res), json!({ "runDetectorOnce": true }));
    assert_eq!(
        f.relay.calls(),
        [RelayCall::RunDetectorOnce {
            agent_lookup_key: lookup_key(&f.engine_a, ENGINE_A_HOST),
            detector_id: 7,
        }]
    );
}

#[tokio::test]
async fn run_once_refuses_a_stopped_instance_before_an_unknown_detector() {
    let f = fixture().await;
    {
        let store = f.store();
        write_refs(&store, &f.engine_a, &[(1, "model-a1")], &[]);
        store
            .set_engine_instance_stopped(&f.engine_a, true)
            .unwrap();
    }

    for detector_id in ["1", "2", "x"] {
        let res = f.sec(&run_once(&f.engine_a, detector_id), &[A]).await;
        assert_eq!(
            refused(&res),
            (
                "INSTANCE_STOPPED".into(),
                "agentKey".into(),
                ENGINE_KEY.into()
            ),
            "{detector_id}"
        );
        let extensions = extensions(&res);
        for key in ["detectorId", "nodeId", "agentKey"] {
            assert!(extensions.get(key).is_none(), "{key}: {res:?}");
        }
    }
    assert_eq!(f.relay.calls(), []);
}

#[tokio::test]
async fn run_once_refuses_a_detector_not_in_the_applied_document() {
    let f = fixture().await;
    write_refs(
        &f.store(),
        &f.engine_a,
        &[(1, "model-a1")],
        &[(2, "model-a2")],
    );

    // Only in the pending document, and in neither.
    for (detector_id, id) in [("2", 2), ("3", 3)] {
        let res = f.sec(&run_once(&f.engine_a, detector_id), &[A]).await;
        assert_eq!(
            refused(&res),
            (
                "DETECTOR_NOT_FOUND".into(),
                "detectorId".into(),
                detector_id.into()
            )
        );
        assert_eq!(extensions(&res)["detectorId"], json!(id));
    }

    // Not an i32.
    for detector_id in ["x", "1.0", "2147483648"] {
        let res = f.sec(&run_once(&f.engine_a, detector_id), &[A]).await;
        assert_eq!(
            refused(&res),
            (
                "DETECTOR_NOT_FOUND".into(),
                "detectorId".into(),
                detector_id.into()
            )
        );
        assert!(
            extensions(&res).get("detectorId").is_none(),
            "{detector_id}: {res:?}"
        );
    }

    // An instance with no record has no applied detector.
    let res = f.sys(&run_once(&f.engine_b, "1")).await;
    assert_eq!(refused(&res).0, "DETECTOR_NOT_FOUND");
    assert_eq!(f.relay.calls(), []);
}

#[tokio::test]
async fn run_once_maps_relay_errors() {
    let f = fixture().await;
    write_refs(&f.store(), &f.engine_a, &[(1, "model-a1")], &[]);
    let before = f.records(&f.engine_a);
    let key = lookup_key(&f.engine_a, ENGINE_A_HOST);

    f.relay
        .answer_with(RelayAnswer::Refused("a round is running".to_string()));
    let res = f.sec(&run_once(&f.engine_a, "1"), &[A]).await;
    assert_eq!(
        refused(&res),
        (
            "ENGINE_REFUSED".into(),
            "detectorId".into(),
            "a round is running".into()
        )
    );
    assert_eq!(extensions(&res)["detectorId"], json!(1));

    f.relay.answer_with(RelayAnswer::Unreachable);
    let res = f.sec(&run_once(&f.engine_a, "1"), &[A]).await;
    assert_eq!(
        refused(&res),
        (
            "INSTANCE_UNREACHABLE".into(),
            "detectorId".into(),
            key.clone()
        )
    );
    assert_eq!(extensions(&res)["detectorId"], json!(1));

    assert_eq!(f.relay.calls().len(), 2);
    assert_eq!(f.records(&f.engine_a), before, "nothing is written");
}

#[tokio::test]
async fn the_default_backend_is_unreachable() {
    let schema = TestSchema::new().await;
    let engine = {
        let store = schema.store();
        let engine = insert_engine_instance(&store, A, ENGINE_A_HOST, ENGINE_KEY);
        TestModel {
            instance: engine.clone(),
            ..TestModel::new("model-a1", A)
        }
        .replace(&store);
        write_refs(&store, &engine, &[(1, "model-a1")], &[]);
        engine
    };

    let res = schema
        .execute_as_system_admin(&run_once(&engine, "1"))
        .await;
    assert_eq!(
        refused(&res),
        (
            "INSTANCE_UNREACHABLE".into(),
            "detectorId".into(),
            lookup_key(&engine, ENGINE_A_HOST)
        )
    );
    for query in [start(&engine), stop(&engine)] {
        let res = schema.execute_as_system_admin(&query).await;
        assert_eq!(single_error(&res).0, "Not supported");
        assert_eq!(refused(&res).0, "INSTANCE_UNREACHABLE");
    }
}

// ---------------------------------------------------------------------------
// Eligibility and scope

#[tokio::test]
async fn an_ineligible_agent_is_refused_without_a_backend_call() {
    let f = fixture().await;
    let (sensor, uninstalled, engine_elsewhere) = {
        let store = f.store();
        (
            insert_agent_node(
                &store,
                A,
                "sensor.example.com",
                "001.piglet",
                AgentKind::Sensor,
                Some(1),
            ),
            insert_agent_node(
                &store,
                A,
                "uninstalled.example.com",
                ENGINE_KEY,
                AgentKind::Unsupervised,
                None,
            ),
            insert_engine_instance(&store, A, "engine-a2.example.com", "002.reconverge"),
        )
    };
    let missing_on_a = ModelInstance {
        node_id: f.engine_a.node_id,
        agent_key: engine_elsewhere.agent_key.clone(),
    };
    for instance in [&sensor, &uninstalled, &missing_on_a] {
        for (query, _) in operations(instance) {
            for res in [f.sys(&query).await, f.sec(&query, &[A]).await] {
                assert_eq!(
                    refused(&res),
                    (
                        "INSTANCE_NOT_ELIGIBLE".into(),
                        "agentKey".into(),
                        instance.agent_key.clone()
                    ),
                    "{query}"
                );
            }
        }
    }
    assert_eq!(f.relay.calls(), []);
}

#[tokio::test]
async fn an_instance_without_an_applied_hostname_or_profile_is_not_eligible() {
    let f = fixture().await;
    let node_id = f.engine_a.node_id;
    let applied = f.node(node_id).profile.expect("applied profile");
    let not_eligible = (
        "INSTANCE_NOT_ELIGIBLE".to_string(),
        "nodeId".to_string(),
        node_id.to_string(),
    );

    let mut no_hostname = applied.clone();
    no_hostname.hostname = String::new();
    f.set_profiles(node_id, Some(no_hostname), Some(applied.clone()));
    for (query, _) in operations(&f.engine_a) {
        assert_eq!(refused(&f.sys(&query).await), not_eligible, "{query}");
        assert_eq!(refused(&f.sec(&query, &[A]).await), not_eligible, "{query}");
    }

    // With no applied profile, a scoped caller reaches the node through its
    // draft profile.
    f.set_profiles(node_id, None, Some(applied));
    for (query, _) in operations(&f.engine_a) {
        assert_eq!(refused(&f.sys(&query).await), not_eligible, "{query}");
        assert_eq!(refused(&f.sec(&query, &[A]).await), not_eligible, "{query}");
    }

    // With neither profile, a scoped caller cannot reach the node.
    f.set_profiles(node_id, None, None);
    for (query, _) in operations(&f.engine_a) {
        assert_eq!(refused(&f.sys(&query).await), not_eligible, "{query}");
        forbidden(&f.sec(&query, &[A]).await);
    }
    assert_eq!(f.relay.calls(), []);
}

#[tokio::test]
async fn an_unknown_or_malformed_node_keeps_the_plain_errors() {
    let f = fixture().await;
    let unknown = ModelInstance {
        node_id: 9999,
        agent_key: ENGINE_KEY.to_string(),
    };
    for (query, _) in operations(&unknown) {
        let res = f.sys(&query).await;
        assert_eq!(single_error(&res).0, "no such node", "{query}");
    }
    let res = f
        .sys("mutation { stopEngineInstance(nodeId: \"x\", agentKey: \"001.reconverge\") }")
        .await;
    assert_eq!(single_error(&res).0, "invalid ID");
    assert_eq!(f.relay.calls(), []);
}

#[tokio::test]
async fn a_caller_of_another_customer_is_refused() {
    let f = fixture().await;
    {
        let store = f.store();
        write_refs(&store, &f.engine_a, &[(1, "model-a1")], &[]);
        write_refs(&store, &f.engine_b, &[(1, "model-b1")], &[]);
    }

    for (query, _) in operations(&f.engine_a) {
        forbidden(&f.sec(&query, &[B]).await);
    }
    forbidden(
        &f.as_role(&read(&f.engine_a), Role::SecurityMonitor, &[B])
            .await,
    );
    assert_eq!(f.relay.calls(), [], "the backend is not called");

    for (query, field) in operations(&f.engine_b) {
        let res = data(f.sec(&query, &[B]).await);
        assert!(!res[field].is_null(), "{query}");
    }
    let res = data(
        f.as_role(&read(&f.engine_b), Role::SecurityMonitor, &[B])
            .await,
    );
    assert_eq!(res["engineInstance"]["stopped"], json!(false));
    assert_eq!(f.relay.calls().len(), 3);

    for instance in [&f.engine_a, &f.engine_b] {
        for (query, field) in operations(instance) {
            let res = data(f.sys(&query).await);
            assert!(!res[field].is_null(), "{query}");
        }
    }
    assert_eq!(f.relay.calls().len(), 9);
}

#[tokio::test]
async fn a_security_monitor_is_refused_the_mutations() {
    let f = fixture().await;
    write_refs(&f.store(), &f.engine_a, &[(1, "model-a1")], &[]);
    for (query, _) in &operations(&f.engine_a)[..3] {
        forbidden(&f.as_role(query, Role::SecurityMonitor, &[A]).await);
    }
    assert_eq!(f.relay.calls(), []);
}

// ---------------------------------------------------------------------------
// The engine instance read

#[tokio::test]
async fn the_read_returns_the_stopped_state_and_every_status() {
    let f = fixture().await;
    {
        let store = f.store();
        write_refs(
            &store,
            &f.engine_a,
            &[(3, "model-a3"), (1, "model-a1")],
            &[(2, "model-a2")],
        );
        store
            .set_detector_status(&f.engine_a, 3, &finished_status())
            .unwrap();
        store
            .set_detector_status(
                &f.engine_a,
                2,
                &first_status(review_database::DetectorState::PausedForRun),
            )
            .unwrap();
        store
            .set_engine_instance_stopped(&f.engine_a, true)
            .unwrap();
    }

    let expected = json!({
        "engineInstance": {
            "nodeId": f.engine_a.node_id.to_string(),
            "agentKey": ENGINE_KEY,
            "stopped": true,
            "detectors": [
                {
                    "detectorId": "2",
                    "state": "PAUSED_FOR_RUN",
                    "finishedAt": null,
                    "outcome": null,
                    "reason": null,
                    "events": "0",
                    "sources": [],
                    "reportedAt": time("2026-10-21T00:00:01Z").to_rfc3339(),
                },
                {
                    "detectorId": "3",
                    "state": "RUNNING",
                    "finishedAt": time("2026-10-21T00:05:00Z").to_rfc3339(),
                    "outcome": "FAILED",
                    "reason": "source failed",
                    "events": "12345678901",
                    "sources": [
                        { "source": "piglet.a.example.com", "state": "SERVED", "reason": null },
                        {
                            "source": "piglet.b.example.com",
                            "state": "SERVED_BY_NO_NODE",
                            "reason": null
                        },
                        {
                            "source": "reproduce.c.example.com",
                            "state": "FAILED",
                            "reason": "read failed"
                        },
                    ],
                    "reportedAt": time("2026-10-21T00:05:01Z").to_rfc3339(),
                },
            ],
        }
    });
    assert_eq!(data(f.sec(&read(&f.engine_a), &[A]).await), expected);
    assert_eq!(
        data(
            f.as_role(&read(&f.engine_a), Role::SecurityMonitor, &[A])
                .await
        ),
        expected
    );
}

#[tokio::test]
async fn the_read_shows_every_detector_state_and_outcome() {
    let f = fixture().await;
    {
        let store = f.store();
        write_refs(
            &store,
            &f.engine_a,
            &[(1, "model-a1"), (2, "model-a2"), (3, "model-a3")],
            &[],
        );
        store
            .set_detector_status(
                &f.engine_a,
                1,
                &first_status(review_database::DetectorState::Disabled),
            )
            .unwrap();
        store
            .set_detector_status(
                &f.engine_a,
                2,
                &first_status(review_database::DetectorState::NoModel),
            )
            .unwrap();
        let mut succeeded = finished_status();
        succeeded.outcome = Some(review_database::RoundOutcome::Succeeded);
        store
            .set_detector_status(&f.engine_a, 3, &succeeded)
            .unwrap();
    }
    let res = data(
        f.sys(&format!(
            "{{ engineInstance(nodeId: \"{}\", agentKey: \"{ENGINE_KEY}\") {{ detectors {{ \
             detectorId state outcome }} }} }}",
            f.engine_a.node_id
        ))
        .await,
    );
    assert_eq!(
        res["engineInstance"]["detectors"],
        json!([
            { "detectorId": "1", "state": "DISABLED", "outcome": null },
            { "detectorId": "2", "state": "NO_MODEL", "outcome": null },
            { "detectorId": "3", "state": "RUNNING", "outcome": "SUCCEEDED" },
        ])
    );
}

#[tokio::test]
async fn the_read_of_an_instance_with_no_record_is_empty_and_not_stopped() {
    let f = fixture().await;
    let res = data(f.sec(&read(&f.engine_a), &[A]).await);
    assert_eq!(
        res,
        json!({
            "engineInstance": {
                "nodeId": f.engine_a.node_id.to_string(),
                "agentKey": ENGINE_KEY,
                "stopped": false,
                "detectors": [],
            }
        })
    );
}

#[tokio::test]
async fn the_read_shows_the_delivery_of_each_applied_source() {
    let f = fixture().await;
    let generator = insert_generator_node_with(
        &f.store(),
        "gen-1.example.com",
        A,
        Some(generator_config(&f.server_name)),
    );
    let policy = {
        let store = f.store();
        let policy =
            insert_assigned_policy(&store, "series", A, &generator, PolicyShape::default());
        TestModel {
            instance: f.engine_a.clone(),
            kind: "Timeseries",
            trained_sources: vec![policy.to_string()],
            ..TestModel::new("ts-a", A)
        }
        .replace(&store);
        let detector = |id, model: &str, sources: Vec<String>| EngineDetectorRef {
            id,
            model: model.to_string(),
            sources,
            indicator: None,
        };
        let mut map = store.node_map();
        let (node, _, _) = map.get_by_id(f.engine_a.node_id).unwrap().unwrap();
        let update = NodeUpdate::from(node);
        let document = EngineDocumentWrite {
            agent_key: f.engine_a.agent_key.clone(),
            applied: Some(EngineDocumentRefs {
                detectors: vec![
                    detector(5, "ts-a", vec![policy.to_string(), "999".to_string()]),
                    detector(6, "model-a1", vec![f.sensor_a.clone()]),
                ],
            }),
            pending: Some(EngineDocumentRefs {
                detectors: vec![detector(8, "model-a2", vec![f.sensor_a.clone()])],
            }),
        };
        map.update_with_engine_documents(f.engine_a.node_id, &update, &update, &[document])
            .unwrap();
        // Detector 8 has a status, but only the pending document has it.
        for id in [5, 6, 8] {
            store
                .set_detector_status(&f.engine_a, id, &finished_status())
                .unwrap();
        }
        policy
    };
    f.relay.set_online("gen-1.example.com", &[&generator]);

    let res = data(
        f.sec(
            &format!(
                "{{ engineInstance(nodeId: \"{}\", agentKey: \"{ENGINE_KEY}\") {{ detectors {{ \
                 detectorId sourceDelivery {{ source delivery }} }} }} }}",
                f.engine_a.node_id
            ),
            &[A],
        )
        .await,
    );
    assert_eq!(
        res["engineInstance"]["detectors"],
        json!([
            {
                "detectorId": "5",
                "sourceDelivery": [
                    { "source": policy.to_string(), "delivery": "ASSIGNEE_ONLINE" },
                    { "source": "999", "delivery": null },
                ],
            },
            {
                "detectorId": "6",
                "sourceDelivery": [{ "source": f.sensor_a, "delivery": null }],
            },
            { "detectorId": "8", "sourceDelivery": [] },
        ])
    );
}
