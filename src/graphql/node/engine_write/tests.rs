//! Resolver tests of the engine documents and the node guards of
//! `insertNode`, `updateNodeDraft`, `applyNode` and `applyNodeDraft`.

use chrono::Utc;
use review_database::{
    AgentStatus, EngineDetectorRef, EngineDocumentRefs, ExternalServiceKind, ExternalServiceStatus,
    Lifecycle, ModelMethod, ModelUse, NewTrainingDefinition,
};
use serde_json::{Value, json};

use super::*;
use crate::graphql::{
    Role, TestSchema,
    model_test_support::{TestModel, data, insert_definition, insert_indicator, single_error},
    run_test_support::{
        insert_data_store_node, insert_engine_instance, insert_log_collector_node,
        insert_sensor_node, relay_schema,
    },
};

const A: u32 = 1;
const B: u32 = 2;
const ENGINE_KEY: &str = "001.reconverge";
const STORE_HOST: &str = "store.example.com";
/// The address Data Store `STORE_HOST` publishes on.
const OWN_ADDRESS: &str = "10.0.0.5:38371";
/// An address that is none of a Data Store's own.
const OVERRIDE: &str = "192.0.2.1:9999";

struct Fixture {
    schema: TestSchema,
    engine_a: ModelInstance,
    engine_a2: ModelInstance,
    sensor_a: String,
    sensor_b: String,
    logs_a: String,
    server_name: String,
}

async fn fixture() -> Fixture {
    let (schema, relay) = relay_schema().await;
    relay.resolve(STORE_HOST, 1, &["10.0.0.5"]);
    let store = schema.store();
    let engine_a = insert_engine_instance(&store, A, "engine-a.example.com", ENGINE_KEY);
    let engine_a2 = insert_engine_instance(&store, A, "engine-a2.example.com", ENGINE_KEY);
    let engine_b = insert_engine_instance(&store, B, "engine-b.example.com", ENGINE_KEY);
    let sensor_a = insert_sensor_node(&store, A, "sensor-a.example.com");
    let sensor_b = insert_sensor_node(&store, B, "sensor-b.example.com");
    let logs_a = insert_log_collector_node(&store, A, "logs-a.example.com");
    let server_name = insert_data_store_node(&store, A, STORE_HOST);
    let model_a = model(&store, "model-a", A, &engine_a, "Multifield");
    model(&store, "model-a1", A, &engine_a, "Multifield");
    model(&store, "prefix-a", A, &engine_a, "Prefix");
    model(&store, "model-a2", A, &engine_a2, "Multifield");
    let model_b = model(&store, "model-b", B, &engine_b, "Multifield");
    insert_indicator(&store, "ind-a", model_a);
    insert_indicator(&store, "ind-b", model_b);
    drop(store);
    Fixture {
        schema,
        engine_a,
        engine_a2,
        sensor_a,
        sensor_b,
        logs_a,
        server_name,
    }
}

fn model(store: &Store, name: &str, customer_id: u32, instance: &ModelInstance, kind: &str) -> u32 {
    TestModel {
        instance: instance.clone(),
        kind,
        ..TestModel::new(name, customer_id)
    }
    .replace(store)
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

    /// Returns a document with one detector of id 1 serving `model` from
    /// `sources` through Data Store `STORE_HOST` at its own address.
    fn doc(&self, model: &str, sources: &[&str], extra: &str) -> String {
        detector(1, model, sources, (&self.server_name, OWN_ADDRESS), extra)
    }

    /// Returns a valid document of `engine_a`.
    fn valid(&self) -> String {
        self.doc("model-a", &[&self.sensor_a], "")
    }

    fn node(&self, id: u32) -> Node {
        self.store()
            .node_map()
            .get_by_id(id)
            .expect("read node")
            .expect("node exists")
            .0
    }

    fn agent(&self, instance: &ModelInstance) -> Agent {
        self.node(instance.node_id)
            .agents
            .into_iter()
            .find(|agent| agent.key == instance.agent_key)
            .expect("agent exists")
    }

    /// Returns the `updateNodeDraft` that sets the draft of `instance` to
    /// `draft`, made from the stored node.
    fn save_query(&self, instance: &ModelInstance, draft: Option<&str>) -> String {
        let old = self.node(instance.node_id);
        let new = with_draft(&old, &instance.agent_key, draft);
        update_draft(&old, &new)
    }

    /// Sets the draft of `instance` to `draft` as a Security Administrator
    /// of customer A.
    async fn save(&self, instance: &ModelInstance, draft: Option<&str>) -> async_graphql::Response {
        self.sec(&self.save_query(instance, draft), &[A]).await
    }

    /// Stores `draft` as the draft of `instance` through the agent row, which
    /// writes no references.
    fn seed(&self, instance: &ModelInstance, draft: Option<&str>) {
        let old = self.agent(instance);
        let mut new = old.clone();
        new.draft = draft.map(config);
        self.store()
            .agents_map()
            .update(&old, &new)
            .expect("update agent row");
    }

    /// Applies the stored node of `instance` as a Security Administrator of
    /// customer A.
    async fn apply(&self, node_id: u32) -> async_graphql::Response {
        self.sec(&apply(&self.node(node_id)), &[A]).await
    }

    /// Returns the applied and the pending references of `instance`.
    fn refs(&self, instance: &ModelInstance) -> (EngineDocumentRefs, EngineDocumentRefs) {
        self.store()
            .engine_instance_states()
            .expect("read engine instances")
            .into_iter()
            .find(|state| state.instance == *instance)
            .map(|state| (state.applied, state.pending))
            .unwrap_or_default()
    }

    /// Replaces the profiles of node `id` through a plain node update.
    fn set_profiles(&self, id: u32, profile: Option<NodeProfile>, draft: Option<NodeProfile>) {
        let old = NodeUpdate::from(self.node(id));
        let mut new = NodeUpdate::from(self.node(id));
        new.profile = profile;
        new.profile_draft = draft;
        let store = self.store();
        store
            .node_map()
            .update(id, &old, &new)
            .expect("update profiles");
    }

    /// Returns the node of the sensor or Log Collector source `source`.
    fn source_node(&self, source: &str) -> Node {
        let hostname = source.split_once('.').unwrap().1;
        self.store()
            .node_map()
            .iter(review_database::event::Direction::Forward, None)
            .map(Result::unwrap)
            .find(|node| {
                node.profile
                    .as_ref()
                    .is_some_and(|p| p.hostname == hostname)
            })
            .expect("source node exists")
    }

    /// Returns the `updateNodeDraft` that gives node `node` the draft profile
    /// `customer_id` and `hostname`.
    fn move_query(node: &Node, customer_id: u32, hostname: &str) -> String {
        let mut new = node.clone();
        new.profile_draft = Some(NodeProfile {
            customer_id,
            description: String::new(),
            hostname: hostname.to_string(),
        });
        update_draft(node, &new)
    }
}

fn config(text: &str) -> AgentConfig {
    text.to_string().try_into().expect("valid TOML")
}

/// Returns a `[[detectors]]` entry; `extra` holds further detector keys.
fn detector(
    id: i32,
    model: &str,
    sources: &[&str],
    (server_name, address): (&str, &str),
    extra: &str,
) -> String {
    format!(
        r#"
[[detectors]]
id = {id}
enabled = true
model = "{model}"
sources = {sources}
period = "5m"
start = "2026-10-21T00:00:00Z"
batch_size = 500000
{extra}

[detectors.data_store]
address = "{address}"
server_name = "{server_name}"
"#,
        sources = serde_json::to_string(sources).unwrap(),
    )
}

fn with_draft(node: &Node, agent_key: &str, draft: Option<&str>) -> Node {
    let mut node = node.clone();
    for agent in &mut node.agents {
        if agent.key == agent_key {
            agent.draft = draft.map(config);
        }
    }
    node
}

/// Returns `text` as a GraphQL string literal.
fn gql(text: &str) -> String {
    serde_json::to_string(text).unwrap()
}

fn text(config: Option<&AgentConfig>) -> String {
    config.map_or_else(|| "null".to_string(), |c| gql(c.as_ref()))
}

fn profile_input(profile: Option<&NodeProfile>) -> String {
    profile.map_or_else(
        || "null".to_string(),
        |p| {
            format!(
                "{{ customerId: \"{}\", description: {}, hostname: {} }}",
                p.customer_id,
                gql(&p.description),
                gql(&p.hostname)
            )
        },
    )
}

fn agent_kind(kind: AgentKind) -> &'static str {
    match kind {
        AgentKind::Unsupervised => "UNSUPERVISED",
        AgentKind::Sensor => "SENSOR",
        AgentKind::SemiSupervised => "SEMI_SUPERVISED",
        AgentKind::TimeSeriesGenerator => "TIME_SERIES_GENERATOR",
        AgentKind::LogCollector => "LOG_COLLECTOR",
    }
}

fn agent_status(status: AgentStatus) -> &'static str {
    match status {
        AgentStatus::Disabled => "DISABLED",
        AgentStatus::Enabled => "ENABLED",
        AgentStatus::ReloadFailed => "RELOAD_FAILED",
        AgentStatus::Unknown => "UNKNOWN",
    }
}

fn services(node: &Node) -> String {
    node.external_services
        .iter()
        .map(|service| {
            format!(
                "{{ kind: {}, key: {}, status: {}, draft: {} }}",
                match service.kind {
                    ExternalServiceKind::DataStore => "DATA_STORE",
                    ExternalServiceKind::TiContainer => "TI_CONTAINER",
                },
                gql(&service.key),
                match service.status {
                    ExternalServiceStatus::Disabled => "DISABLED",
                    ExternalServiceStatus::Enabled => "ENABLED",
                    ExternalServiceStatus::ReloadFailed => "RELOAD_FAILED",
                    ExternalServiceStatus::Unknown => "UNKNOWN",
                },
                text(service.draft.as_ref())
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Returns `node` as a `NodeInput`.
fn node_input(node: &Node) -> String {
    let agents = node
        .agents
        .iter()
        .map(|agent| {
            format!(
                "{{ kind: {}, key: {}, status: {}, config: {}, draft: {} }}",
                agent_kind(agent.kind),
                gql(&agent.key),
                agent_status(agent.status),
                text(agent.config.as_ref()),
                text(agent.draft.as_ref())
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{ name: {}, nameDraft: {}, profile: {}, profileDraft: {}, agents: [{agents}], \
         externalServices: [{}] }}",
        gql(&node.name),
        node.name_draft
            .as_deref()
            .map_or_else(|| "null".to_string(), gql),
        profile_input(node.profile.as_ref()),
        profile_input(node.profile_draft.as_ref()),
        services(node)
    )
}

/// Returns `node` as a `NodeDraftInput`.
fn draft_input(node: &Node) -> String {
    let agents = node
        .agents
        .iter()
        .map(|agent| {
            format!(
                "{{ kind: {}, key: {}, status: {}, draft: {} }}",
                agent_kind(agent.kind),
                gql(&agent.key),
                agent_status(agent.status),
                text(agent.draft.as_ref())
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{{ nameDraft: {}, profileDraft: {}, agents: [{agents}], externalServices: [{}] }}",
        gql(node.name_draft.as_deref().unwrap_or(&node.name)),
        profile_input(node.profile_draft.as_ref()),
        services(node)
    )
}

fn update_draft(old: &Node, new: &Node) -> String {
    format!(
        "mutation {{ updateNodeDraft(id: \"{}\", old: {}, new: {}) }}",
        old.id,
        node_input(old),
        draft_input(new)
    )
}

fn apply(node: &Node) -> String {
    format!(
        "mutation {{ applyNode(id: \"{}\", node: {}) }}",
        node.id,
        node_input(node)
    )
}

fn apply_draft(node: &Node) -> String {
    format!(
        "mutation {{ applyNodeDraft(id: \"{}\", node: {}) {{ id }} }}",
        node.id,
        node_input(node)
    )
}

fn insert_node(customer_id: u32, hostname: &str, draft: Option<&str>) -> String {
    format!(
        "mutation {{ insertNode(name: {name}, customerId: \"{customer_id}\", description: \"\", \
         hostname: {hostname}, agents: [{{ kind: UNSUPERVISED, key: {key}, status: ENABLED, \
         draft: {draft} }}], externalServices: []) }}",
        name = gql(&format!("new node at {hostname}")),
        hostname = gql(hostname),
        key = gql(ENGINE_KEY),
        draft = draft.map_or_else(|| "null".to_string(), gql),
    )
}

/// Returns the code, `field`, `value` and `detectorId` of the single error of
/// `res`.
fn refused(res: &async_graphql::Response) -> (String, String, String, Value) {
    let (_, extensions) = single_error(res);
    let get = |key: &str| match &extensions[key] {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    (
        get("code"),
        get("field"),
        get("value"),
        extensions["detectorId"].clone(),
    )
}

/// Returns the message of the single error of `res`, which must carry no
/// code.
fn plain_error(res: &async_graphql::Response) -> String {
    let (message, extensions) = single_error(res);
    assert!(extensions.get("code").is_none(), "{res:?}");
    message
}

fn ok(res: async_graphql::Response) {
    data(res);
}

// ---------------------------------------------------------------------------
// Accepted documents and their links

#[tokio::test]
async fn a_saved_draft_links_its_models_and_apply_links_them_as_applied() {
    let f = fixture().await;
    let labeldb = "labeldb = { columns = [{ column_ids = [15], db = \"HttpUriThreat\" }] }\n\
                   suspicious_tokens = \"ind-a\"";
    let document = format!(
        "cpus = 4\n{}{}",
        f.doc("model-a", &[&f.sensor_a, &f.logs_a], labeldb),
        detector(
            2,
            "prefix-a",
            &[&f.sensor_a],
            (&f.server_name, OWN_ADDRESS),
            "enabled = false"
        )
        .replace("enabled = true\n", "")
    );
    ok(f.save(&f.engine_a, Some(&document)).await);

    let expected = EngineDocumentRefs {
        detectors: vec![
            EngineDetectorRef {
                id: 1,
                model: "model-a".to_string(),
                sources: vec![f.sensor_a.clone(), f.logs_a.clone()],
                indicator: Some("ind-a".to_string()),
            },
            EngineDetectorRef {
                id: 2,
                model: "prefix-a".to_string(),
                sources: vec![f.sensor_a.clone()],
                indicator: None,
            },
        ],
    };
    assert_eq!(
        f.refs(&f.engine_a),
        (EngineDocumentRefs::default(), expected.clone())
    );
    let users = |name: &str| f.store().model_users(name).unwrap();
    assert_eq!(
        users("model-a"),
        [ModelUse {
            instance: f.engine_a.clone(),
            detector_id: 1,
            applied: false,
            pending: true,
        }]
    );
    assert_eq!(
        users("prefix-a").len(),
        1,
        "a disabled detector names its model"
    );

    ok(f.apply(f.engine_a.node_id).await);
    assert_eq!(f.refs(&f.engine_a), (expected.clone(), expected));
    assert_eq!(
        users("model-a"),
        [ModelUse {
            instance: f.engine_a.clone(),
            detector_id: 1,
            applied: true,
            pending: true,
        }]
    );
    assert_eq!(
        f.agent(&f.engine_a).config.as_ref().map(AsRef::as_ref),
        Some(document.as_str())
    );

    // Removing the detectors unlinks the models from the draft, then from
    // the config.
    ok(f.save(&f.engine_a, Some("detectors = []")).await);
    assert_eq!(
        users("model-a"),
        [ModelUse {
            instance: f.engine_a.clone(),
            detector_id: 1,
            applied: true,
            pending: false,
        }]
    );
    ok(f.apply(f.engine_a.node_id).await);
    assert_eq!(users("model-a"), Vec::<ModelUse>::new());
}

#[tokio::test]
async fn documents_without_detectors_are_accepted() {
    let f = fixture().await;
    for (i, document) in ["", "detectors = []", "cpus = 4"].into_iter().enumerate() {
        ok(f.save(&f.engine_a, Some(document)).await);
        ok(f.apply(f.engine_a.node_id).await);
        assert_eq!(
            f.agent(&f.engine_a).config.as_ref().map(AsRef::as_ref),
            Some(document)
        );
        assert_eq!(f.refs(&f.engine_a), Default::default());
        ok(f.sys(&insert_node(
            A,
            &format!("new-{i}.example.com"),
            Some(document),
        ))
        .await);
    }
}

#[tokio::test]
async fn bounds_are_accepted_at_their_limit() {
    let f = fixture().await;
    let document = format!(
        "cpus = 64\n{}",
        f.doc(
            "model-a",
            &[&f.sensor_a],
            "read_lag = \"1h\"\nmax_event_id_num = 100"
        )
        .replace("period = \"5m\"", "period = \"1m\"")
        .replace("batch_size = 500000", "batch_size = 5000000")
    );
    ok(f.save(&f.engine_a, Some(&document)).await);
    ok(f.apply(f.engine_a.node_id).await);
}

// ---------------------------------------------------------------------------
// Refusals of RFC 0006 §5.3

/// A document refused by RFC 0006 §5.3, with the refusal's code, `field`,
/// `value` and `detectorId`.
struct Refused {
    document: String,
    code: &'static str,
    field: &'static str,
    value: String,
    detector_id: i32,
}

// One entry per refusal.
#[allow(clippy::too_many_lines)]
fn refusal_cases(f: &Fixture) -> Vec<Refused> {
    let case = |document: String, code, field, value: &str, detector_id| Refused {
        document,
        code,
        field,
        value: value.to_string(),
        detector_id,
    };
    let two = |first: (i32, &str), second: (i32, &str)| {
        format!(
            "{}{}",
            detector(
                first.0,
                first.1,
                &[&f.sensor_a],
                (&f.server_name, OWN_ADDRESS),
                ""
            ),
            detector(
                second.0,
                second.1,
                &[&f.sensor_a],
                (&f.server_name, OWN_ADDRESS),
                ""
            )
        )
    };
    let valid = f.valid();
    vec![
        case(
            f.doc("no-such-model", &[&f.sensor_a], ""),
            "MODEL_NOT_OF_INSTANCE",
            "detectors[0].model",
            "no-such-model",
            1,
        ),
        case(
            f.doc("model-a2", &[&f.sensor_a], ""),
            "MODEL_NOT_OF_INSTANCE",
            "detectors[0].model",
            "model-a2",
            1,
        ),
        case(
            f.doc("model-b", &[&f.sensor_a], ""),
            "MODEL_NOT_OF_INSTANCE",
            "detectors[0].model",
            "model-b",
            1,
        ),
        case(
            two((1, "model-a"), (2, "model-a")),
            "DUPLICATE_ENTRY",
            "detectors[1].model",
            "model-a",
            2,
        ),
        case(
            two((1, "model-a"), (1, "model-a1")),
            "DUPLICATE_ENTRY",
            "detectors[1].id",
            "1",
            1,
        ),
        case(
            f.doc("model-a", &[], ""),
            "INVALID_DOCUMENT",
            "detectors[0].sources",
            "",
            1,
        ),
        case(
            f.doc("model-a", &[&f.sensor_a, &f.sensor_a], ""),
            "DUPLICATE_ENTRY",
            "detectors[0].sources[1]",
            &f.sensor_a,
            1,
        ),
        case(
            f.doc("model-a", &[&f.sensor_a, &f.sensor_b], ""),
            "SOURCE_NOT_ALLOWED",
            "detectors[0].sources[1]",
            &f.sensor_b,
            1,
        ),
        case(
            detector(
                1,
                "model-a",
                &[&f.sensor_a],
                ("001.giganto.nowhere.example.com", OWN_ADDRESS),
                "",
            ),
            "DATA_STORE_NOT_INSTALLED",
            "detectors[0].data_store.server_name",
            "001.giganto.nowhere.example.com",
            1,
        ),
        case(
            f.doc("model-a", &[&f.sensor_a], "suspicious_tokens = \"ind-b\""),
            "INDICATOR_NOT_ALLOWED",
            "detectors[0].suspicious_tokens",
            "ind-b",
            1,
        ),
        case(
            f.doc("model-a", &[&f.sensor_a], "suspicious_tokens = \"no-such\""),
            "INDICATOR_NOT_ALLOWED",
            "detectors[0].suspicious_tokens",
            "no-such",
            1,
        ),
        case(
            f.doc(
                "prefix-a",
                &[&f.sensor_a],
                "labeldb = { columns = [{ column_ids = [1], db = \"X\" }] }",
            ),
            "FIELD_NOT_ALLOWED",
            "detectors[0].labeldb",
            "",
            1,
        ),
        case(
            format!("cpus = 65\n{valid}"),
            "BOUND_VIOLATED",
            "cpus",
            "65",
            0,
        ),
        case(
            valid.replace("period = \"5m\"", "period = \"59s\""),
            "BOUND_VIOLATED",
            "detectors[0].period",
            "59s",
            1,
        ),
        case(
            f.doc("model-a", &[&f.sensor_a], "read_lag = \"3601s\""),
            "BOUND_VIOLATED",
            "detectors[0].read_lag",
            "3601s",
            1,
        ),
        case(
            valid.replace("batch_size = 500000", "batch_size = 5000001"),
            "BOUND_VIOLATED",
            "detectors[0].batch_size",
            "5000001",
            1,
        ),
        case(
            f.doc("model-a", &[&f.sensor_a], "max_event_id_num = 101"),
            "BOUND_VIOLATED",
            "detectors[0].max_event_id_num",
            "101",
            1,
        ),
        case(
            f.doc("model-a", &[&f.sensor_a], "event_type = \"http\""),
            "UNKNOWN_FIELD",
            "detectors[0].event_type",
            "event_type",
            1,
        ),
        case(
            f.doc(
                "model-a",
                &[&f.sensor_a],
                "labeldb = { protocol = \"http\", columns = [] }",
            ),
            "UNKNOWN_FIELD",
            "detectors[0].labeldb.protocol",
            "protocol",
            1,
        ),
        case(
            format!("export_path = \"/tmp/out\"\n{valid}"),
            "UNKNOWN_FIELD",
            "export_path",
            "export_path",
            0,
        ),
        case(
            "test = 'toml'".to_string(),
            "UNKNOWN_FIELD",
            "test",
            "test",
            0,
        ),
    ]
}

fn assert_refused(res: &async_graphql::Response, case: &Refused) {
    let (code, field, value, detector_id) = refused(res);
    assert_eq!(code, case.code, "{}", case.document);
    assert_eq!(field, case.field, "{}", case.document);
    assert_eq!(value, case.value, "{}", case.document);
    let expected_id = if case.detector_id == 0 {
        Value::Null
    } else {
        Value::from(case.detector_id)
    };
    assert_eq!(detector_id, expected_id, "{}", case.document);
}

#[tokio::test]
async fn each_refusal_is_returned_by_a_draft_save() {
    let f = fixture().await;
    for case in refusal_cases(&f) {
        let res = f.save(&f.engine_a, Some(&case.document)).await;
        assert_refused(&res, &case);
        assert_eq!(f.agent(&f.engine_a).draft, None, "{}", case.document);
        assert_eq!(f.refs(&f.engine_a), Default::default());
    }
    let query = f
        .save_query(&f.engine_a, Some("cpus = 99"))
        .replace(&gql("cpus = 99"), &gql("not toml"));
    let res = f.sec(&query, &[A]).await;
    let (code, field, value, _) = refused(&res);
    assert_eq!((code.as_str(), field.as_str()), ("INVALID_DOCUMENT", ""));
    assert_ne!(value, "");
}

#[tokio::test]
async fn each_refusal_is_returned_by_apply_node_and_apply_node_draft() {
    let f = fixture().await;
    for case in refusal_cases(&f) {
        f.seed(&f.engine_a, Some(&case.document));
        let res = f.apply(f.engine_a.node_id).await;
        assert_refused(&res, &case);
        let query = apply_draft(&f.node(f.engine_a.node_id));
        assert_refused(&f.sec(&query, &[A]).await, &case);
        assert_eq!(f.agent(&f.engine_a).config, None, "{}", case.document);
        assert_eq!(f.refs(&f.engine_a), Default::default());
    }
}

#[tokio::test]
async fn a_missing_model_and_another_instances_model_get_one_message() {
    let f = fixture().await;
    let mut messages = Vec::new();
    for model in ["model-x", "model-y", "model-a2", "model-b"] {
        let document = f.doc(model, &[&f.sensor_a], "");
        let res = f.save(&f.engine_a, Some(&document)).await;
        messages.push(single_error(&res).0.replace(model, "MODEL"));
    }
    assert!(messages.iter().all(|m| *m == messages[0]), "{messages:?}");
}

#[tokio::test]
async fn a_detector_on_a_node_without_an_applied_profile_is_refused() {
    let f = fixture().await;
    let node = Node {
        id: u32::MAX,
        name: "bare".to_string(),
        name_draft: Some("bare".to_string()),
        profile: None,
        profile_draft: None,
        agents: vec![Agent {
            node_id: u32::MAX,
            key: ENGINE_KEY.to_string(),
            kind: AgentKind::Unsupervised,
            status: AgentStatus::Enabled,
            config: None,
            draft: None,
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::NotInstalled,
            bound_addrs: vec![],
            instance: None,
        }],
        external_services: vec![],
        creation_time: Utc::now(),
    };
    let id = f.store().node_map().put(&node).unwrap();
    let bare = ModelInstance {
        node_id: id,
        agent_key: ENGINE_KEY.to_string(),
    };
    let query = f.save_query(&bare, Some(&f.valid()));
    let (code, field, value, detector_id) = refused(&f.sys(&query).await);
    assert_eq!(
        (code.as_str(), field.as_str(), value.as_str()),
        (
            "SOURCE_NOT_ALLOWED",
            "detectors[0].sources[0]",
            f.sensor_a.as_str()
        )
    );
    assert_eq!(detector_id, Value::from(1));
    ok(f.sys(&f.save_query(&bare, Some("cpus = 4"))).await);

    // An apply of the document is refused alike.
    f.seed(&bare, Some(&f.valid()));
    let stored = f.node(id);
    let (code, field, value, detector_id) = refused(&f.sys(&apply(&stored)).await);
    assert_eq!(
        (code.as_str(), field.as_str(), value.as_str()),
        (
            "SOURCE_NOT_ALLOWED",
            "detectors[0].sources[0]",
            f.sensor_a.as_str()
        )
    );
    assert_eq!(detector_id, Value::from(1));
    assert_eq!(f.node(id), stored);

    // A new node has no applied profile either.
    let res = f
        .sys(&insert_node(A, "new.example.com", Some(&f.valid())))
        .await;
    assert_eq!(refused(&res).0, "SOURCE_NOT_ALLOWED");
    let message = single_error(&res).0;
    assert!(!message.contains(&u32::MAX.to_string()), "{message}");
    let res = f
        .sys(&insert_node(A, "new.example.com", Some("not toml")))
        .await;
    assert_eq!(refused(&res).0, "INVALID_DOCUMENT");
    let res = f
        .sys(&insert_node(
            A,
            "new.example.com",
            Some("export_path = \"/x\""),
        ))
        .await;
    assert_eq!(refused(&res).0, "UNKNOWN_FIELD");
}

// ---------------------------------------------------------------------------
// The Data Store address override

#[tokio::test]
async fn an_address_override_is_refused_on_save_unless_kept_or_set_by_a_system_admin() {
    let f = fixture().await;
    let overridden = |extra: &str| {
        detector(
            1,
            "model-a",
            &[&f.sensor_a],
            (&f.server_name, OVERRIDE),
            extra,
        )
    };
    let res = f.save(&f.engine_a, Some(&overridden(""))).await;
    let (code, field, value, detector_id) = refused(&res);
    assert_eq!(
        (code.as_str(), field.as_str(), value.as_str()),
        (
            "ADDRESS_OVERRIDE_FORBIDDEN",
            "detectors[0].data_store.address",
            OVERRIDE
        )
    );
    assert_eq!(detector_id, Value::from(1));

    // A System Administrator may set it.
    let query = f.save_query(&f.engine_a, Some(&overridden("")));
    ok(f.sys(&query).await);
    // Kept from the stored draft, it is accepted from anyone.
    ok(f.save(&f.engine_a, Some(&overridden("stats = true"))).await);
    // Kept from the stored config once the draft no longer has it.
    ok(f.apply(f.engine_a.node_id).await);
    ok(f.save(&f.engine_a, Some(&f.valid())).await);
    ok(f.save(&f.engine_a, Some(&overridden("stats = false")))
        .await);
}

#[tokio::test]
async fn apply_keeps_the_address_override_of_the_draft_it_applies() {
    let f = fixture().await;
    let overridden = detector(1, "model-a", &[&f.sensor_a], (&f.server_name, OVERRIDE), "");
    f.seed(&f.engine_a, Some(&overridden));
    ok(f.apply(f.engine_a.node_id).await);
    assert_eq!(f.refs(&f.engine_a).0.detectors.len(), 1);
}

// ---------------------------------------------------------------------------
// Unchanged and stale documents

#[tokio::test]
async fn an_unchanged_draft_is_not_validated_on_save_but_is_on_apply() {
    let f = fixture().await;
    ok(f.save(&f.engine_a, Some(&f.valid())).await);
    let saved = f.refs(&f.engine_a);

    // The sensor's node moves to customer B behind the document's back.
    let sensor = f.source_node(&f.sensor_a);
    let moved = NodeProfile {
        customer_id: B,
        ..sensor.profile.clone().unwrap()
    };
    f.set_profiles(sensor.id, Some(moved.clone()), Some(moved));

    let stored = f.node(f.engine_a.node_id);
    let mut edited = stored.clone();
    edited.profile_draft.as_mut().unwrap().description = "edited".to_string();
    ok(f.sec(&update_draft(&stored, &edited), &[A]).await);
    assert_eq!(f.refs(&f.engine_a), saved);

    let res = f.apply(f.engine_a.node_id).await;
    let (code, field, _, _) = refused(&res);
    assert_eq!(
        (code.as_str(), field.as_str()),
        ("SOURCE_NOT_ALLOWED", "detectors[0].sources[0]")
    );
    let after = f.node(f.engine_a.node_id);
    assert_eq!(
        after.profile, stored.profile,
        "nothing of the apply is written"
    );
    assert_eq!(f.agent(&f.engine_a).config, None);
    assert_eq!(f.refs(&f.engine_a), saved);
}

#[tokio::test]
async fn an_unchanged_draft_in_the_retired_format_is_saved() {
    let f = fixture().await;
    f.seed(&f.engine_a, Some("test = 'toml'"));
    let stored = f.node(f.engine_a.node_id);
    let mut edited = stored.clone();
    edited.name_draft = Some("renamed".to_string());
    ok(f.sec(&update_draft(&stored, &edited), &[A]).await);
    assert_eq!(
        f.node(f.engine_a.node_id).name_draft.as_deref(),
        Some("renamed")
    );
    assert_eq!(f.refs(&f.engine_a), Default::default());
}

#[tokio::test]
async fn a_draft_save_from_a_stale_draft_is_refused() {
    let f = fixture().await;
    let stale = f.node(f.engine_a.node_id);
    let seeded = f.doc("model-a1", &[&f.sensor_a], "");
    f.seed(&f.engine_a, Some(&seeded));
    let stored = f.node(f.engine_a.node_id);

    for draft in [Some(f.valid()), Some(seeded.clone()), None] {
        let new = with_draft(&stale, ENGINE_KEY, draft.as_deref());
        let res = f.sec(&update_draft(&stale, &new), &[A]).await;
        assert_eq!(plain_error(&res), STALE_NODE, "{draft:?}");
        assert_eq!(f.node(f.engine_a.node_id), stored);
        assert_eq!(f.refs(&f.engine_a), Default::default());
    }

    // A stale request is refused as stale even when its draft is not TOML.
    let new = with_draft(&stale, ENGINE_KEY, Some("cpus = 99"));
    let query = update_draft(&stale, &new).replace(&gql("cpus = 99"), &gql("not toml"));
    let res = f.sec(&query, &[A]).await;
    assert_eq!(plain_error(&res), STALE_NODE);
    assert_eq!(f.node(f.engine_a.node_id), stored);
    assert_eq!(f.refs(&f.engine_a), Default::default());
}

#[tokio::test]
async fn an_apply_from_a_stale_node_is_refused() {
    let f = fixture().await;
    f.seed(&f.engine_a, Some(&f.valid()));
    let stored = f.node(f.engine_a.node_id);

    let stale_draft = with_draft(&stored, ENGINE_KEY, Some("detectors = []"));
    let res = f.sec(&apply(&stale_draft), &[A]).await;
    assert_eq!(plain_error(&res), STALE_NODE);

    let mut stale_config = stored.clone();
    stale_config.agents[0].config = Some(config("cpus = 1"));
    let res = f.sec(&apply(&stale_config), &[A]).await;
    assert_eq!(plain_error(&res), STALE_NODE);

    let res = f.sec(&apply_draft(&stale_draft), &[A]).await;
    assert_eq!(plain_error(&res), STALE_NODE);
    assert_eq!(f.node(f.engine_a.node_id), stored);
    assert_eq!(f.refs(&f.engine_a), Default::default());
}

#[tokio::test]
async fn a_change_of_kind_to_or_from_unsupervised_is_refused() {
    let f = fixture().await;
    let agent = |key: &str, kind| Agent {
        node_id: u32::MAX,
        key: key.to_string(),
        kind,
        status: AgentStatus::Enabled,
        config: None,
        draft: None,
        installed_version: None,
        installed_commit: None,
        lifecycle: Lifecycle::NotInstalled,
        bound_addrs: vec![],
        instance: None,
    };
    let profile = NodeProfile {
        customer_id: A,
        description: String::new(),
        hostname: "mixed.example.com".to_string(),
    };
    let node = Node {
        id: u32::MAX,
        name: "mixed".to_string(),
        name_draft: Some("mixed".to_string()),
        profile: Some(profile.clone()),
        profile_draft: Some(profile),
        agents: vec![
            agent("002.reconverge", AgentKind::Unsupervised),
            agent("002.piglet", AgentKind::Sensor),
        ],
        external_services: vec![],
        creation_time: Utc::now(),
    };
    let id = f.store().node_map().put(&node).unwrap();
    let stored = f.node(id);
    for (i, key, kind) in [
        (0, "002.reconverge", AgentKind::Sensor),
        (1, "002.piglet", AgentKind::Unsupervised),
    ] {
        let mut new = stored.clone();
        new.agents[i].kind = kind;
        let res = f.sys(&update_draft(&stored, &new)).await;
        assert_eq!(
            plain_error(&res),
            format!("agent `{key}` cannot change its kind to or from Unsupervised")
        );
    }
    let mut twice = stored.clone();
    twice.agents[1] = agent("002.reconverge", AgentKind::Unsupervised);
    let res = f.sys(&update_draft(&stored, &twice)).await;
    assert_eq!(
        plain_error(&res),
        "agent key `002.reconverge` is listed more than once"
    );
    assert_eq!(f.node(id), stored);
}

#[tokio::test]
async fn an_insert_listing_an_engine_key_twice_is_refused() {
    let f = fixture().await;
    let before = f.store().node_map().count().unwrap();
    let agent = format!(
        "{{ kind: UNSUPERVISED, key: {}, status: ENABLED, draft: null }}",
        gql(ENGINE_KEY)
    );
    let query = format!(
        "mutation {{ insertNode(name: \"twice\", customerId: \"{A}\", description: \"\", \
         hostname: \"twice.example.com\", agents: [{agent}, {agent}], externalServices: []) }}"
    );
    let res = f.sys(&query).await;
    assert_eq!(
        plain_error(&res),
        format!("agent key `{ENGINE_KEY}` is listed more than once")
    );
    assert_eq!(f.store().node_map().count().unwrap(), before);
}

// ---------------------------------------------------------------------------
// The refusals of the store

fn changed(text: &str) -> ChangedDocument {
    ChangedDocument {
        agent_key: ENGINE_KEY.to_string(),
        document: Some(EngineDocument::parse(text).unwrap()),
    }
}

#[test]
// One check per refusal of the store.
#[allow(clippy::too_many_lines)]
fn the_store_refusals_map_to_the_resolver_codes() {
    let text = format!(
        "{}{}",
        detector(
            7,
            "first",
            &["piglet.a"],
            ("001.giganto.s", OWN_ADDRESS),
            ""
        ),
        detector(
            9,
            "second",
            &["piglet.a"],
            ("001.giganto.s", OWN_ADDRESS),
            "suspicious_tokens = \"ind\""
        )
    );
    let documents = [changed(&text)];
    let old = NodeUpdate {
        name: None,
        name_draft: None,
        profile: None,
        profile_draft: None,
        agents: vec![],
        external_services: vec![],
    };
    let map = |error: EngineDocumentError| store_refusal(error.into(), &old, &documents);
    let key = ENGINE_KEY.to_string();
    let extensions = |error: &Error| {
        serde_json::to_value(error.extensions.as_ref().expect("a refusal has extensions")).unwrap()
    };

    let missing = map(EngineDocumentError::ModelNotFound {
        agent_key: key.clone(),
        model: "second".to_string(),
    });
    let other = map(EngineDocumentError::ModelOfAnotherInstance {
        agent_key: key.clone(),
        model: "second".to_string(),
    });
    assert_eq!(missing.message, other.message);
    assert!(!missing.message.contains("exist"), "{}", missing.message);
    for error in [&missing, &other] {
        assert_eq!(
            extensions(error),
            json!({
                "code": "MODEL_NOT_OF_INSTANCE",
                "field": "detectors[1].model",
                "value": "second",
                "detectorId": 9,
            })
        );
    }

    let duplicate_model = map(EngineDocumentError::DuplicateModel {
        agent_key: key.clone(),
        model: "first".to_string(),
    });
    assert_eq!(extensions(&duplicate_model)["code"], "DUPLICATE_ENTRY");
    let duplicate_id = map(EngineDocumentError::DuplicateDetectorId {
        agent_key: key.clone(),
        detector_id: 7,
    });
    assert_eq!(extensions(&duplicate_id)["code"], "DUPLICATE_ENTRY");
    let indicator = map(EngineDocumentError::IndicatorNotFound {
        agent_key: key.clone(),
        indicator: "ind".to_string(),
    });
    assert_eq!(
        extensions(&indicator),
        json!({
            "code": "INDICATOR_NOT_ALLOWED",
            "field": "detectors[1].suspicious_tokens",
            "value": "ind",
            "detectorId": 9,
        })
    );

    let stale = map(EngineDocumentError::StaleDocument {
        agent_key: key.clone(),
    });
    assert_eq!(stale.message, STALE_NODE);
    assert!(stale.extensions.is_none());
    let kept = NodeUpdate {
        name: None,
        name_draft: None,
        profile: None,
        profile_draft: None,
        external_services: vec![],
        agents: vec![Agent {
            node_id: 0,
            key: key.clone(),
            kind: AgentKind::Unsupervised,
            status: AgentStatus::Enabled,
            config: None,
            draft: None,
            installed_version: None,
            installed_commit: None,
            lifecycle: Lifecycle::NotInstalled,
            bound_addrs: vec![],
            instance: None,
        }],
    };
    let gone = store_refusal(
        EngineDocumentError::NotUnsupervisedAgent {
            node_id: 0,
            agent_key: key.clone(),
        }
        .into(),
        &kept,
        &documents,
    );
    assert_eq!(gone.message, STALE_NODE);
    let kind = map(EngineDocumentError::KindChanged {
        agent_key: key.clone(),
    });
    assert_eq!(
        kind.message,
        format!("agent `{key}` cannot change its kind to or from Unsupervised")
    );
    let twice = map(EngineDocumentError::DuplicateAgentKey {
        agent_key: key.clone(),
    });
    assert_eq!(
        twice.message,
        format!("agent key `{key}` is listed more than once")
    );
    let bug = EngineDocumentError::DraftWithoutReferences { agent_key: key };
    let internal = map(bug.clone());
    assert_eq!(internal.message, bug.to_string());
    assert!(internal.extensions.is_none());
}

// ---------------------------------------------------------------------------
// The engine configuration lock

/// Runs `query` while the test holds the engine configuration lock, checking
/// with `unwritten` that nothing is written until the lock is released.
async fn under_lock(
    f: &Fixture,
    query: &str,
    unwritten: impl Fn() -> bool,
) -> async_graphql::Response {
    let guard = f.schema.hold_engine_config_lock().await;
    let (res, ()) = tokio::join!(f.sys(query), async {
        while f.schema.engine_config_lock_users() < 2 {
            tokio::task::yield_now().await;
        }
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(unwritten(), "nothing is written while the lock is held");
        drop(guard);
    });
    res
}

#[tokio::test]
async fn node_writes_wait_for_the_engine_configuration_lock() {
    let f = fixture().await;

    let query = f.save_query(&f.engine_a, Some(&f.valid()));
    ok(under_lock(&f, &query, || f.agent(&f.engine_a).draft.is_none()).await);
    assert!(f.agent(&f.engine_a).draft.is_some());

    let query = apply(&f.node(f.engine_a.node_id));
    ok(under_lock(&f, &query, || f.agent(&f.engine_a).config.is_none()).await);
    assert!(f.agent(&f.engine_a).config.is_some());

    f.seed(&f.engine_a2, Some(&f.doc("model-a2", &[&f.sensor_a], "")));
    let query = apply_draft(&f.node(f.engine_a2.node_id));
    ok(under_lock(&f, &query, || f.agent(&f.engine_a2).config.is_none()).await);
    assert!(f.agent(&f.engine_a2).config.is_some());

    let count = || f.store().node_map().count().unwrap();
    let before = count();
    let query = insert_node(A, "new.example.com", Some("cpus = 4"));
    ok(under_lock(&f, &query, || count() == before).await);
    assert_eq!(count(), before + 1);
}

fn definition_text(source: &str, server_name: &str) -> String {
    format!(
        r#"event_kind = "http"
method = "multidimension"
sources = ["{source}"]
window_start = "2026-10-14T00:00:00Z"
window_end = "2026-10-21T00:00:00Z"

[data_store]
address = "{OWN_ADDRESS}"
server_name = "{server_name}"

[csv]
format = [{{ data_type = "utf8", weight = 1.0 }}]
"#
    )
}

#[tokio::test]
async fn a_definition_and_a_customer_move_started_together_end_with_one_accepted() {
    let f = fixture().await;
    let sensor = f.source_node(&f.sensor_a);
    ok(
        f.sys(&Fixture::move_query(&sensor, B, "sensor-a.example.com"))
            .await,
    );
    let sensor = f.node(sensor.id);
    let define = format!(
        "mutation {{ insertTrainingDefinition(nodeId: \"{}\", agentKey: {}, name: \"def\", \
         definition: {}) }}",
        f.engine_a.node_id,
        gql(ENGINE_KEY),
        gql(&definition_text(&f.sensor_a, &f.server_name))
    );
    let move_query = apply(&sensor);
    let (defined, moved) = tokio::join!(f.sys(&define), f.sys(&move_query));
    assert_eq!(
        usize::from(defined.errors.is_empty()) + usize::from(moved.errors.is_empty()),
        1,
        "{defined:?} {moved:?}"
    );
    let definition = f.store().training_definition("def").unwrap();
    let customer = f.node(sensor.id).profile.unwrap().customer_id;
    if defined.errors.is_empty() {
        assert!(definition.is_some());
        assert_eq!(customer, A);
        assert_eq!(refused(&moved).0, "CUSTOMER_CHANGE_REFUSED");
    } else {
        assert!(definition.is_none());
        assert_eq!(customer, B);
        assert_eq!(refused(&defined).0, "SOURCE_NOT_ALLOWED");
    }
}

// ---------------------------------------------------------------------------
// The node guards of RFC 0006 §5.11

#[tokio::test]
async fn a_customer_change_is_refused_while_an_engine_owns_a_model() {
    let f = fixture().await;
    let engine = f.node(f.engine_a.node_id);
    let hostname = &engine.profile.as_ref().unwrap().hostname;
    let res = f.sys(&Fixture::move_query(&engine, B, hostname)).await;
    let (message, extensions) = single_error(&res);
    assert_eq!(extensions["code"], "CUSTOMER_CHANGE_REFUSED");
    assert_eq!(extensions["field"], "customer_id");
    assert_eq!(extensions["value"], "model-a");
    assert!(message.contains(ENGINE_KEY), "{message}");

    // A draft without a profile counts as a change.
    let mut cleared = engine.clone();
    cleared.profile_draft = None;
    let res = f.sys(&update_draft(&engine, &cleared)).await;
    assert_eq!(refused(&res).0, "CUSTOMER_CHANGE_REFUSED");

    // So does an apply of a draft that already has another customer.
    let moved = NodeProfile {
        customer_id: B,
        ..engine.profile.clone().unwrap()
    };
    f.set_profiles(engine.id, engine.profile.clone(), Some(moved));
    let res = f.sys(&apply(&f.node(engine.id))).await;
    assert_eq!(refused(&res).0, "CUSTOMER_CHANGE_REFUSED");
    assert_eq!(f.node(engine.id).profile, engine.profile);
}

#[tokio::test]
async fn a_customer_change_is_refused_while_an_engine_owns_only_a_definition() {
    let f = fixture().await;
    let engine = insert_engine_instance(&f.store(), A, "engine-c.example.com", ENGINE_KEY);
    insert_definition(&f.store(), "def-c", A, &engine, "ind-a");
    let node = f.node(engine.node_id);
    let res = f
        .sys(&Fixture::move_query(&node, B, "engine-c.example.com"))
        .await;
    let (code, field, value, _) = refused(&res);
    assert_eq!(
        (code.as_str(), field.as_str(), value.as_str()),
        ("CUSTOMER_CHANGE_REFUSED", "customer_id", "def-c")
    );
}

#[tokio::test]
async fn a_customer_change_is_refused_while_a_document_lists_the_nodes_source() {
    let f = fixture().await;
    ok(f.save(
        &f.engine_a,
        Some(&f.doc("model-a", &[&f.sensor_a, &f.logs_a], "")),
    )
    .await);

    for source in [&f.sensor_a, &f.logs_a] {
        let node = f.source_node(source);
        let hostname = node.profile.as_ref().unwrap().hostname.clone();
        let query = Fixture::move_query(&node, B, &hostname);

        let (_, extensions) = single_error(&f.sys(&query).await);
        assert_eq!(
            extensions,
            json!({
                "code": "CUSTOMER_CHANGE_REFUSED",
                "field": "customer_id",
                "value": source,
                "detectorId": 1,
                "nodeId": f.engine_a.node_id.to_string(),
                "agentKey": ENGINE_KEY,
            })
        );
        let (message, extensions) = single_error(&f.sec(&query, &[A, B]).await);
        assert_eq!(
            extensions,
            json!({
                "code": "CUSTOMER_CHANGE_REFUSED",
                "field": "customer_id",
                "value": source,
            })
        );
        assert!(!message.contains(ENGINE_KEY), "{message}");
        assert_eq!(f.node(node.id), node);
    }

    // An edit changing neither the customer nor the hostname is accepted.
    let node = f.source_node(&f.sensor_a);
    let mut edited = node.clone();
    edited.profile_draft.as_mut().unwrap().description = "edited".to_string();
    ok(f.sec(&update_draft(&node, &edited), &[A]).await);

    // Once no document lists the source, the move is accepted.
    ok(f.save(&f.engine_a, Some("detectors = []")).await);
    let node = f.node(node.id);
    ok(
        f.sys(&Fixture::move_query(&node, B, "sensor-a.example.com"))
            .await,
    );
    ok(f.sys(&apply(&f.node(node.id))).await);
    assert_eq!(f.node(node.id).profile.unwrap().customer_id, B);
}

#[tokio::test]
async fn a_customer_change_is_refused_while_a_definition_lists_the_nodes_source() {
    let f = fixture().await;
    f.store()
        .insert_training_definition(NewTrainingDefinition {
            name: "def".to_string(),
            customer_id: A,
            instance: f.engine_a.clone(),
            method: ModelMethod::Multidimension,
            event_kind: "http".to_string(),
            sources: vec![f.sensor_a.clone()],
            indicator: None,
            definition: String::new(),
        })
        .unwrap();
    let node = f.source_node(&f.sensor_a);
    let query = Fixture::move_query(&node, B, "sensor-a.example.com");
    let (_, extensions) = single_error(&f.sys(&query).await);
    assert_eq!(
        extensions,
        json!({
            "code": "CUSTOMER_CHANGE_REFUSED",
            "field": "customer_id",
            "value": f.sensor_a,
            "definition": "def",
        })
    );
    let (_, extensions) = single_error(&f.sec(&query, &[A, B]).await);
    assert!(extensions.get("definition").is_none(), "{extensions}");

    f.store().remove_training_definition("def").unwrap();
    ok(f.sys(&query).await);
}

#[tokio::test]
async fn removing_the_sensor_or_log_collector_first_does_not_lift_the_guard() {
    let f = fixture().await;
    ok(f.save(
        &f.engine_a,
        Some(&f.doc("model-a", &[&f.sensor_a, &f.logs_a], "")),
    )
    .await);
    for source in [&f.sensor_a, &f.logs_a] {
        let node = f.source_node(source);
        let mut removed = node.clone();
        removed.agents.clear();
        ok(f.sys(&update_draft(&node, &removed)).await);
        ok(f.sys(&apply(&f.node(node.id))).await);
        let node = f.node(node.id);
        assert_eq!(node.agents, Vec::<Agent>::new());
        let hostname = node.profile.as_ref().unwrap().hostname.clone();
        let res = f.sys(&Fixture::move_query(&node, B, &hostname)).await;
        let (code, _, value, _) = refused(&res);
        assert_eq!(
            (code.as_str(), value.as_str()),
            ("CUSTOMER_CHANGE_REFUSED", source.as_str())
        );
    }
}

#[tokio::test]
async fn a_new_node_or_a_hostname_change_is_refused_for_a_listed_name() {
    let f = fixture().await;
    ok(f.save(
        &f.engine_a,
        Some(&f.doc("model-a", &[&f.sensor_a, &f.logs_a], "")),
    )
    .await);

    for (source, hostname) in [
        (&f.sensor_a, "sensor-a.example.com"),
        (&f.logs_a, "logs-a.example.com"),
    ] {
        // A new node of another customer at the listed hostname.
        let res = f.sys(&insert_node(B, hostname, None)).await;
        let (code, field, value, _) = refused(&res);
        assert_eq!(
            (code.as_str(), field.as_str(), value.as_str()),
            ("CUSTOMER_CHANGE_REFUSED", "customer_id", source.as_str())
        );
        // A node of another customer moving to the listed hostname.
        let node = f.source_node(&f.sensor_b);
        let res = f.sys(&Fixture::move_query(&node, B, hostname)).await;
        let (code, field, value, _) = refused(&res);
        assert_eq!(
            (code.as_str(), field.as_str(), value.as_str()),
            ("CUSTOMER_CHANGE_REFUSED", "hostname", source.as_str())
        );
    }

    // A training definition holds the names as a document does.
    ok(f.save(&f.engine_a, Some("detectors = []")).await);
    f.store()
        .insert_training_definition(NewTrainingDefinition {
            name: "def".to_string(),
            customer_id: A,
            instance: f.engine_a.clone(),
            method: ModelMethod::Multidimension,
            event_kind: "http".to_string(),
            sources: vec![f.sensor_a.clone(), f.logs_a.clone()],
            indicator: None,
            definition: String::new(),
        })
        .unwrap();
    for (source, hostname) in [
        (&f.sensor_a, "sensor-a.example.com"),
        (&f.logs_a, "logs-a.example.com"),
    ] {
        let (_, extensions) = single_error(&f.sys(&insert_node(B, hostname, None)).await);
        assert_eq!(
            extensions,
            json!({
                "code": "CUSTOMER_CHANGE_REFUSED",
                "field": "customer_id",
                "value": source,
                "definition": "def",
            })
        );
        let node = f.source_node(&f.sensor_b);
        let query = Fixture::move_query(&node, B, hostname);
        let (_, extensions) = single_error(&f.sys(&query).await);
        assert_eq!(
            extensions,
            json!({
                "code": "CUSTOMER_CHANGE_REFUSED",
                "field": "hostname",
                "value": source,
                "definition": "def",
            })
        );
    }

    // Once nothing lists the names, only the hostname's own node stands in
    // the way.
    f.store().remove_training_definition("def").unwrap();
    let res = f.sys(&insert_node(B, "logs-a.example.com", None)).await;
    let (message, extensions) = single_error(&res);
    assert!(extensions.get("code").is_none(), "{extensions}");
    assert!(message.contains("already in use"), "{message}");
}

/// What lists the source names in the Apply guard tests: a draft document of
/// `engine_a` or a training definition of customer A.
#[derive(Clone, Copy, Debug)]
enum Holder {
    Document,
    Definition,
}

impl Fixture {
    /// Makes `holder`, of customer A, list `sources`.
    async fn hold(&self, holder: Holder, sources: &[&str]) {
        match holder {
            Holder::Document => ok(self
                .save(&self.engine_a, Some(&self.doc("model-a", sources, "")))
                .await),
            Holder::Definition => self
                .store()
                .insert_training_definition(NewTrainingDefinition {
                    name: "def".to_string(),
                    customer_id: A,
                    instance: self.engine_a.clone(),
                    method: ModelMethod::Multidimension,
                    event_kind: "http".to_string(),
                    sources: sources.iter().map(ToString::to_string).collect(),
                    indicator: None,
                    definition: String::new(),
                })
                .expect("insert training definition"),
        }
    }

    /// Stores a draft profile of `customer_id` and `hostname` on node `id`,
    /// keeping its applied profile, without the guard a draft save runs, and
    /// returns the stored node.
    fn seed_move(&self, id: u32, customer_id: u32, hostname: &str) -> Node {
        let node = self.node(id);
        let moved = NodeProfile {
            customer_id,
            description: String::new(),
            hostname: hostname.to_string(),
        };
        self.set_profiles(id, node.profile.clone(), Some(moved));
        self.node(id)
    }

    /// Checks that `applyNode` and `applyNodeDraft` of the stored `node`, as a
    /// System Administrator, each refuse with `CUSTOMER_CHANGE_REFUSED` on
    /// `field` for `source`, naming `holder`, and leave the node as stored.
    async fn assert_apply_refused(&self, node: &Node, holder: Holder, field: &str, source: &str) {
        assert_eq!(self.node(node.id), *node, "the request matches the store");
        for query in [apply(node), apply_draft(node)] {
            let (_, extensions) = single_error(&self.sys(&query).await);
            assert_eq!(extensions["code"], "CUSTOMER_CHANGE_REFUSED", "{query}");
            assert_eq!(extensions["field"], field, "{query}");
            assert_eq!(extensions["value"], source, "{query}");
            match holder {
                Holder::Document => {
                    assert_eq!(extensions["agentKey"], ENGINE_KEY, "{query}");
                    assert_eq!(
                        extensions["nodeId"],
                        self.engine_a.node_id.to_string(),
                        "{query}"
                    );
                }
                Holder::Definition => assert_eq!(extensions["definition"], "def", "{query}"),
            }
            assert_eq!(self.node(node.id), *node, "{query}");
        }
    }
}

#[tokio::test]
async fn an_apply_of_a_customer_change_is_refused_while_another_customer_lists_the_source() {
    for holder in [Holder::Document, Holder::Definition] {
        let f = fixture().await;
        f.hold(holder, &[&f.sensor_a, &f.logs_a]).await;
        for source in [&f.sensor_a, &f.logs_a] {
            let node = f.source_node(source);
            let hostname = node.profile.as_ref().unwrap().hostname.clone();
            let node = f.seed_move(node.id, B, &hostname);
            f.assert_apply_refused(&node, holder, "customer_id", source)
                .await;
        }
    }
}

#[tokio::test]
async fn an_apply_of_a_hostname_change_is_refused_for_another_customers_listed_name() {
    for holder in [Holder::Document, Holder::Definition] {
        let f = fixture().await;
        f.hold(holder, &[&f.sensor_a, &f.logs_a]).await;
        for (source, hostname) in [
            (&f.sensor_a, "sensor-a.example.com"),
            (&f.logs_a, "logs-a.example.com"),
        ] {
            // The store keeps a hostname to one node, so the listed node
            // leaves it first, which its own customer's holder allows.
            let listed = f.source_node(source);
            let vacated = format!("moved-{hostname}");
            ok(f.sys(&Fixture::move_query(&listed, A, &vacated)).await);
            ok(f.sys(&apply(&f.node(listed.id))).await);
            assert_eq!(f.node(listed.id).profile.unwrap().hostname, vacated);

            let node = f.source_node(&f.sensor_b);
            let node = f.seed_move(node.id, B, hostname);
            f.assert_apply_refused(&node, holder, "hostname", source)
                .await;
        }
    }
}

#[tokio::test]
async fn an_applied_removal_of_the_sensor_or_log_collector_does_not_lift_the_apply_guard() {
    for holder in [Holder::Document, Holder::Definition] {
        let f = fixture().await;
        f.hold(holder, &[&f.sensor_a, &f.logs_a]).await;
        for source in [&f.sensor_a, &f.logs_a] {
            let node = f.source_node(source);
            let mut removed = node.clone();
            removed.agents.clear();
            ok(f.sys(&update_draft(&node, &removed)).await);
            ok(f.sys(&apply(&f.node(node.id))).await);
            assert_eq!(f.node(node.id).agents, Vec::<Agent>::new());

            let hostname = node.profile.as_ref().unwrap().hostname.clone();
            let node = f.seed_move(node.id, B, &hostname);
            f.assert_apply_refused(&node, holder, "customer_id", source)
                .await;
        }
    }
}
