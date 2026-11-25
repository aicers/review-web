//! Tests of how `applyNode` and `applyNodeDraft` complete Semi-supervised
//! Engine documents: the refusals they translate, the documents they store,
//! and the agents they notify.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_graphql::Value as GqlValue;
use async_trait::async_trait;
use review_database::{
    AgentKind, AgentStatus, ClusteringModelTypeRef, CompletionMode, DetectionModelsSectionError,
    Lifecycle, ModelInstance, Node, NodeProfile, NodeUpdate, OperatorValueType, Store,
    complete_engine_document, event::LearningMethod,
};
use review_protocol::types::ResourceUsage;
use serde_json::json;

use super::{
    engine_write::{completion_refusal, detection_models_refusal, unsupervised_refusal},
    test_support::{node_draft_input, node_input, stored_node},
};
use crate::graphql::{
    AgentManager, SharedAgentManager, TestSchema,
    customer::{NetworkListItemsTargetAgentLookupKeysPair, NetworksTargetAgentLookupKeysPair},
    model_test_support::TestModel,
    time_series_generation_test_support::{insert_generator_node, insert_policy, sensor_name},
};

const MUTATIONS: [&str; 2] = ["applyNode", "applyNodeDraft"];
const HOST: &str = "h.example.com";
const FIRST: &str = "001.hog";
const SECOND: &str = "002.hog";
const APPLIED: &str = "[detection_models.port_scan]\nenabled = false\n";
const PARTIAL: &str = "[detection_models.port_scan]\nenabled = true\n";

/// What a [`Recorder`] was asked to do.
#[derive(Clone, Default)]
struct Calls(Arc<Mutex<Recorded>>);

#[derive(Default)]
struct Recorded {
    /// The agent lookup keys of `update_config`.
    configs: Vec<String>,
    /// `internal`, `allow` or `block`, per network broadcast.
    networks: Vec<&'static str>,
    /// The generators of each `time_series_generation_policies_changed`.
    generators: Vec<Vec<ModelInstance>>,
}

impl Calls {
    fn configs(&self) -> Vec<String> {
        self.0.lock().expect("not poisoned").configs.clone()
    }

    fn networks(&self) -> Vec<&'static str> {
        self.0.lock().expect("not poisoned").networks.clone()
    }

    fn generators(&self) -> Vec<Vec<ModelInstance>> {
        self.0.lock().expect("not poisoned").generators.clone()
    }

    fn clear(&self) {
        *self.0.lock().expect("not poisoned") = Recorded::default();
    }
}

/// An `AgentManager` that records every notification and broadcast an apply
/// sends, and accepts them all.
struct Recorder(Calls);

#[async_trait]
impl AgentManager for Recorder {
    async fn request_customer_data_deletion(
        &self,
        _targets: &[crate::customer_data_deletion::CustomerDataDeletionTarget],
    ) -> Result<(), anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn send_agent_specific_internal_networks(
        &self,
        _networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        self.0
            .0
            .lock()
            .expect("not poisoned")
            .networks
            .push("internal");
        Ok(vec![])
    }

    async fn send_agent_specific_allow_networks(
        &self,
        _networks: &[NetworkListItemsTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        self.0
            .0
            .lock()
            .expect("not poisoned")
            .networks
            .push("allow");
        Ok(vec![])
    }

    async fn send_agent_specific_block_networks(
        &self,
        _networks: &[NetworkListItemsTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        self.0
            .0
            .lock()
            .expect("not poisoned")
            .networks
            .push("block");
        Ok(vec![])
    }

    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
        Ok(HashMap::new())
    }

    async fn time_series_generation_policies_changed(&self, generators: &[ModelInstance]) {
        self.0
            .0
            .lock()
            .expect("not poisoned")
            .generators
            .push(generators.to_vec());
    }

    async fn capabilities(&self, hostname: &str) -> Result<BTreeSet<String>, anyhow::Error> {
        anyhow::bail!("{hostname} is unreachable")
    }

    async fn get_resource_usage(&self, hostname: &str) -> Result<ResourceUsage, anyhow::Error> {
        anyhow::bail!("{hostname} is unreachable")
    }

    async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn ping(&self, hostname: &str) -> Result<Duration, anyhow::Error> {
        anyhow::bail!("{hostname} is unreachable")
    }

    async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn update_config(&self, agent_lookup_key: &str) -> Result<(), anyhow::Error> {
        self.0
            .0
            .lock()
            .expect("not poisoned")
            .configs
            .push(agent_lookup_key.to_string());
        Ok(())
    }
}

/// A test schema with a node [`HOST`] of customer 1 carrying a Sensor and a
/// Time Series Generator, and another generator that holds a time series
/// generation policy reading that Sensor, so that a customer change of the node
/// tells it.
struct Fixture {
    schema: TestSchema,
    calls: Calls,
    node_id: u32,
    /// The generator a customer or hostname change of the node tells.
    generator: ModelInstance,
}

impl Fixture {
    /// Returns the fixture with Semi-supervised Engine agents of the given
    /// keys and applied documents added to the node.
    async fn new(hogs: &[(&str, Option<&str>)]) -> Self {
        let calls = Calls::default();
        let manager: SharedAgentManager = Arc::new(Recorder(calls.clone()));
        let schema = TestSchema::new_with_params(manager, None).await;
        let (node_id, generator) = {
            let store = schema.store();
            let node_id = insert_generator_node(&store, HOST, 1).node_id;
            let generator = insert_generator_node(&store, "g.example.com", 1);
            let policy = insert_policy(&store, "on h", 1, &sensor_name(HOST));
            store
                .time_series_generation_policy_map()
                .assign(policy, Some(&generator), true)
                .expect("assign policy");
            update_node(&store, node_id, |node| {
                for (key, config) in hogs {
                    node.agents.push(hog(key, *config));
                }
            });
            (node_id, generator)
        };
        Self {
            schema,
            calls,
            node_id,
            generator,
        }
    }

    fn node(&self) -> Node {
        stored_node(&self.schema.store(), self.node_id)
    }

    fn config(&self, key: &str) -> Option<String> {
        self.node()
            .agents
            .iter()
            .find(|agent| agent.key == key)
            .and_then(|agent| agent.config.as_ref())
            .map(|config| config.as_ref().to_string())
    }

    fn current_revision(&self, key: &str) -> Option<u64> {
        self.schema
            .store()
            .config_revision(&instance(self.node_id, key))
            .expect("read revision")
    }

    /// Saves the drafts and profile `edit` makes through `updateNodeDraft`,
    /// and returns the node it stored.
    async fn stage(&self, edit: impl FnOnce(&mut Node)) -> Node {
        let stored = self.node();
        let mut draft = stored.clone();
        edit(&mut draft);
        let res = self
            .schema
            .execute_as_system_admin(&format!(
                "mutation {{ updateNodeDraft(id: \"{}\", old: {}, new: {}) }}",
                self.node_id,
                node_input(&stored),
                node_draft_input(&draft, true, true)
            ))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        self.node()
    }

    /// Saves `drafts` as the drafts of the agents they name.
    async fn stage_drafts(&self, drafts: &[(&str, &str)]) -> Node {
        self.stage(|node| set_drafts(node, drafts)).await
    }

    async fn apply(&self, mutation: &str, node: &Node) -> async_graphql::Response {
        let selection = if mutation == "applyNodeDraft" {
            " { id }"
        } else {
            ""
        };
        self.schema
            .execute_as_system_admin(&format!(
                "mutation {{ {mutation}(id: \"{}\", node: {}){selection} }}",
                self.node_id,
                node_input(node)
            ))
            .await
    }

    async fn revision_document(&self, key: &str, revision: u64) -> Option<String> {
        let res = self
            .schema
            .execute_as_system_admin(&format!(
                "{{ configRevision(nodeId: \"{}\", agentKey: \"{key}\", revision: \
                 \"{revision}\") {{ document }} }}",
                self.node_id
            ))
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        res.data.into_json().expect("JSON data")["configRevision"]["document"]
            .as_str()
            .map(ToString::to_string)
    }
}

fn instance(node_id: u32, key: &str) -> ModelInstance {
    ModelInstance {
        node_id,
        agent_key: key.to_string(),
    }
}

fn hog(key: &str, config: Option<&str>) -> review_database::Agent {
    let config = config.map(|c| c.to_string().try_into().expect("valid TOML"));
    review_database::Agent {
        node_id: u32::MAX,
        key: key.to_string(),
        kind: AgentKind::SemiSupervised,
        status: AgentStatus::Enabled,
        config: config.clone(),
        draft: config,
        installed_version: None,
        installed_commit: None,
        lifecycle: Lifecycle::NotInstalled,
        bound_addrs: vec![],
        instance: None,
        run_as_root: false,
        run_as_root_draft: None,
        privilege_profile: None,
    }
}

fn update_node(store: &Store, id: u32, edit: impl FnOnce(&mut NodeUpdate)) {
    let mut map = store.node_map();
    let (node, _, _) = map.get_by_id(id).expect("read node").expect("node exists");
    let old = NodeUpdate::from(node.clone());
    let mut new = NodeUpdate::from(node);
    edit(&mut new);
    map.update(id, &old, &new).expect("update node");
}

fn set_drafts(node: &mut Node, drafts: &[(&str, &str)]) {
    for (key, draft) in drafts {
        let agent = node
            .agents
            .iter_mut()
            .find(|agent| agent.key == *key)
            .expect("the agent is on the node");
        agent.draft = Some(draft.to_string().try_into().expect("valid TOML"));
    }
}

fn profile(customer_id: u32) -> NodeProfile {
    NodeProfile {
        customer_id,
        description: String::new(),
        hostname: HOST.to_string(),
    }
}

fn completed(document: &str) -> String {
    complete_engine_document(
        AgentKind::SemiSupervised,
        document,
        &|_| None,
        &|_| None,
        CompletionMode::Apply,
    )
    .expect("completes")
}

fn lookup_key(key: &str) -> String {
    format!("{key}.{HOST}")
}

/// A refusal as `(message, code, field, value, agentKey)`.
type Refusal = (String, String, String, String, String);

fn extension(error: &async_graphql::Error, name: &str) -> String {
    match error.extensions.as_ref().and_then(|e| e.get(name)) {
        Some(GqlValue::String(value)) => value.clone(),
        other => panic!("extension {name} is {other:?}"),
    }
}

fn refusal_of_error(error: &async_graphql::Error) -> Refusal {
    (
        error.message.clone(),
        extension(error, "code"),
        extension(error, "field"),
        extension(error, "value"),
        extension(error, "agentKey"),
    )
}

fn refusal_of(res: &async_graphql::Response) -> Refusal {
    assert_eq!(res.errors.len(), 1, "{:?}", res.errors);
    let error = res.errors.first().expect("one error");
    let extensions = error.extensions.as_ref().expect("extensions");
    let get = |name: &str| match extensions.get(name) {
        Some(GqlValue::String(value)) => value.clone(),
        other => panic!("extension {name} is {other:?}"),
    };
    (
        error.message.clone(),
        get("code"),
        get("field"),
        get("value"),
        get("agentKey"),
    )
}

fn refusal(message: &str, code: &str, field: &str, value: &str, agent_key: &str) -> Refusal {
    (
        message.to_string(),
        code.to_string(),
        field.to_string(),
        value.to_string(),
        agent_key.to_string(),
    )
}

#[test]
#[allow(clippy::too_many_lines)] // one case per error variant
fn every_completion_error_maps_to_its_code_and_extensions() {
    const DOCUMENT: &str = "[detection_models.port_scan]\nenabled = 1 # on\n";
    let section = || "port_scan".to_string();
    let cases = [
        (
            DetectionModelsSectionError::InvalidToml("expected `=`".to_string()),
            refusal(
                "the engine document is not valid TOML: expected `=`",
                "INVALID_DOCUMENT",
                "",
                "expected `=`",
                FIRST,
            ),
        ),
        (
            DetectionModelsSectionError::NotATable,
            refusal(
                "`detection_models` is not a table",
                "INVALID_DOCUMENT",
                "detection_models",
                "",
                FIRST,
            ),
        ),
        (
            DetectionModelsSectionError::SectionNotATable { section: section() },
            refusal(
                "`detection_models.port_scan` is not a table",
                "INVALID_DOCUMENT",
                "detection_models.port_scan",
                "",
                FIRST,
            ),
        ),
        (
            DetectionModelsSectionError::TypeMismatch {
                section: section(),
                key: "enabled".to_string(),
                expected: OperatorValueType::Bool,
            },
            refusal(
                "`detection_models.port_scan.enabled` must be a boolean",
                "INVALID_DOCUMENT",
                "detection_models.port_scan.enabled",
                "1",
                FIRST,
            ),
        ),
        (
            DetectionModelsSectionError::UnknownModel {
                section: "no_such_model".to_string(),
            },
            refusal(
                "`detection_models.no_such_model` names no detection model",
                "UNKNOWN_FIELD",
                "detection_models.no_such_model",
                "",
                FIRST,
            ),
        ),
        (
            DetectionModelsSectionError::ModelOfAnotherEngine {
                section: section(),
                model_engine: LearningMethod::Unsupervised,
                document_engine: LearningMethod::SemiSupervised,
            },
            refusal(
                "`detection_models.port_scan` names a model of the Unsupervised engine, not of \
                 the SemiSupervised engine",
                "UNKNOWN_FIELD",
                "detection_models.port_scan",
                "",
                FIRST,
            ),
        ),
        (
            DetectionModelsSectionError::UnknownKey {
                section: section(),
                key: "threshold".to_string(),
            },
            refusal(
                "`detection_models.port_scan` has no operator value `threshold`",
                "UNKNOWN_FIELD",
                "detection_models.port_scan.threshold",
                "",
                FIRST,
            ),
        ),
        (
            DetectionModelsSectionError::OutOfRange {
                section: section(),
                key: "threshold".to_string(),
                value: "101".to_string(),
                min: "1".to_string(),
                max: "100".to_string(),
            },
            refusal(
                "`detection_models.port_scan.threshold` is 101, outside the range 1 to 100",
                "BOUND_VIOLATED",
                "detection_models.port_scan.threshold",
                "101",
                FIRST,
            ),
        ),
    ];
    for (error, expected) in cases {
        let mapped = detection_models_refusal(&error, FIRST, DOCUMENT);
        assert_eq!(refusal_of_error(&mapped), expected, "{error:?}");
    }
}

#[test]
fn a_wrong_type_value_is_written_as_its_toml_value() {
    let mismatch = |section: &str| DetectionModelsSectionError::TypeMismatch {
        section: section.to_string(),
        key: "enabled".to_string(),
        expected: OperatorValueType::Bool,
    };
    let cases = [
        (
            "[detection_models.port_scan]\nenabled =   \"yes\"   # not a boolean\n",
            "\"yes\"",
        ),
        ("[detection_models.port_scan]\nenabled = 1\n", "1"),
        (
            "detection_models = { port_scan = { enabled = 'yes' } }\n",
            "\"yes\"",
        ),
        (
            "[detection_models.port_scan]\nenabled = [ 1, 2 ]\n",
            "[1, 2]",
        ),
    ];
    for (document, value) in cases {
        let mapped = detection_models_refusal(&mismatch("port_scan"), FIRST, document);
        assert_eq!(extension(&mapped, "value"), value, "{document}");
    }
}

#[tokio::test]
async fn a_refused_document_refuses_the_apply_with_its_code() {
    let cases = [
        (
            "detection_models = 1\n",
            refusal(
                "`detection_models` is not a table",
                "INVALID_DOCUMENT",
                "detection_models",
                "",
                FIRST,
            ),
        ),
        (
            "[detection_models]\nport_scan = 1\n",
            refusal(
                "`detection_models.port_scan` is not a table",
                "INVALID_DOCUMENT",
                "detection_models.port_scan",
                "",
                FIRST,
            ),
        ),
        (
            "[detection_models.no_such_model]\nenabled = true\n",
            refusal(
                "`detection_models.no_such_model` names no detection model",
                "UNKNOWN_FIELD",
                "detection_models.no_such_model",
                "",
                FIRST,
            ),
        ),
        (
            "[detection_models.port_scan]\nthreshold = 3\n",
            refusal(
                "`detection_models.port_scan` has no operator value `threshold`",
                "UNKNOWN_FIELD",
                "detection_models.port_scan.threshold",
                "",
                FIRST,
            ),
        ),
        (
            "[detection_models.port_scan]\nenabled = \"yes\" # on\n",
            refusal(
                "`detection_models.port_scan.enabled` must be a boolean",
                "INVALID_DOCUMENT",
                "detection_models.port_scan.enabled",
                "\"yes\"",
                FIRST,
            ),
        ),
    ];
    for mutation in MUTATIONS {
        for (draft, expected) in &cases {
            let f = Fixture::new(&[(FIRST, Some(APPLIED))]).await;
            let node = f.stage_drafts(&[(FIRST, draft)]).await;
            // `updateNodeDraft` stores the draft as given.
            let stored_draft = node
                .agents
                .iter()
                .find(|agent| agent.key == FIRST)
                .and_then(|agent| agent.draft.as_ref())
                .map(|draft| draft.as_ref().to_string());
            assert_eq!(stored_draft.as_deref(), Some(*draft), "{mutation}");

            let res = f.apply(mutation, &node).await;
            assert_eq!(refusal_of(&res), *expected, "{mutation}: {draft}");
            assert_eq!(f.config(FIRST), Some(completed(APPLIED)), "{mutation}");
            assert_eq!(f.current_revision(FIRST), Some(1), "{mutation}");
            assert!(f.calls.configs().is_empty(), "{mutation}");
        }
    }
}

#[tokio::test]
async fn one_refused_agent_refuses_the_whole_apply_and_tells_no_one() {
    for mutation in MUTATIONS {
        let f = Fixture::new(&[(FIRST, Some(APPLIED)), (SECOND, Some(APPLIED))]).await;
        let node = f
            .stage(|node| {
                node.name_draft = Some("renamed".to_string());
                node.profile_draft = Some(profile(2));
                set_drafts(
                    node,
                    &[
                        (FIRST, PARTIAL),
                        (SECOND, "[detection_models.port_scan]\nenabled = 0\n"),
                    ],
                );
            })
            .await;
        let before = f.node();
        let history = |f: &Fixture| {
            [FIRST, SECOND].map(|key| {
                let store = f.schema.store();
                let instance = instance(f.node_id, key);
                (
                    store.config_revision(&instance).expect("read revision"),
                    store
                        .config_revision_record(&instance, 1)
                        .expect("read history"),
                    store
                        .config_revision_record(&instance, 2)
                        .expect("read history"),
                )
            })
        };
        let history_before = history(&f);
        f.calls.clear();

        let res = f.apply(mutation, &node).await;
        assert_eq!(
            refusal_of(&res),
            refusal(
                "`detection_models.port_scan.enabled` must be a boolean",
                "INVALID_DOCUMENT",
                "detection_models.port_scan.enabled",
                "0",
                SECOND,
            ),
            "{mutation}"
        );
        assert_eq!(f.node(), before, "{mutation}");
        assert_eq!(f.node().profile, Some(profile(1)), "{mutation}");
        assert_eq!(history(&f), history_before, "{mutation}");
        assert_eq!(history_before[1].2, None, "{mutation}");
        assert!(f.calls.configs().is_empty(), "{mutation}");
        assert!(f.calls.networks().is_empty(), "{mutation}");
        assert!(f.calls.generators().is_empty(), "{mutation}");
    }
}

#[tokio::test]
async fn documents_are_stored_completed_as_revision_1() {
    for mutation in MUTATIONS {
        let f = Fixture::new(&[(FIRST, None), (SECOND, None)]).await;
        let node = f.stage_drafts(&[(FIRST, PARTIAL), (SECOND, "")]).await;
        f.calls.clear();

        let res = f.apply(mutation, &node).await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        for (key, draft) in [(FIRST, PARTIAL), (SECOND, "")] {
            assert_eq!(f.config(key), Some(completed(draft)), "{mutation}: {key}");
            assert_eq!(f.current_revision(key), Some(1), "{mutation}: {key}");
            assert_eq!(
                f.revision_document(key, 1).await,
                Some(completed(draft)),
                "{mutation}: {key}"
            );
        }
        let mut notified = f.calls.configs();
        notified.sort_unstable();
        if mutation == "applyNode" {
            assert_eq!(notified, [lookup_key(FIRST), lookup_key(SECOND)]);
        } else {
            assert!(notified.is_empty(), "{mutation}: {notified:?}");
        }
    }
}

#[tokio::test]
async fn an_empty_draft_is_notified_only_when_its_completed_config_changes() {
    for mutation in MUTATIONS {
        let f = Fixture::new(&[(FIRST, None)]).await;
        let node = f.stage_drafts(&[(FIRST, "")]).await;
        f.calls.clear();

        // No other agent is notified, but the empty draft's completed config
        // is new.
        let res = f.apply(mutation, &node).await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        assert_eq!(f.config(FIRST), Some(completed("")), "{mutation}");
        if mutation == "applyNode" {
            assert_eq!(f.calls.configs(), [lookup_key(FIRST)]);
        } else {
            assert!(f.calls.configs().is_empty(), "{mutation}");
        }

        // The same empty draft applied again leaves the completed config as
        // it is.
        f.calls.clear();
        let res = f.apply(mutation, &f.node()).await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        assert_eq!(f.config(FIRST), Some(completed("")), "{mutation}");
        assert_eq!(f.current_revision(FIRST), Some(1), "{mutation}");
        assert!(f.calls.configs().is_empty(), "{mutation}");
    }
}

#[tokio::test]
async fn an_empty_draft_is_not_notified_without_a_hostname() {
    let f = Fixture::new(&[(FIRST, None)]).await;
    update_node(&f.schema.store(), f.node_id, |node| {
        node.profile = None;
        node.profile_draft = None;
    });
    let node = f.stage_drafts(&[(FIRST, "")]).await;
    f.calls.clear();
    let res = f.apply("applyNode", &node).await;
    assert!(res.errors.is_empty(), "{:?}", res.errors);
    assert_eq!(f.config(FIRST), Some(completed("")));
    assert!(f.calls.configs().is_empty(), "{:?}", f.calls.configs());
}

#[tokio::test]
async fn a_customer_change_still_broadcasts_and_tells_the_generators() {
    for mutation in MUTATIONS {
        let f = Fixture::new(&[(FIRST, Some(APPLIED))]).await;
        let node = f
            .stage(|node| {
                node.profile_draft = Some(profile(2));
                set_drafts(node, &[(FIRST, PARTIAL)]);
            })
            .await;
        f.calls.clear();

        let res = f.apply(mutation, &node).await;
        assert!(res.errors.is_empty(), "{mutation}: {:?}", res.errors);
        assert_eq!(f.node().profile, Some(profile(2)), "{mutation}");
        assert_eq!(f.config(FIRST), Some(completed(PARTIAL)), "{mutation}");
        assert_eq!(
            f.calls.networks(),
            ["internal", "allow", "block"],
            "{mutation}"
        );
        assert_eq!(
            f.calls.generators(),
            [vec![f.generator.clone()]],
            "{mutation}"
        );
        // The revision records the customer the apply left the node with.
        let record = f
            .schema
            .store()
            .config_revision_record(&instance(f.node_id, FIRST), 2)
            .expect("read history")
            .expect("revision 2 exists");
        assert_eq!(record.customer_id, Some(2), "{mutation}");
        assert_eq!(
            json!(f.calls.configs()),
            if mutation == "applyNode" {
                json!([lookup_key(FIRST)])
            } else {
                json!([])
            },
            "{mutation}"
        );
    }
}

// ---------------------------------------------------------------------------
// Unsupervised Engine documents
//
// review-web's own engine document checker refuses a `detection_models`
// table before the database write, so the completion errors of such
// documents are produced here by completing real documents as the database
// write does, and translated below the mutations.

const ENGINE: &str = "001.reconverge";

fn http_url_v1() -> ClusteringModelTypeRef {
    ClusteringModelTypeRef::Catalog {
        id: "http_url".to_string(),
        version: 1,
    }
}

fn server_daily_tls_v1() -> ClusteringModelTypeRef {
    ClusteringModelTypeRef::Catalog {
        id: "server_daily_tls".to_string(),
        version: 1,
    }
}

/// The clustering model type of the models the documents below name: `m` is
/// `http_url` version 1, `c` is custom, and no other model exists.
fn model_type(name: &str) -> Option<ClusteringModelTypeRef> {
    match name {
        "m" => Some(http_url_v1()),
        "c" => Some(ClusteringModelTypeRef::Custom),
        _ => None,
    }
}

/// Returns the completion error of the Unsupervised Engine document
/// `document` as the database write returns it.
fn unsupervised_error(document: &str) -> DetectionModelsSectionError {
    complete_engine_document(
        AgentKind::Unsupervised,
        document,
        &model_type,
        &|_| None,
        CompletionMode::Apply,
    )
    .expect_err(document)
}

/// Returns `sections` under the `detection_models` of one detector running
/// the model `model`.
fn detector_of(model: &str, sections: &str) -> String {
    format!("[[detectors]]\nid = 1\nmodel = \"{model}\"\n{sections}")
}

#[test]
#[allow(clippy::too_many_lines)] // one case per completion error
fn every_unsupervised_completion_error_maps_to_its_code_field_and_value() {
    const SECTION: &str = "detectors[0].detection_models";
    let label_db_match = |columns: &str| {
        detector_of(
            "m",
            &format!("[detectors.detection_models.label_db_match]\ncolumns = {columns}\n"),
        )
    };
    let far_outlier = |line: &str| {
        detector_of(
            "m",
            &format!("[detectors.detection_models.far_outlier]\n{line}\n"),
        )
    };
    let column = |cell: &str| format!("{SECTION}.label_db_match.columns[0].{cell}");
    let cases: Vec<(String, (&str, String, &str))> = vec![
        // INVALID_DOCUMENT
        (
            "[[detectors]\n".to_string(),
            ("INVALID_DOCUMENT", String::new(), ""),
        ),
        (
            "detectors = 1\n".to_string(),
            ("INVALID_DOCUMENT", String::new(), ""),
        ),
        (
            "[[detectors]]\nid = 1\n".to_string(),
            ("INVALID_DOCUMENT", "detectors[0].model".to_string(), ""),
        ),
        (
            "[[detectors]]\nmodel = 3\n".to_string(),
            ("INVALID_DOCUMENT", "detectors[0].model".to_string(), "3"),
        ),
        (
            detector_of("m", "detection_models = 1\n"),
            ("INVALID_DOCUMENT", SECTION.to_string(), "1"),
        ),
        (
            detector_of("m", "[detectors.detection_models]\nfar_outlier = 1\n"),
            ("INVALID_DOCUMENT", format!("{SECTION}.far_outlier"), "1"),
        ),
        (
            far_outlier("enabled = 1"),
            (
                "INVALID_DOCUMENT",
                format!("{SECTION}.far_outlier.enabled"),
                "1",
            ),
        ),
        (
            label_db_match("[1]"),
            (
                "INVALID_DOCUMENT",
                format!("{SECTION}.label_db_match.columns[0]"),
                "1",
            ),
        ),
        (
            label_db_match("[{ column_ids = [1], db = 3 }]"),
            ("INVALID_DOCUMENT", column("db"), "3"),
        ),
        // UNKNOWN_FIELD
        (
            detector_of("m", "[detectors.detection_models.no_such_model]\n"),
            ("UNKNOWN_FIELD", format!("{SECTION}.no_such_model"), ""),
        ),
        (
            detector_of("m", "[detectors.detection_models.port_scan]\n"),
            ("UNKNOWN_FIELD", format!("{SECTION}.port_scan"), ""),
        ),
        (
            far_outlier("threshold = 1"),
            (
                "UNKNOWN_FIELD",
                format!("{SECTION}.far_outlier.threshold"),
                "",
            ),
        ),
        (
            label_db_match("[{ column_ids = [1], db = \"d\", extra = 1 }]"),
            ("UNKNOWN_FIELD", column("extra"), ""),
        ),
        // FIELD_NOT_ALLOWED
        (
            detector_of("c", "[detectors.detection_models.far_outlier]\n"),
            ("FIELD_NOT_ALLOWED", format!("{SECTION}.far_outlier"), ""),
        ),
        (
            detector_of("x", "[detectors.detection_models.label_db_match]\n"),
            ("FIELD_NOT_ALLOWED", format!("{SECTION}.label_db_match"), ""),
        ),
        (
            label_db_match("[{ db = \"d\" }]"),
            ("FIELD_NOT_ALLOWED", column("column_ids"), ""),
        ),
        (
            label_db_match("[{ column_ids = [1] }]"),
            ("FIELD_NOT_ALLOWED", column("db"), ""),
        ),
        // BOUND_VIOLATED
        (
            detector_of(
                "m",
                "[detectors.detection_models.label_db_match]\nevent_range = 0\n",
            ),
            (
                "BOUND_VIOLATED",
                format!("{SECTION}.label_db_match.event_range"),
                "0",
            ),
        ),
        (
            label_db_match("[{ column_ids = [1], db = \"d\", min_score = 0.0 }]"),
            ("BOUND_VIOLATED", column("min_score"), "0.0"),
        ),
        (
            label_db_match("[{ column_ids = [-1], db = \"d\" }]"),
            ("BOUND_VIOLATED", column("column_ids"), "-1"),
        ),
        (
            label_db_match("[{ column_ids = [], db = \"d\" }]"),
            ("BOUND_VIOLATED", column("column_ids"), "[]"),
        ),
        (
            label_db_match("[{ column_ids = [1], db = \"\" }]"),
            ("BOUND_VIOLATED", column("db"), "\"\""),
        ),
    ];
    for (document, (code, field, value)) in cases {
        let error = unsupervised_error(&document);
        let mapped = unsupervised_refusal(&error, ENGINE);
        assert_eq!(
            refusal_of_error(&mapped),
            refusal(&error.to_string(), code, &field, value, ENGINE),
            "{document}"
        );
        // A Semi-supervised Engine document never yields these errors, and
        // its translation passes them on unchanged.
        if !matches!(
            error,
            DetectionModelsSectionError::InvalidToml(_)
                | DetectionModelsSectionError::NotATable
                | DetectionModelsSectionError::SectionNotATable { .. }
                | DetectionModelsSectionError::TypeMismatch { .. }
                | DetectionModelsSectionError::UnknownModel { .. }
                | DetectionModelsSectionError::ModelOfAnotherEngine { .. }
                | DetectionModelsSectionError::UnknownKey { .. }
                | DetectionModelsSectionError::OutOfRange { .. }
        ) {
            assert_eq!(
                refusal_of_error(&detection_models_refusal(&error, ENGINE, &document)),
                refusal_of_error(&mapped),
                "{document}"
            );
        }
    }
}

#[test]
fn synthetic_errors_of_every_variant_map_by_what_they_reject() {
    use review_database::{CellError, CellErrorKind, DetectorError};

    let cell = |kind: CellErrorKind| {
        DetectionModelsSectionError::Cell(Box::new(CellError {
            section: "label_db_match".to_string(),
            key: "columns".to_string(),
            index: 2,
            cell: "db".to_string(),
            kind,
        }))
    };
    let detector = |error: DetectionModelsSectionError, value: Option<&str>| {
        DetectionModelsSectionError::Detector(Box::new(DetectorError {
            index: 3,
            error,
            value: value.map(ToString::to_string),
        }))
    };
    let db = "detectors[3].detection_models.label_db_match.columns[2].db";
    let cases = [
        (
            detector(
                cell(CellErrorKind::TypeMismatch {
                    expected: OperatorValueType::NonEmptyString,
                }),
                Some("3"),
            ),
            ("INVALID_DOCUMENT", db, "3"),
        ),
        (
            detector(cell(CellErrorKind::Unknown), None),
            ("UNKNOWN_FIELD", db, ""),
        ),
        (
            detector(cell(CellErrorKind::Missing), None),
            ("FIELD_NOT_ALLOWED", db, ""),
        ),
        (
            detector(
                cell(CellErrorKind::OutOfRange {
                    value: "2".to_string(),
                    min: "0".to_string(),
                    max: "1".to_string(),
                }),
                Some("2"),
            ),
            ("BOUND_VIOLATED", db, "2"),
        ),
        (
            detector(cell(CellErrorKind::Empty), Some("\"\"")),
            ("BOUND_VIOLATED", db, "\"\""),
        ),
        (
            detector(
                DetectionModelsSectionError::DisallowedModel {
                    section: "far_outlier".to_string(),
                },
                None,
            ),
            (
                "FIELD_NOT_ALLOWED",
                "detectors[3].detection_models.far_outlier",
                "",
            ),
        ),
        (
            DetectionModelsSectionError::DetectorsNotAnArrayOfTables,
            ("INVALID_DOCUMENT", "", ""),
        ),
        (
            DetectionModelsSectionError::InvalidToml("expected `=`".to_string()),
            ("INVALID_DOCUMENT", "", ""),
        ),
    ];
    for (error, (code, field, value)) in cases {
        assert_eq!(
            refusal_of_error(&unsupervised_refusal(&error, ENGINE)),
            refusal(&error.to_string(), code, field, value, ENGINE),
            "{error:?}"
        );
    }
}

fn engine(key: &str, config: Option<&str>) -> review_database::Agent {
    review_database::Agent {
        kind: AgentKind::Unsupervised,
        ..hog(key, config)
    }
}

/// A detector of a time-series type's model looks up the stored policies its
/// sources name before its sections are checked, and the refused agent is
/// still found with them.
#[tokio::test]
async fn the_refused_time_series_detector_is_found_with_the_stored_policies() {
    let f = Fixture::new(&[(FIRST, Some(APPLIED))]).await;
    let policy = {
        let store = f.schema.store();
        update_node(&store, f.node_id, |node| {
            node.agents.push(engine(ENGINE, None));
        });
        TestModel {
            clustering_model_type: server_daily_tls_v1(),
            ..TestModel::new("t", 1)
        }
        .replace(&store);
        insert_policy(&store, "p", 1, &sensor_name(HOST))
    };
    let stored = f.node();
    let time_series = format!(
        "[[detectors]]\nid = 1\nmodel = \"t\"\nsources = [\"{policy}\"]\ndetection_models = 1\n"
    );
    let mut new = NodeUpdate::from(stored.clone());
    for agent in &mut new.agents {
        if agent.key == ENGINE {
            agent.config = Some(time_series.clone().try_into().expect("valid TOML"));
        }
    }
    let sensors_looked_up = Mutex::new(Vec::new());
    let refused = complete_engine_document(
        AgentKind::Unsupervised,
        &time_series,
        &|name| (name == "t").then(server_daily_tls_v1),
        &|id| {
            sensors_looked_up.lock().expect("not poisoned").push(id);
            None
        },
        CompletionMode::Apply,
    )
    .expect_err("`detection_models` is not a table");
    assert_eq!(*sensors_looked_up.lock().expect("not poisoned"), [policy]);
    let error = anyhow::Error::new(refused.clone());
    let store = f.schema.store();
    let mapped = completion_refusal(&error, &store, &stored, &new).expect("the agent is found");
    assert_eq!(
        refusal_of_error(&mapped),
        refusal_of_error(&unsupervised_refusal(&refused, ENGINE))
    );
}

#[tokio::test]
async fn the_refused_unsupervised_agent_is_found_with_the_stored_model_types() {
    let f = Fixture::new(&[(FIRST, Some(APPLIED))]).await;
    {
        let store = f.schema.store();
        for (name, model_type) in [("m", http_url_v1()), ("c", ClusteringModelTypeRef::Custom)] {
            TestModel {
                clustering_model_type: model_type,
                ..TestModel::new(name, 1)
            }
            .replace(&store);
        }
        update_node(&store, f.node_id, |node| {
            node.agents.push(engine(ENGINE, None));
            node.agents.push(engine("002.reconverge", None));
        });
    }
    let stored = f.node();
    // `far_outlier` is allowed for `m`, so its wrong-type value is what the
    // database write refuses; without the stored type the section itself
    // would be refused, and no agent would be found.
    let document = detector_of(
        "m",
        "[detectors.detection_models.far_outlier]\nenabled = 1\n",
    );
    let disallowed = detector_of("c", "[detectors.detection_models.far_outlier]\n");
    for (agent_key, document, expected) in [
        (
            ENGINE,
            &document,
            (
                "INVALID_DOCUMENT",
                "detectors[0].detection_models.far_outlier.enabled",
                "1",
            ),
        ),
        (
            "002.reconverge",
            &disallowed,
            (
                "FIELD_NOT_ALLOWED",
                "detectors[0].detection_models.far_outlier",
                "",
            ),
        ),
    ] {
        let mut new = NodeUpdate::from(stored.clone());
        for agent in &mut new.agents {
            if agent.key == agent_key {
                agent.config = Some(document.clone().try_into().expect("valid TOML"));
            }
        }
        let refused = unsupervised_error(document);
        let error = anyhow::Error::new(refused.clone())
            .context(format!("cannot complete the document of agent {agent_key}"));
        let store = f.schema.store();
        let mapped = completion_refusal(&error, &store, &stored, &new).expect("the agent is found");
        let (code, field, value) = expected;
        assert_eq!(
            refusal_of_error(&mapped),
            refusal(&refused.to_string(), code, field, value, agent_key)
        );
    }

    // A Semi-supervised Engine refusal is still found among the agents and
    // translated as before, its wrong-type value read from the document.
    let hog_document = "[detection_models.port_scan]\nenabled = \"yes\"\n";
    let mut new = NodeUpdate::from(stored.clone());
    for agent in &mut new.agents {
        if agent.key == FIRST {
            agent.config = Some(hog_document.to_string().try_into().expect("valid TOML"));
        }
    }
    let refused = complete_engine_document(
        AgentKind::SemiSupervised,
        hog_document,
        &|_| None,
        &|_| None,
        CompletionMode::Apply,
    )
    .expect_err("a wrong-type value");
    let error = anyhow::Error::new(refused.clone());
    let store = f.schema.store();
    let mapped = completion_refusal(&error, &store, &stored, &new).expect("the agent is found");
    assert_eq!(
        refusal_of_error(&mapped),
        refusal(
            &refused.to_string(),
            "INVALID_DOCUMENT",
            "detection_models.port_scan.enabled",
            "\"yes\"",
            FIRST,
        )
    );
}
