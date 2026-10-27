//! Test helpers that create models, engine instances and indicators through
//! review-database's guarded writers.

use std::collections::HashSet;
use std::io::Write;

use chrono::{DateTime, Utc};
use review_database::{
    EngineDetectorRef, EngineDocumentRefs, EngineDocumentWrite, ModelInstance, ModelMethod,
    ModelOwner, NewTrainingDefinition, NodeUpdate, Store, TrainedWith, types::ModelBatchInfo,
};
use serde::Serialize;

/// The agent key of the engine instance test models belong to.
pub(super) const TEST_AGENT_KEY: &str = "unsupervised@test";
/// The event kind test models are trained on.
pub(super) const TEST_EVENT_KIND: &str = "http";

/// Returns the engine instance a test model of `customer_id` belongs to by
/// default: the agent [`TEST_AGENT_KEY`] of the node whose id is the customer
/// id. No agent row backs it.
pub(super) fn test_instance(customer_id: u32) -> ModelInstance {
    ModelInstance {
        node_id: customer_id,
        agent_key: TEST_AGENT_KEY.to_string(),
    }
}

/// A model to create or replace with [`TestModel::replace`].
pub(super) struct TestModel<'a> {
    pub(super) name: &'a str,
    pub(super) customer_id: u32,
    pub(super) instance: ModelInstance,
    /// The record `kind`: `Multifield`, `Prefix` or `Timeseries`.
    pub(super) kind: &'a str,
    pub(super) version: i32,
    /// The batch timestamps of the rounds the replace makes current.
    pub(super) rounds: &'a [i64],
    pub(super) trained_at: DateTime<Utc>,
    /// The sources of the definition that trained the model.
    pub(super) trained_sources: Vec<String>,
}

impl<'a> TestModel<'a> {
    /// Returns a multidimension model `name` of `customer_id` on
    /// [`test_instance`], with no rounds.
    pub(super) fn new(name: &'a str, customer_id: u32) -> Self {
        Self {
            name,
            customer_id,
            instance: test_instance(customer_id),
            kind: "Multifield",
            version: 1,
            rounds: &[],
            trained_at: Utc::now(),
            trained_sources: Vec::new(),
        }
    }

    /// Creates the model, or replaces it, making its current result the
    /// previous one. Returns its id.
    pub(super) fn replace(self, store: &Store) -> u32 {
        let model = review_database::Model {
            id: 0,
            name: self.name.to_string(),
            version: self.version,
            kind: self.kind.to_string(),
            serialized_classifier: vec![1, 2, 3],
            max_event_id_num: 50,
            event_kind: TEST_EVENT_KIND.to_string(),
            classification_id: 0,
            batch_info: self
                .rounds
                .iter()
                .map(|&id| ModelBatchInfo {
                    id,
                    earliest: id,
                    latest: id + 1,
                    size: 1,
                    sensors: vec!["sensor".to_string()],
                })
                .collect(),
            scores: review_database::types::ModelScores::new(),
        };
        let owner = ModelOwner {
            customer_id: self.customer_id,
            instance: self.instance,
        };
        let trained = TrainedWith {
            run_id: 1,
            definition: String::new(),
            sources: self.trained_sources,
        };
        store
            .replace_model(model, owner, self.trained_at, trained)
            .expect("replace a test model")
            .id
    }
}

/// Creates the multidimension model `name` for `customer_id`, or replaces it,
/// making its current result the previous one. Returns its id.
pub(super) fn replace_model(store: &Store, name: &str, customer_id: u32) -> u32 {
    TestModel::new(name, customer_id).replace(store)
}

/// Creates the models `model-0`, `model-1`, … of `customer_id` until one has
/// the id `id`, and returns that id.
///
/// Model ids are handed out from 0 in creation order, so this lets a test
/// address its model by a fixed id.
pub(super) fn replace_models_through(store: &Store, id: u32, customer_id: u32) -> u32 {
    for i in 0..=id {
        let created = replace_model(store, &format!("model-{i}"), customer_id);
        assert_eq!(created, i, "model ids are handed out in order");
    }
    id
}

/// Returns a test schema whose store holds the models with ids 0 through
/// `id`, all of customer 0.
pub(super) async fn schema_with_models_through(id: u32) -> super::TestSchema {
    let schema = super::TestSchema::new().await;
    replace_models_through(&schema.store(), id, 0);
    schema
}

/// Stores a node of `customer_id` with an applied profile and an installed
/// Unsupervised Engine agent [`TEST_AGENT_KEY`], and returns that instance.
pub(super) fn insert_engine_node(store: &Store, customer_id: u32) -> ModelInstance {
    let hostname = format!("engine-{customer_id}.example.com");
    let profile = review_database::NodeProfile {
        customer_id,
        description: String::new(),
        hostname: hostname.clone(),
    };
    let agent = review_database::Agent {
        node_id: u32::MAX,
        key: TEST_AGENT_KEY.to_string(),
        kind: review_database::AgentKind::Unsupervised,
        status: review_database::AgentStatus::Enabled,
        config: None,
        draft: None,
        installed_version: Some("1.0.0".to_string()),
        installed_commit: Some("abcdef".to_string()),
        lifecycle: review_database::Lifecycle::Running,
        bound_addrs: vec![],
        instance: Some(1),
    };
    let node = review_database::Node {
        id: u32::MAX,
        name: hostname.clone(),
        name_draft: Some(hostname),
        profile: Some(profile.clone()),
        profile_draft: Some(profile),
        agents: vec![agent],
        external_services: vec![],
        creation_time: Utc::now(),
    };
    let node_id = store.node_map().put(&node).expect("insert engine node");
    ModelInstance {
        node_id,
        agent_key: TEST_AGENT_KEY.to_string(),
    }
}

/// Records that detector `detector_id` of `instance`'s applied engine document
/// serves `model` with `indicator`.
pub(super) fn name_in_applied_document(
    store: &Store,
    instance: &ModelInstance,
    detector_id: i32,
    model: &str,
    indicator: &str,
) {
    let mut map = store.node_map();
    let (node, _, _) = map
        .get_by_id(instance.node_id)
        .expect("read engine node")
        .expect("engine node exists");
    let update = NodeUpdate::from(node);
    let document = EngineDocumentWrite {
        agent_key: instance.agent_key.clone(),
        applied: Some(EngineDocumentRefs {
            detectors: vec![EngineDetectorRef {
                id: detector_id,
                model: model.to_string(),
                sources: vec![],
                indicator: Some(indicator.to_string()),
            }],
        }),
        pending: None,
    };
    map.update_with_engine_documents(instance.node_id, &update, &update, &[document])
        .expect("write engine document references");
}

/// Stores the training definition `name` of `customer_id` on `instance`,
/// naming `indicator`.
pub(super) fn insert_definition(
    store: &Store,
    name: &str,
    customer_id: u32,
    instance: &ModelInstance,
    indicator: &str,
) {
    store
        .insert_training_definition(NewTrainingDefinition {
            name: name.to_string(),
            customer_id,
            instance: instance.clone(),
            method: ModelMethod::Multidimension,
            event_kind: TEST_EVENT_KIND.to_string(),
            sources: vec![],
            indicator: Some(indicator.to_string()),
            definition: String::new(),
        })
        .expect("insert training definition");
}

/// Stores the indicator `name` of `model_id` through the guarded insert.
pub(super) fn insert_indicator(store: &Store, name: &str, model_id: u32) {
    store
        .insert_model_indicator(review_database::ModelIndicator {
            name: name.to_string(),
            description: format!("indicator {name}"),
            model_id,
            tokens: HashSet::from([vec!["token".to_string()]]),
            last_modification_time: Utc::now(),
        })
        .expect("insert indicator");
}

/// The stored form of an indicator's value, as the `dbfile` of
/// `insertIndicator` and `updateIndicator` carries it.
#[derive(Serialize)]
struct IndicatorValue {
    description: String,
    model_id: u32,
    tokens: HashSet<Vec<String>>,
    #[serde(with = "chrono::serde::ts_seconds")]
    last_modification_time: DateTime<Utc>,
}

/// Returns the `dbfile` of an indicator of `model_id` with `description`: its
/// value, bincode-serialized, gzip-compressed and base64-encoded.
pub(super) fn indicator_dbfile(model_id: u32, description: &str) -> String {
    use base64::Engine as _;
    use bincode::Options;

    let value = IndicatorValue {
        description: description.to_string(),
        model_id,
        tokens: HashSet::from([vec!["token".to_string()]]),
        last_modification_time: Utc::now(),
    };
    let serialized = bincode::DefaultOptions::new()
        .serialize(&value)
        .expect("serialize indicator");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&serialized).expect("compress indicator");
    let compressed = encoder.finish().expect("compress indicator");
    base64::engine::general_purpose::STANDARD.encode(compressed)
}

/// Returns the message and the extensions of the single error of `response`.
pub(super) fn single_error(response: &async_graphql::Response) -> (String, serde_json::Value) {
    assert_eq!(response.errors.len(), 1, "{response:?}");
    let error = serde_json::to_value(&response.errors[0]).expect("serialize error");
    (
        response.errors[0].message.clone(),
        error["extensions"].clone(),
    )
}

/// Returns the data of `response`, which must have no error.
pub(super) fn data(response: async_graphql::Response) -> serde_json::Value {
    assert!(response.errors.is_empty(), "{response:?}");
    response.data.into_json().expect("data is JSON")
}
