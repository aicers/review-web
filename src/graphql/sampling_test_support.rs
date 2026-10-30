//! Test support for sampling policies: an `AgentManager` that records the
//! generators it is told about, and the nodes, generators and uses that
//! policies need.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use chrono::Utc;
use review_database::{
    Agent, AgentKind, AgentStatus, Lifecycle, ModelInstance, ModelMethod, NewSamplingPolicy,
    NewTrainingDefinition, Node, NodeProfile, NodeUpdate, SamplingInterval, SamplingKind,
    SamplingPeriod, Store,
};
use review_protocol::types::ResourceUsage;
use tempfile::TempDir;

use super::{
    AgentManager, SharedAgentManager, customer::NetworksTargetAgentLookupKeysPair,
    run_test_support::insert_data_store_node,
};

/// The agent key of the Time Series Generator of a node from
/// [`insert_generator_node`].
pub(super) const GENERATOR_KEY: &str = "crusher@test";
/// The agent key of the Sensor of a node from [`insert_generator_node`].
pub(super) const SENSOR_KEY: &str = "piglet@test";

/// Returns the sensor name of a node from [`insert_generator_node`].
pub(super) fn sensor_name(hostname: &str) -> String {
    format!("piglet.{hostname}")
}

/// Returns the Data Store name the generator of a node from
/// [`insert_generator_node`] is configured with.
pub(super) fn data_store_name(hostname: &str) -> String {
    format!("001.giganto.{hostname}")
}

/// Returns a Time Series Generator configuration naming the Data Store
/// `giganto_name`.
pub(super) fn generator_config(giganto_name: &str) -> String {
    format!("giganto_name = {giganto_name:?}\n")
}

fn agent(kind: AgentKind, key: &str, config: Option<String>) -> Agent {
    let config = config.map(|config| config.try_into().expect("a valid agent configuration"));
    Agent {
        node_id: u32::MAX,
        key: key.to_string(),
        kind,
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

/// Stores the node `hostname` of `customer_id`, applied, with a Sensor
/// [`SENSOR_KEY`] and a Time Series Generator [`GENERATOR_KEY`] whose Data
/// Store is [`data_store_name`], and returns the generator.
pub(super) fn insert_generator_node(
    store: &Store,
    hostname: &str,
    customer_id: u32,
) -> ModelInstance {
    insert_generator_node_with(
        store,
        hostname,
        customer_id,
        Some(generator_config(&data_store_name(hostname))),
    )
}

/// Stores the node [`insert_generator_node`] stores, with `config` as the
/// generator's applied configuration and draft, and returns the generator.
pub(super) fn insert_generator_node_with(
    store: &Store,
    hostname: &str,
    customer_id: u32,
    config: Option<String>,
) -> ModelInstance {
    let profile = NodeProfile {
        customer_id,
        description: String::new(),
        hostname: hostname.to_string(),
    };
    let node = Node {
        id: u32::MAX,
        name: hostname.to_string(),
        name_draft: Some(hostname.to_string()),
        profile: Some(profile.clone()),
        profile_draft: Some(profile),
        agents: vec![
            // A draft equal to the config keeps an apply from removing it.
            agent(AgentKind::Sensor, SENSOR_KEY, Some(String::new())),
            agent(AgentKind::TimeSeriesGenerator, GENERATOR_KEY, config),
        ],
        external_services: vec![],
        creation_time: Utc::now(),
    };
    let node_id = store.node_map().put(&node).expect("insert generator node");
    ModelInstance {
        node_id,
        agent_key: GENERATOR_KEY.to_string(),
    }
}

/// The shape of a policy from [`insert_shaped_policy`].
#[derive(Clone, Copy)]
pub(super) struct PolicyShape {
    pub(super) kind: SamplingKind,
    pub(super) column: Option<u32>,
    pub(super) interval: SamplingInterval,
    pub(super) period: SamplingPeriod,
    pub(super) offset: i32,
}

impl Default for PolicyShape {
    fn default() -> Self {
        Self {
            kind: SamplingKind::Conn,
            column: None,
            interval: SamplingInterval::FifteenMinutes,
            period: SamplingPeriod::OneDay,
            offset: 0,
        }
    }
}

/// Stores a draft policy `name` of `customer_id` reading `node`, and returns
/// its ID.
pub(super) fn insert_policy(store: &Store, name: &str, customer_id: u32, node: &str) -> u32 {
    insert_shaped_policy(store, name, customer_id, node, PolicyShape::default())
}

/// Stores a draft policy `name` of `customer_id` reading `node` with
/// `shape`, and returns its ID.
pub(super) fn insert_shaped_policy(
    store: &Store,
    name: &str,
    customer_id: u32,
    node: &str,
    shape: PolicyShape,
) -> u32 {
    store
        .sampling_policy_map()
        .insert(NewSamplingPolicy {
            name: name.to_string(),
            kind: shape.kind,
            interval: shape.interval,
            period: shape.period,
            offset: shape.offset,
            src_ip: None,
            dst_ip: None,
            node: Some(node.to_string()),
            column: shape.column,
            customer_id,
        })
        .expect("insert policy")
}

/// Stores a policy `name` of `customer_id` with `shape`, reading the sensor
/// of the node of `generator` and assigned to it, and returns its ID.
pub(super) fn insert_assigned_policy(
    store: &Store,
    name: &str,
    customer_id: u32,
    generator: &ModelInstance,
    shape: PolicyShape,
) -> u32 {
    let (node, _, _) = store
        .node_map()
        .get_by_id(generator.node_id)
        .expect("read generator node")
        .expect("generator node exists");
    let hostname = node.profile.expect("generator node is applied").hostname;
    let id = insert_shaped_policy(store, name, customer_id, &sensor_name(&hostname), shape);
    store
        .sampling_policy_map()
        .assign(id, Some(generator), true)
        .expect("assign policy");
    id
}

/// Replaces the applied configuration and the draft of the generator
/// `generator` with `config`, leaving its policies as they are.
pub(super) fn set_generator_config(
    store: &Store,
    generator: &ModelInstance,
    config: Option<String>,
) {
    let mut map = store.node_map();
    let (node, _, _) = map
        .get_by_id(generator.node_id)
        .expect("read generator node")
        .expect("generator node exists");
    let old = NodeUpdate::from(node.clone());
    let mut new = NodeUpdate::from(node);
    let config = config.map(|config| config.try_into().expect("a valid agent configuration"));
    for agent in &mut new.agents {
        if agent.key == generator.agent_key {
            agent.config.clone_from(&config);
            agent.draft.clone_from(&config);
        }
    }
    map.update(generator.node_id, &old, &new)
        .expect("update generator configuration");
}

/// Returns a timeseries training definition reading the policies `sources`
/// from the Data Store `server_name` at `address`, with `extra` top-level
/// lines.
pub(super) fn timeseries_definition(
    sources: &[u32],
    server_name: &str,
    address: &str,
    extra: &str,
) -> String {
    let sources = sources
        .iter()
        .map(|id| format!("\"{id}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        r#"event_kind = "timeseries"
method = "timeseries"
sources = [{sources}]
window_start = "2026-10-14T00:00:00Z"
window_end = "2026-10-21T00:00:00Z"
{extra}

[data_store]
address = "{address}"
server_name = "{server_name}"
"#
    )
}

/// Puts the policy `id` in use: the timeseries training definition `name` of
/// `customer_id`, on the engine instance `engine`, names it as a source.
pub(super) fn use_policy(
    store: &Store,
    name: &str,
    customer_id: u32,
    engine: &ModelInstance,
    id: u32,
) {
    store
        .insert_training_definition(NewTrainingDefinition {
            name: name.to_string(),
            customer_id,
            instance: engine.clone(),
            method: ModelMethod::Timeseries,
            event_kind: "conn".to_string(),
            sources: vec![id.to_string()],
            indicator: None,
            definition: String::new(),
        })
        .expect("insert training definition");
}

/// The calls a [`DeliveryRecorder`] received when it received none.
pub(super) const NO_DELIVERIES: [Vec<ModelInstance>; 0] = [];

/// The calls of `sampling_policies_changed` a [`DeliveryRecorder`] received,
/// in order.
#[derive(Clone, Default)]
pub(super) struct Deliveries(Arc<Mutex<Vec<Vec<ModelInstance>>>>);

impl Deliveries {
    /// Returns the generators of each call.
    pub(super) fn calls(&self) -> Vec<Vec<ModelInstance>> {
        self.0
            .lock()
            .expect("no test thread panics while holding the lock")
            .clone()
    }
}

/// An `AgentManager` that records every `sampling_policies_changed` call,
/// reaching no generator, accepts every configuration update, and refuses
/// everything else.
pub(super) struct DeliveryRecorder {
    deliveries: Deliveries,
}

impl DeliveryRecorder {
    pub(super) fn boxed() -> (SharedAgentManager, Deliveries) {
        let deliveries = Deliveries::default();
        let manager = Self {
            deliveries: deliveries.clone(),
        };
        (Arc::new(manager), deliveries)
    }
}

#[async_trait]
impl AgentManager for DeliveryRecorder {
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
        anyhow::bail!("no agent is connected")
    }

    async fn send_agent_specific_allow_networks(
        &self,
        _networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        anyhow::bail!("no agent is connected")
    }

    async fn send_agent_specific_block_networks(
        &self,
        _networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        anyhow::bail!("no agent is connected")
    }

    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
        Ok(HashMap::new())
    }

    async fn sampling_policies_changed(&self, generators: &[ModelInstance]) {
        self.deliveries
            .0
            .lock()
            .expect("no test thread panics while holding the lock")
            .push(generators.to_vec());
    }

    async fn capabilities(&self, _hostname: &str) -> Result<BTreeSet<String>, anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn get_resource_usage(&self, _hostname: &str) -> Result<ResourceUsage, anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn ping(&self, _hostname: &str) -> Result<Duration, anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn update_config(&self, _agent_lookup_key: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }
}

/// The customer of the policies of a [`PolicyFixture`].
pub(super) const POLICY_CUSTOMER: u32 = 1;
/// The other customer of a [`PolicyFixture`].
pub(super) const OTHER_POLICY_CUSTOMER: u32 = 2;
/// An address of the first Data Store of a [`PolicyFixture`].
pub(super) const OWN_ADDRESS: &str = "10.0.0.5:38371";

/// A store with two Data Stores of [`POLICY_CUSTOMER`], a Time Series
/// Generator of each of [`POLICY_CUSTOMER`] and [`OTHER_POLICY_CUSTOMER`]
/// writing to the first, one of [`POLICY_CUSTOMER`] writing to the second,
/// and two policies of [`POLICY_CUSTOMER`] of the default shape assigned to
/// the first generator.
pub(super) struct PolicyFixture {
    _db: TempDir,
    _backup: TempDir,
    pub(super) store: Store,
    /// The first Data Store, on `store.example.com`.
    pub(super) server_name: String,
    /// The second Data Store, on `store2.example.com`.
    pub(super) other_server_name: String,
    /// The generator on `gen-a.example.com`.
    pub(super) generator: ModelInstance,
    /// The generator on `gen-a2.example.com`.
    pub(super) other_generator: ModelInstance,
    /// The generator on `gen-b.example.com`.
    pub(super) generator_b: ModelInstance,
    pub(super) assigned: [u32; 2],
}

impl PolicyFixture {
    pub(super) fn new() -> Self {
        let db = tempfile::tempdir().expect("create a database directory");
        let backup = tempfile::tempdir().expect("create a backup directory");
        let store = Store::new(db.path(), backup.path(), None).expect("open a store");
        let server_name = insert_data_store_node(&store, POLICY_CUSTOMER, "store.example.com");
        let other_server_name =
            insert_data_store_node(&store, POLICY_CUSTOMER, "store2.example.com");
        let generator = insert_generator_node_with(
            &store,
            "gen-a.example.com",
            POLICY_CUSTOMER,
            Some(generator_config(&server_name)),
        );
        let other_generator = insert_generator_node_with(
            &store,
            "gen-a2.example.com",
            POLICY_CUSTOMER,
            Some(generator_config(&other_server_name)),
        );
        let generator_b = insert_generator_node_with(
            &store,
            "gen-b.example.com",
            OTHER_POLICY_CUSTOMER,
            Some(generator_config(&server_name)),
        );
        let assigned = ["p1", "p2"].map(|name| {
            insert_assigned_policy(
                &store,
                name,
                POLICY_CUSTOMER,
                &generator,
                PolicyShape::default(),
            )
        });
        Self {
            _db: db,
            _backup: backup,
            store,
            server_name,
            other_server_name,
            generator,
            other_generator,
            generator_b,
            assigned,
        }
    }

    /// Returns a timeseries definition reading `sources` from the first Data
    /// Store at [`OWN_ADDRESS`].
    pub(super) fn definition(&self, sources: &[u32]) -> String {
        timeseries_definition(sources, &self.server_name, OWN_ADDRESS, "")
    }

    /// Stores a policy of [`POLICY_CUSTOMER`] of `shape` assigned to
    /// `generator`, and returns its ID.
    pub(super) fn assigned_policy(
        &self,
        name: &str,
        generator: &ModelInstance,
        shape: PolicyShape,
    ) -> u32 {
        insert_assigned_policy(&self.store, name, POLICY_CUSTOMER, generator, shape)
    }
}
