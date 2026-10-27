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
    NewTrainingDefinition, Node, NodeProfile, SamplingInterval, SamplingKind, SamplingPeriod,
    Store,
};
use review_protocol::types::ResourceUsage;

use super::{AgentManager, SharedAgentManager, customer::NetworksTargetAgentLookupKeysPair};

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
            agent(
                AgentKind::TimeSeriesGenerator,
                GENERATOR_KEY,
                Some(generator_config(&data_store_name(hostname))),
            ),
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

/// Stores a draft policy `name` of `customer_id` reading `node`, and returns
/// its ID.
pub(super) fn insert_policy(store: &Store, name: &str, customer_id: u32, node: &str) -> u32 {
    store
        .sampling_policy_map()
        .insert(NewSamplingPolicy {
            name: name.to_string(),
            kind: SamplingKind::Conn,
            interval: SamplingInterval::FifteenMinutes,
            period: SamplingPeriod::OneDay,
            offset: 0,
            src_ip: None,
            dst_ip: None,
            node: Some(node.to_string()),
            column: None,
            customer_id,
        })
        .expect("insert policy")
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
