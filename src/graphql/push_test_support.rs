//! Test support for the network lists pushed to agents: an `AgentManager`
//! that records them, and the nodes and groups they are pushed for.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use chrono::Utc;
use review_database::{
    Agent, AgentKind, AgentStatus, HostNetworkGroup, Lifecycle, Node, NodeProfile,
};
use tokio::sync::Notify;

use super::{
    AgentManager, SamplingPolicy, SharedAgentManager, TestSchema,
    customer::NetworksTargetAgentLookupKeysPair,
};

/// One push: the target lookup keys and the group of each pair it sent.
pub(super) type Push = Vec<(Vec<String>, HostNetworkGroup)>;

/// The pushes a [`RecordingAgentManager`] received, by kind, in order.
#[derive(Clone, Default)]
pub(super) struct Pushes {
    internal: Arc<Mutex<Vec<Push>>>,
    allow: Arc<Mutex<Vec<Push>>>,
    block: Arc<Mutex<Vec<Push>>>,
}

impl Pushes {
    /// Returns the internal network pushes.
    pub(super) fn internal(&self) -> Vec<Push> {
        recorded(&self.internal)
    }

    /// Returns the allowlist pushes.
    pub(super) fn allow(&self) -> Vec<Push> {
        recorded(&self.allow)
    }

    /// Returns the blocklist pushes.
    pub(super) fn block(&self) -> Vec<Push> {
        recorded(&self.block)
    }
}

fn recorded(pushes: &Mutex<Vec<Push>>) -> Vec<Push> {
    pushes
        .lock()
        .expect("no test thread panics while holding the lock")
        .clone()
}

fn record(
    pushes: &Mutex<Vec<Push>>,
    networks: &[NetworksTargetAgentLookupKeysPair],
) -> Vec<String> {
    pushes
        .lock()
        .expect("no test thread panics while holding the lock")
        .push(
            networks
                .iter()
                .map(|pair| {
                    (
                        pair.target_agent_lookup_keys().to_vec(),
                        pair.networks().clone(),
                    )
                })
                .collect(),
        );
    networks
        .iter()
        .flat_map(|pair| pair.target_agent_lookup_keys().iter().cloned())
        .collect()
}

/// The kind of push a [`Pause`] holds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PushKind {
    Internal,
    Allow,
}

/// A pause of the first push of one kind a [`RecordingAgentManager`] receives.
#[derive(Default)]
pub(super) struct Pause {
    /// Notified once the paused push has been recorded.
    pub(super) entered: Notify,
    /// Notified to let the paused push return.
    pub(super) release: Notify,
}

/// An `AgentManager` that records every internal network, allowlist and
/// blocklist push, and reaches no agent otherwise.
pub(super) struct RecordingAgentManager {
    pushes: Pushes,
    /// Whether every push fails after it is recorded.
    failing: bool,
    /// The pause of the first push of its kind, until that push takes it.
    pause: Mutex<Option<(PushKind, Arc<Pause>)>>,
}

impl RecordingAgentManager {
    pub(super) fn boxed() -> (SharedAgentManager, Pushes) {
        Self::boxed_with(false, None)
    }

    fn boxed_with(
        failing: bool,
        pause: Option<(PushKind, Arc<Pause>)>,
    ) -> (SharedAgentManager, Pushes) {
        let pushes = Pushes::default();
        let manager = Self {
            pushes: pushes.clone(),
            failing,
            pause: Mutex::new(pause),
        };
        (Arc::new(manager), pushes)
    }

    fn record(
        &self,
        pushes: &Mutex<Vec<Push>>,
        networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        let sent = record(pushes, networks);
        if self.failing {
            anyhow::bail!("{} agents are unreachable", sent.len());
        }
        Ok(sent)
    }

    /// Holds a push of `kind` until released, if it is the one paused.
    async fn hold(&self, kind: PushKind) {
        let pause = {
            let mut pause = self
                .pause
                .lock()
                .expect("no test thread panics while holding the lock");
            if pause.as_ref().is_some_and(|(paused, _)| *paused == kind) {
                pause.take().map(|(_, pause)| pause)
            } else {
                None
            }
        };
        if let Some(pause) = pause {
            pause.entered.notify_one();
            pause.release.notified().await;
        }
    }
}

#[async_trait]
impl AgentManager for RecordingAgentManager {
    async fn request_customer_data_deletion(
        &self,
        _targets: &[crate::customer_data_deletion::CustomerDataDeletionTarget],
    ) -> Result<(), anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn send_agent_specific_internal_networks(
        &self,
        networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        let sent = self.record(&self.pushes.internal, networks);
        self.hold(PushKind::Internal).await;
        sent
    }

    async fn send_agent_specific_allow_networks(
        &self,
        networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        let sent = self.record(&self.pushes.allow, networks);
        self.hold(PushKind::Allow).await;
        sent
    }

    async fn send_agent_specific_block_networks(
        &self,
        networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        self.record(&self.pushes.block, networks)
    }

    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
        Ok(HashMap::new())
    }

    async fn broadcast_crusher_sampling_policy(
        &self,
        _sampling_policies: &[SamplingPolicy],
    ) -> Result<(), anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn capabilities(
        &self,
        hostname: &str,
    ) -> Result<std::collections::BTreeSet<String>, anyhow::Error> {
        anyhow::bail!("{hostname} is unreachable")
    }

    async fn get_resource_usage(
        &self,
        hostname: &str,
    ) -> Result<review_protocol::types::ResourceUsage, anyhow::Error> {
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
        anyhow::bail!("{agent_lookup_key} is unreachable")
    }
}

/// Returns a schema whose agent manager records every push.
pub(super) async fn recording_schema() -> (TestSchema, Pushes) {
    schema_with(false, None).await
}

/// Returns a schema whose agent manager records every push and then fails it.
pub(super) async fn failing_schema() -> (TestSchema, Pushes) {
    schema_with(true, None).await
}

/// Returns a schema whose agent manager records every push, and holds the
/// first push of `kind` after recording it until `release` is notified.
pub(super) async fn paused_schema(kind: PushKind) -> (TestSchema, Pushes, Arc<Pause>) {
    let pause = Arc::new(Pause::default());
    let (schema, pushes) = schema_with(false, Some((kind, pause.clone()))).await;
    (schema, pushes, pause)
}

async fn schema_with(failing: bool, pause: Option<(PushKind, Arc<Pause>)>) -> (TestSchema, Pushes) {
    let (agent_manager, pushes) = RecordingAgentManager::boxed_with(failing, pause);
    let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;
    (schema, pushes)
}

fn agent(key: &str, kind: AgentKind) -> Agent {
    Agent {
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
    }
}

/// Stores a node of `customer_id` at `hostname` running hog and piglet.
pub(super) fn insert_node(schema: &TestSchema, customer_id: u32, hostname: &str) {
    let node = Node {
        id: u32::MAX,
        name: hostname.to_string(),
        name_draft: Some(hostname.to_string()),
        profile: Some(NodeProfile {
            customer_id,
            description: String::new(),
            hostname: hostname.to_string(),
        }),
        profile_draft: None,
        agents: vec![
            agent("001.hog", AgentKind::SemiSupervised),
            agent("001.piglet", AgentKind::Sensor),
        ],
        external_services: vec![],
        creation_time: Utc::now(),
    };
    schema.store().node_map().put(&node).expect("insert node");
}

pub(super) fn group(
    hosts: &[&str],
    networks: &[&str],
    ranges: &[(&str, &str)],
) -> HostNetworkGroup {
    HostNetworkGroup::new(
        hosts.iter().map(|h| h.parse().unwrap()).collect(),
        networks.iter().map(|n| n.parse().unwrap()).collect(),
        ranges
            .iter()
            .map(|(s, e)| s.parse().unwrap()..=e.parse().unwrap())
            .collect(),
    )
}
