//! Test support for the Unsupervised Engine relay: an `AgentManager` that
//! records every train, clone, cancel, run once, start and stop request and
//! can be told to fail them, and the nodes a training definition names.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use chrono::Utc;
use review_database::{
    Agent, AgentKind, AgentStatus, ExternalService, ExternalServiceKind, ExternalServiceStatus,
    Lifecycle, ModelInstance, Node, NodeProfile, RunId, Store,
};
use tokio::sync::Notify;

use super::{AgentManager, TestSchema, customer::NetworksTargetAgentLookupKeysPair};
use crate::backend::{DataStoreReadEndpoint, EngineRefused};

/// The port of `publish_srv_addr` in every test Data Store's draft.
pub(super) const PUBLISH_PORT: u16 = 38_371;

/// A request the relay received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RelayCall {
    Train {
        agent_lookup_key: String,
        run_id: RunId,
        model: String,
        definition: String,
    },
    Clone {
        agent_lookup_key: String,
        run_id: RunId,
        source: String,
        target_name: String,
        strip_events: bool,
    },
    Cancel {
        agent_lookup_key: String,
        run_id: RunId,
    },
    RunDetectorOnce {
        agent_lookup_key: String,
        detector_id: i32,
    },
    StartEngineInstance {
        node_id: u32,
        agent_key: String,
    },
    StopEngineInstance {
        node_id: u32,
        agent_key: String,
    },
}

/// How the relay answers a request.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) enum RelayAnswer {
    /// The instance accepted the request.
    #[default]
    Accepted,
    /// The instance received the request and refused it with the reason.
    Refused(String),
    /// The request did not reach the instance.
    Unreachable,
}

/// A pause of the next Data Store endpoint lookup.
#[derive(Default)]
pub(super) struct Pause {
    /// Notified once the paused lookup has started.
    pub(super) entered: Notify,
    /// Notified to let the paused lookup return.
    pub(super) release: Notify,
}

/// The state a [`Relay`] shares with the test that drives it.
#[derive(Default)]
struct RelayState {
    calls: Mutex<Vec<RelayCall>>,
    answer: Mutex<RelayAnswer>,
    /// Whether a failed request is ended as failed by the relay itself, as
    /// aicers/review does, before it returns.
    ends_runs: Mutex<bool>,
    /// The addresses each `(hostname, instance)` Data Store resolves to.
    endpoints: Mutex<HashMap<(String, u32), Vec<IpAddr>>>,
    endpoint_pause: Mutex<Option<Arc<Pause>>>,
    /// The online agents `online_apps_by_host_id` returns.
    online_apps: Mutex<HashMap<String, Vec<(String, String)>>>,
    store: OnceLock<Arc<RwLock<Store>>>,
}

/// The handle a test drives a recording relay with.
#[derive(Clone, Default)]
pub(super) struct Relay(Arc<RelayState>);

impl Relay {
    /// Returns every request received, in order.
    pub(super) fn calls(&self) -> Vec<RelayCall> {
        lock(&self.0.calls).clone()
    }

    /// Makes every later request answer `answer`.
    pub(super) fn answer_with(&self, answer: RelayAnswer) {
        *lock(&self.0.answer) = answer;
    }

    /// Makes the relay end a failed run itself before returning.
    pub(super) fn end_failed_runs(&self) {
        *lock(&self.0.ends_runs) = true;
    }

    /// Makes `online_apps_by_host_id` list the agents of `instance` as online
    /// on `hostname`, keyed by their agent lookup keys.
    pub(super) fn set_online(&self, hostname: &str, instances: &[&ModelInstance]) {
        let apps = instances
            .iter()
            .map(|instance| {
                (
                    super::gen_agent_lookup_key(&instance.agent_key, hostname),
                    instance.agent_key.clone(),
                )
            })
            .collect();
        lock(&self.0.online_apps).insert(hostname.to_string(), apps);
    }

    /// Makes the Data Store `instance` on `hostname` resolve to `addrs`.
    pub(super) fn resolve(&self, hostname: &str, instance: u32, addrs: &[&str]) {
        lock(&self.0.endpoints).insert(
            (hostname.to_string(), instance),
            addrs
                .iter()
                .map(|addr| addr.parse().expect("a literal address"))
                .collect(),
        );
    }

    /// Holds the next Data Store endpoint lookup until `release` is notified.
    pub(super) fn pause_next_lookup(&self) -> Arc<Pause> {
        let pause = Arc::new(Pause::default());
        *lock(&self.0.endpoint_pause) = Some(pause.clone());
        pause
    }

    /// Records `call` and answers it; a failed request of the run `run_id`
    /// is ended as failed first if the relay ends failed runs. A request that
    /// carries no run passes `None`.
    fn record(&self, call: RelayCall, run_id: Option<RunId>) -> Result<(), anyhow::Error> {
        lock(&self.0.calls).push(call);
        let answer = lock(&self.0.answer).clone();
        let error = match answer {
            RelayAnswer::Accepted => return Ok(()),
            RelayAnswer::Refused(reason) => anyhow::Error::new(EngineRefused { reason }),
            RelayAnswer::Unreachable => anyhow::anyhow!("no live connection"),
        };
        if let Some(run_id) = run_id
            && *lock(&self.0.ends_runs)
        {
            let store = self.0.store.get().expect("the store is set");
            store
                .read()
                .expect("not poisoned")
                .fail_run(run_id, &error.to_string())
                .expect("the relay ends an active run");
        }
        Err(error)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .expect("no test thread panics while holding the lock")
}

#[async_trait]
impl AgentManager for Relay {
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
        anyhow::bail!("not expected to be called")
    }

    async fn send_agent_specific_allow_networks(
        &self,
        _networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn send_agent_specific_block_networks(
        &self,
        _networks: &[NetworksTargetAgentLookupKeysPair],
    ) -> Result<Vec<String>, anyhow::Error> {
        anyhow::bail!("not expected to be called")
    }

    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
        Ok(lock(&self.0.online_apps).clone())
    }

    async fn sampling_policies_changed(&self, _generators: &[review_database::ModelInstance]) {}

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

    async fn data_store_read_endpoint(
        &self,
        hostname: &str,
        instance: u32,
    ) -> Result<DataStoreReadEndpoint, anyhow::Error> {
        let pause = lock(&self.0.endpoint_pause).take();
        if let Some(pause) = pause {
            pause.entered.notify_one();
            pause.release.notified().await;
        }
        let addrs = lock(&self.0.endpoints)
            .get(&(hostname.to_string(), instance))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("{hostname} does not resolve"))?;
        Ok(DataStoreReadEndpoint {
            server_name: format!("{instance:03}.giganto.{hostname}"),
            port: 8443,
            addrs,
        })
    }

    async fn train_model(
        &self,
        agent_lookup_key: &str,
        run_id: RunId,
        model: &str,
        definition: &str,
    ) -> Result<(), anyhow::Error> {
        self.record(
            RelayCall::Train {
                agent_lookup_key: agent_lookup_key.to_string(),
                run_id,
                model: model.to_string(),
                definition: definition.to_string(),
            },
            Some(run_id),
        )
    }

    async fn clone_model(
        &self,
        agent_lookup_key: &str,
        run_id: RunId,
        source: &str,
        target_name: &str,
        strip_events: bool,
    ) -> Result<(), anyhow::Error> {
        self.record(
            RelayCall::Clone {
                agent_lookup_key: agent_lookup_key.to_string(),
                run_id,
                source: source.to_string(),
                target_name: target_name.to_string(),
                strip_events,
            },
            Some(run_id),
        )
    }

    async fn cancel_run(&self, agent_lookup_key: &str, run_id: RunId) -> Result<(), anyhow::Error> {
        self.record(
            RelayCall::Cancel {
                agent_lookup_key: agent_lookup_key.to_string(),
                run_id,
            },
            Some(run_id),
        )
    }

    async fn run_detector_once(
        &self,
        agent_lookup_key: &str,
        detector_id: i32,
    ) -> Result<(), anyhow::Error> {
        self.record(
            RelayCall::RunDetectorOnce {
                agent_lookup_key: agent_lookup_key.to_string(),
                detector_id,
            },
            None,
        )
    }

    async fn start_engine_instance(
        &self,
        node_id: u32,
        agent_key: &str,
    ) -> Result<(), anyhow::Error> {
        self.record(
            RelayCall::StartEngineInstance {
                node_id,
                agent_key: agent_key.to_string(),
            },
            None,
        )
    }

    async fn stop_engine_instance(
        &self,
        node_id: u32,
        agent_key: &str,
    ) -> Result<(), anyhow::Error> {
        self.record(
            RelayCall::StopEngineInstance {
                node_id,
                agent_key: agent_key.to_string(),
            },
            None,
        )
    }
}

/// Returns a schema whose agent manager is a recording relay, and the relay.
pub(super) async fn relay_schema() -> (TestSchema, Relay) {
    let relay = Relay::default();
    let schema = TestSchema::new_with_params(Arc::new(relay.clone()), None, "testuser").await;
    relay
        .0
        .store
        .set(schema.store.clone())
        .unwrap_or_else(|_| panic!("the store is set once"));
    (schema, relay)
}

fn agent(key: &str, kind: AgentKind, instance: Option<u32>) -> Agent {
    Agent {
        node_id: u32::MAX,
        key: key.to_string(),
        kind,
        status: AgentStatus::Enabled,
        config: None,
        draft: None,
        installed_version: instance.map(|_| "1.0.0".to_string()),
        installed_commit: instance.map(|_| "abcdef".to_string()),
        lifecycle: if instance.is_some() {
            Lifecycle::Running
        } else {
            Lifecycle::NotInstalled
        },
        bound_addrs: vec![],
        instance,
        run_as_root: false,
        run_as_root_draft: None,
        privilege_profile: None,
    }
}

fn put_node(
    store: &Store,
    customer_id: u32,
    hostname: &str,
    agents: Vec<Agent>,
    external_services: Vec<ExternalService>,
) -> u32 {
    put_named_node(
        store,
        customer_id,
        hostname,
        hostname,
        agents,
        external_services,
    )
}

/// Stores a node named `name` whose applied hostname is `hostname`.
fn put_named_node(
    store: &Store,
    customer_id: u32,
    name: &str,
    hostname: &str,
    agents: Vec<Agent>,
    external_services: Vec<ExternalService>,
) -> u32 {
    let profile = NodeProfile {
        customer_id,
        description: String::new(),
        hostname: hostname.to_string(),
    };
    let node = Node {
        id: u32::MAX,
        name: name.to_string(),
        name_draft: Some(name.to_string()),
        profile: Some(profile.clone()),
        profile_draft: Some(profile),
        agents,
        external_services,
        creation_time: Utc::now(),
    };
    store.node_map().put(&node).expect("insert node")
}

/// Stores a node of `customer_id` at `hostname` running a sensor, and returns
/// its source name.
pub(super) fn insert_sensor_node(store: &Store, customer_id: u32, hostname: &str) -> String {
    put_node(
        store,
        customer_id,
        hostname,
        vec![agent("001.piglet", AgentKind::Sensor, None)],
        vec![],
    );
    format!("piglet.{hostname}")
}

/// Stores a node of `customer_id` at `hostname` running a Log Collector, and
/// returns its source name.
pub(super) fn insert_log_collector_node(store: &Store, customer_id: u32, hostname: &str) -> String {
    put_node(
        store,
        customer_id,
        hostname,
        vec![agent("001.reproduce", AgentKind::LogCollector, None)],
        vec![],
    );
    format!("reproduce.{hostname}")
}

/// Stores a node of `customer_id` at `hostname` running an installed Data
/// Store instance 1 that publishes on [`PUBLISH_PORT`], and returns the Data
/// Store's name.
pub(super) fn insert_data_store_node(store: &Store, customer_id: u32, hostname: &str) -> String {
    insert_named_data_store_node(store, customer_id, hostname, hostname)
}

/// Stores a node named `name` whose applied hostname is `hostname`, running
/// the Data Store [`insert_data_store_node`] stores, and returns the Data
/// Store's name.
pub(super) fn insert_named_data_store_node(
    store: &Store,
    customer_id: u32,
    name: &str,
    hostname: &str,
) -> String {
    let service = ExternalService {
        node_id: u32::MAX,
        key: format!("giganto1@{hostname}"),
        kind: ExternalServiceKind::DataStore,
        status: ExternalServiceStatus::Enabled,
        draft: Some(
            format!("publish_srv_addr = \"0.0.0.0:{PUBLISH_PORT}\"\n")
                .try_into()
                .expect("valid toml"),
        ),
        installed_version: Some("1.0.0".to_string()),
        installed_commit: Some("abcdef".to_string()),
        lifecycle: Lifecycle::Running,
        bound_addrs: vec![],
        instance: Some(1),
    };
    put_named_node(store, customer_id, name, hostname, vec![], vec![service]);
    format!("001.giganto.{hostname}")
}

/// Stores a node of `customer_id` at `hostname` with an installed
/// Unsupervised Engine instance `agent_key`, and returns the instance.
pub(super) fn insert_engine_instance(
    store: &Store,
    customer_id: u32,
    hostname: &str,
    agent_key: &str,
) -> ModelInstance {
    insert_agent_node(
        store,
        customer_id,
        hostname,
        agent_key,
        AgentKind::Unsupervised,
        Some(1),
    )
}

/// Stores a node of `customer_id` at `hostname` with one agent `agent_key`
/// of `kind`, installed as `instance` if that is `Some`, and returns the node
/// id and the agent key.
pub(super) fn insert_agent_node(
    store: &Store,
    customer_id: u32,
    hostname: &str,
    agent_key: &str,
    kind: AgentKind,
    instance: Option<u32>,
) -> ModelInstance {
    let node_id = put_node(
        store,
        customer_id,
        hostname,
        vec![agent(agent_key, kind, instance)],
        vec![],
    );
    ModelInstance {
        node_id,
        agent_key: agent_key.to_string(),
    }
}
