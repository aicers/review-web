use std::time::Duration;

use async_graphql::{Context, Object, Result, SimpleObject, types::ID};
use review_database::event::Direction;
use serde::{Deserialize, Serialize};
use tracing::info;

use super::{
    super::{Role, RoleGuard, SharedAgentManager},
    TimeSyncMutation, TimeSyncQuery, matches_manager_hostname,
};
use crate::backend::TimeSyncStatus;
use crate::info_with_username;

/// How long the Central Manager host's Host Agent is given to answer a Get or
/// a Set of its time sources, stream acquisition and response included.
const TIME_SOURCES_TIMEOUT: Duration = Duration::from_secs(10);

const MANAGER_NOT_REGISTERED: &str = "the Central Manager node is not registered";
const MANAGER_TIMED_OUT: &str = "the Central Manager host did not answer in time";

/// The time synchronization state a node's Host Agent reports.
#[derive(Clone, Deserialize, Serialize, SimpleObject)]
pub(super) struct NodeTimeSync {
    /// Whether the host's time synchronization service is enabled.
    enabled: bool,
    /// The host's clock is synchronized to the source it is meant to follow,
    /// as of a recent measurement.
    synchronized: bool,
    /// The time source in use, or null when there is none or it is the
    /// host's own clock.
    server: Option<String>,
    /// The host's clock minus its source's at the last measurement, in
    /// seconds: positive when the host is ahead. Null when unknown.
    offset: Option<f64>,
}

impl From<TimeSyncStatus> for NodeTimeSync {
    fn from(status: TimeSyncStatus) -> Self {
        Self {
            enabled: status.enabled,
            synchronized: status.synchronized,
            server: status.server,
            // Exact below 2^53 microseconds (about 285 years), far beyond any
            // clock offset.
            #[allow(clippy::cast_precision_loss)]
            offset: status
                .offset_micros
                .map(|micros| micros as f64 / 1_000_000.0),
        }
    }
}

/// The Central Manager node and the upstream NTP servers of its host.
#[derive(SimpleObject)]
pub(super) struct CentralManagerTimeSources {
    /// The ID of the Central Manager node, as `Node.id` and `NodeStatus.id`
    /// give it.
    node_id: ID,
    /// The upstream NTP servers, in the order of the host's configuration
    /// file. chrony chooses among them by its own measurements; the order sets
    /// no preference. An empty list means none is set: the host then uses
    /// Ubuntu's default servers where reachable, and its own clock otherwise.
    servers: Vec<String>,
}

#[Object]
impl TimeSyncQuery {
    /// The Central Manager node and the upstream NTP servers of its host.
    /// Fails with "the Central Manager host did not answer in time" when its
    /// Host Agent does not answer within 10 seconds.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn central_manager_time_sources(
        &self,
        ctx: &Context<'_>,
    ) -> Result<CentralManagerTimeSources> {
        info_with_username!(ctx, "Central Manager time sources lookup requested");
        let (id, hostname) = manager_node(ctx)?;
        let agent_manager = ctx.data::<SharedAgentManager>()?;
        let servers =
            tokio::time::timeout(TIME_SOURCES_TIMEOUT, agent_manager.time_sources(&hostname))
                .await
                .map_err(|_| MANAGER_TIMED_OUT)??;
        Ok(CentralManagerTimeSources {
            node_id: ID(id.to_string()),
            servers,
        })
    }
}

#[Object]
impl TimeSyncMutation {
    /// Replaces the upstream NTP servers of the Central Manager host and
    /// returns the list sent. The host's Host Agent validates the list before
    /// writing anything and refuses an invalid list whole, with the reason as
    /// the error message. When the Host Agent does not answer within 10
    /// seconds, the request fails with "the Central Manager host did not answer
    /// in time". Any other error, the 10-second deadline included, may leave
    /// the list applied; read it again with `centralManagerTimeSources` before
    /// retrying.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn set_central_manager_time_sources(
        &self,
        ctx: &Context<'_>,
        servers: Vec<String>,
    ) -> Result<Vec<String>> {
        info_with_username!(
            ctx,
            "Central Manager time sources update requested: {servers:?}"
        );
        let (_, hostname) = manager_node(ctx)?;
        let agent_manager = ctx.data::<SharedAgentManager>()?;
        tokio::time::timeout(
            TIME_SOURCES_TIMEOUT,
            agent_manager.set_time_sources(&hostname, &servers),
        )
        .await
        .map_err(|_| MANAGER_TIMED_OUT)??;
        Ok(servers)
    }
}

/// Returns the ID and hostname of the first node, in forward order, whose
/// applied profile names the Central Manager's host.
///
/// Only the node store is read, so no Host Agent is asked and none can delay
/// the lookup.
fn manager_node(ctx: &Context<'_>) -> Result<(u32, String)> {
    let store = crate::graphql::get_store(ctx)?;
    let map = store.node_map();
    for entry in map.iter(Direction::Forward, None) {
        let node = entry?;
        if let Some(profile) = node.profile
            && matches_manager_hostname(&profile.hostname)
        {
            return Ok((node.id, profile.hostname));
        }
    }
    Err(MANAGER_NOT_REGISTERED.into())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::future::pending;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use chrono::Utc;
    use review_protocol::types::ResourceUsage;
    use serde_json::json;
    use tokio::sync::Barrier;

    use super::*;
    use crate::graphql::node::test_support::insert_active_node;
    use crate::graphql::{
        AgentManager, SamplingPolicy, TestSchema, customer::NetworksTargetAgentLookupKeysPair,
    };

    const FOLLOWER: &str = "follower.example.com";
    const SERVERS: [&str; 2] = ["192.0.2.10", "ntp.example.internal"];

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Call {
        Status(String),
        Get(String),
        Set(String, Vec<String>),
    }

    struct StubAgentManager {
        statuses: HashMap<String, Result<TimeSyncStatus, String>>,
        stalled: HashSet<String>,
        time_sources: Result<Vec<String>, String>,
        set_time_sources: Result<(), String>,
        barrier: Option<Arc<Barrier>>,
        calls: Mutex<Vec<Call>>,
    }

    impl StubAgentManager {
        fn new() -> Self {
            Self {
                statuses: HashMap::new(),
                stalled: HashSet::new(),
                time_sources: Ok(SERVERS.iter().map(ToString::to_string).collect()),
                set_time_sources: Ok(()),
                barrier: None,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn record(&self, call: Call) {
            self.calls.lock().unwrap().push(call);
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }

        async fn wait_at_barrier(&self) {
            if let Some(barrier) = &self.barrier {
                barrier.wait().await;
            }
        }

        async fn stall_if(&self, hostname: &str) {
            if self.stalled.contains(hostname) {
                pending::<()>().await;
            }
        }
    }

    #[async_trait]
    impl AgentManager for StubAgentManager {
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
            anyhow::bail!("not expected to be called")
        }

        async fn broadcast_crusher_sampling_policy(
            &self,
            _sampling_policies: &[SamplingPolicy],
        ) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }

        async fn capabilities(&self, _hostname: &str) -> Result<BTreeSet<String>, anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }

        async fn get_resource_usage(
            &self,
            _hostname: &str,
        ) -> Result<ResourceUsage, anyhow::Error> {
            self.wait_at_barrier().await;
            Ok(ResourceUsage {
                cpu_usage: 20.0,
                total_memory: 1000,
                used_memory: 100,
                disk_used_bytes: 100,
                disk_available_bytes: 900,
            })
        }

        async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }

        async fn ping(&self, _hostname: &str) -> Result<Duration, anyhow::Error> {
            self.wait_at_barrier().await;
            Ok(Duration::from_micros(10))
        }

        async fn time_sync_status(&self, hostname: &str) -> Result<TimeSyncStatus, anyhow::Error> {
            self.record(Call::Status(hostname.to_string()));
            self.wait_at_barrier().await;
            self.stall_if(hostname).await;
            match self.statuses.get(hostname) {
                Some(Ok(status)) => Ok(status.clone()),
                Some(Err(e)) => Err(anyhow::anyhow!("{e}")),
                None => anyhow::bail!("no status for {hostname}"),
            }
        }

        async fn time_sources(&self, hostname: &str) -> Result<Vec<String>, anyhow::Error> {
            self.record(Call::Get(hostname.to_string()));
            self.stall_if(hostname).await;
            self.time_sources
                .clone()
                .map_err(|e| anyhow::anyhow!("{e}"))
        }

        async fn set_time_sources(
            &self,
            hostname: &str,
            servers: &[String],
        ) -> Result<(), anyhow::Error> {
            self.record(Call::Set(hostname.to_string(), servers.to_vec()));
            self.stall_if(hostname).await;
            self.set_time_sources
                .clone()
                .map_err(|e| anyhow::anyhow!("{e}"))
        }

        async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }

        async fn update_config(&self, _agent_lookup_key: &str) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }
    }

    fn manager_hostname() -> String {
        let hostname = gethostname::gethostname().to_string_lossy().into_owned();
        assert_ne!(hostname, "");
        hostname
    }

    async fn schema_with(stub: StubAgentManager) -> (TestSchema, Arc<StubAgentManager>) {
        let stub = Arc::new(stub);
        let agent_manager: SharedAgentManager = stub.clone();
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;
        (schema, stub)
    }

    fn servers() -> Vec<String> {
        SERVERS.iter().map(ToString::to_string).collect()
    }

    /// Stores a node whose hostname is only in its draft profile.
    fn put_draft_only_node(store: &review_database::Store, name: &str, hostname: &str) -> u32 {
        let node = review_database::Node {
            id: u32::MAX,
            name: name.to_string(),
            name_draft: Some(name.to_string()),
            profile: None,
            profile_draft: Some(review_database::NodeProfile {
                customer_id: 1,
                description: "draft".to_string(),
                hostname: hostname.to_string(),
            }),
            agents: vec![],
            external_services: vec![],
            creation_time: Utc::now(),
        };
        store.node_map().put(&node).expect("insert node")
    }

    const STATUS_QUERY: &str = r"{nodeStatusList{edges{node{name cpuUsage ping timeSync{enabled synchronized server offset}}}}}";
    const GET_QUERY: &str = r"{centralManagerTimeSources{nodeId servers}}";
    const SET_MUTATION: &str = r#"mutation {
        setCentralManagerTimeSources(servers: ["192.0.2.10", "ntp.example.internal"])
    }"#;

    fn error_message(res: &async_graphql::Response) -> &str {
        assert_eq!(res.errors.len(), 1, "{:?}", res.errors);
        res.errors[0].message.as_str()
    }

    #[tokio::test]
    async fn status_fields_are_reported() {
        let manager = manager_hostname();
        let mut stub = StubAgentManager::new();
        stub.statuses.insert(
            manager.clone(),
            Ok(TimeSyncStatus {
                enabled: true,
                synchronized: true,
                server: None,
                offset_micros: None,
            }),
        );
        stub.statuses.insert(
            FOLLOWER.to_string(),
            Ok(TimeSyncStatus {
                enabled: true,
                synchronized: false,
                server: Some("10.0.0.1".to_string()),
                offset_micros: Some(-1_500),
            }),
        );
        let (schema, _) = schema_with(stub).await;
        insert_active_node(&schema.store(), "manager", 1, &manager);
        insert_active_node(&schema.store(), "follower", 1, FOLLOWER);

        let res = schema
            .execute_as_system_admin(
                r"{nodeStatusList{edges{node{name timeSync{enabled synchronized server offset}}}}}",
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeStatusList": {
                    "edges": [
                        {"node": {"name": "follower", "timeSync": {
                            "enabled": true,
                            "synchronized": false,
                            "server": "10.0.0.1",
                            "offset": -0.0015
                        }}},
                        {"node": {"name": "manager", "timeSync": {
                            "enabled": true,
                            "synchronized": true,
                            "server": null,
                            "offset": null
                        }}}
                    ]
                }
            })
        );
    }

    #[tokio::test]
    async fn unsupported_status_is_null() {
        let mut stub = StubAgentManager::new();
        stub.statuses
            .insert(FOLLOWER.to_string(), Err("not supported".to_string()));
        let (schema, _) = schema_with(stub).await;
        insert_active_node(&schema.store(), "follower", 1, FOLLOWER);

        let res = schema.execute_as_system_admin(STATUS_QUERY).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let node = &data["nodeStatusList"]["edges"][0]["node"];
        assert_eq!(node["timeSync"], json!(null));
        assert_ne!(node["cpuUsage"], json!(null));
        assert_ne!(node["ping"], json!(null));
    }

    #[tokio::test(start_paused = true)]
    async fn status_timeout_is_null() {
        let manager = manager_hostname();
        let mut stub = StubAgentManager::new();
        stub.stalled.insert(manager.clone());
        let (schema, stub) = schema_with(stub).await;
        insert_active_node(&schema.store(), "manager", 1, &manager);

        let res = schema.execute_as_system_admin(STATUS_QUERY).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let node = &data["nodeStatusList"]["edges"][0]["node"];
        assert_eq!(node["timeSync"], json!(null));
        assert_eq!(node["cpuUsage"], json!(20.0));
        assert_eq!(stub.calls(), vec![Call::Status(manager)]);
    }

    #[tokio::test]
    async fn status_requests_are_concurrent() {
        let manager = manager_hostname();
        let mut stub = StubAgentManager::new();
        stub.barrier = Some(Arc::new(Barrier::new(3)));
        stub.statuses.insert(
            manager.clone(),
            Ok(TimeSyncStatus {
                enabled: false,
                synchronized: false,
                server: None,
                offset_micros: None,
            }),
        );
        let (schema, _) = schema_with(stub).await;
        insert_active_node(&schema.store(), "manager", 1, &manager);

        let res = tokio::time::timeout(
            Duration::from_secs(10),
            schema.execute_as_system_admin(STATUS_QUERY),
        )
        .await
        .expect("the three requests run concurrently");
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        let data = res.data.into_json().unwrap();
        let node = &data["nodeStatusList"]["edges"][0]["node"];
        assert_eq!(node["timeSync"]["enabled"], json!(false));
        assert_ne!(node["cpuUsage"], json!(null));
        assert_ne!(node["ping"], json!(null));
    }

    #[tokio::test]
    async fn query_returns_manager_node_and_servers() {
        let manager = manager_hostname();
        let (schema, stub) = schema_with(StubAgentManager::new()).await;
        insert_active_node(&schema.store(), "follower", 1, FOLLOWER);
        let id = insert_active_node(&schema.store(), "manager", 1, &manager);
        let expected = json!({
            "centralManagerTimeSources": {
                "nodeId": id.to_string(),
                "servers": SERVERS,
            }
        });

        let res = schema.execute_as_system_admin(GET_QUERY).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(res.data.into_json().unwrap(), expected);

        for role in [Role::SecurityAdministrator, Role::SecurityMonitor] {
            let res = schema
                .execute_as_scoped_user(GET_QUERY, role, Some(vec![2]))
                .await;
            assert!(res.errors.is_empty(), "{role:?}: {:?}", res.errors);
            assert_eq!(res.data.into_json().unwrap(), expected);
        }

        assert_eq!(stub.calls(), vec![Call::Get(manager); 3]);
    }

    /// Returns the OS hostname and a profile hostname that adds a domain to it.
    fn manager_hostname_with_domain(domain: &str) -> (String, String) {
        let os = manager_hostname();
        let hostname = format!("{os}.{domain}");
        (os, hostname)
    }

    #[tokio::test]
    async fn query_recognizes_manager_by_profile_hostname_with_domain() {
        let (os, hostname) = manager_hostname_with_domain("example.com");
        let (schema, stub) = schema_with(StubAgentManager::new()).await;
        insert_active_node(&schema.store(), "follower", 1, FOLLOWER);
        let id = insert_active_node(&schema.store(), "manager", 1, &hostname);

        let res = schema.execute_as_system_admin(GET_QUERY).await;
        if os.contains('.') {
            // A dotted OS hostname is compared exactly.
            assert_eq!(error_message(&res), MANAGER_NOT_REGISTERED);
            assert_eq!(stub.calls(), vec![]);
        } else {
            assert!(res.errors.is_empty(), "{:?}", res.errors);
            assert_eq!(
                res.data.into_json().unwrap(),
                json!({
                    "centralManagerTimeSources": {
                        "nodeId": id.to_string(),
                        "servers": SERVERS,
                    }
                })
            );
            assert_eq!(stub.calls(), vec![Call::Get(hostname)]);
        }
    }

    #[tokio::test]
    async fn mutation_recognizes_manager_by_profile_hostname_with_domain() {
        let (os, hostname) = manager_hostname_with_domain("example.com");
        let (schema, stub) = schema_with(StubAgentManager::new()).await;
        insert_active_node(&schema.store(), "follower", 1, FOLLOWER);
        insert_active_node(&schema.store(), "manager", 1, &hostname);

        let res = schema.execute_as_system_admin(SET_MUTATION).await;
        if os.contains('.') {
            // A dotted OS hostname is compared exactly.
            assert_eq!(error_message(&res), MANAGER_NOT_REGISTERED);
            assert_eq!(stub.calls(), vec![]);
        } else {
            assert!(res.errors.is_empty(), "{:?}", res.errors);
            assert_eq!(
                res.data.into_json().unwrap(),
                json!({"setCentralManagerTimeSources": SERVERS})
            );
            assert_eq!(stub.calls(), vec![Call::Set(hostname, servers())]);
        }
    }

    #[tokio::test]
    async fn first_of_several_matching_nodes_is_the_manager() {
        let (os, first) = manager_hostname_with_domain("a.example");
        let (_, second) = manager_hostname_with_domain("b.example");
        let (schema, stub) = schema_with(StubAgentManager::new()).await;
        let id = insert_active_node(&schema.store(), "manager-a", 1, &first);
        insert_active_node(&schema.store(), "manager-b", 1, &second);

        let res = schema.execute_as_system_admin(GET_QUERY).await;
        if os.contains('.') {
            // A dotted OS hostname is compared exactly.
            assert_eq!(error_message(&res), MANAGER_NOT_REGISTERED);
            assert_eq!(stub.calls(), vec![]);
        } else {
            assert!(res.errors.is_empty(), "{:?}", res.errors);
            assert_eq!(
                res.data.into_json().unwrap()["centralManagerTimeSources"]["nodeId"],
                json!(id.to_string())
            );
            assert_eq!(stub.calls(), vec![Call::Get(first)]);
        }
    }

    #[tokio::test]
    async fn query_without_manager_node_fails() {
        let (schema, stub) = schema_with(StubAgentManager::new()).await;
        insert_active_node(&schema.store(), "follower", 1, FOLLOWER);
        let res = schema.execute_as_system_admin(GET_QUERY).await;
        assert_eq!(error_message(&res), MANAGER_NOT_REGISTERED);
        assert_eq!(stub.calls(), vec![]);

        let (schema, stub) = schema_with(StubAgentManager::new()).await;
        put_draft_only_node(&schema.store(), "manager", &manager_hostname());
        let res = schema.execute_as_system_admin(GET_QUERY).await;
        assert_eq!(error_message(&res), MANAGER_NOT_REGISTERED);
        assert_eq!(stub.calls(), vec![]);
    }

    #[tokio::test]
    async fn query_passes_agent_error_through() {
        let manager = manager_hostname();
        let message = format!("no roxyd is connected for host {manager}");
        let mut stub = StubAgentManager::new();
        stub.time_sources = Err(message.clone());
        let (schema, _) = schema_with(stub).await;
        insert_active_node(&schema.store(), "manager", 1, &manager);

        let res = schema.execute_as_system_admin(GET_QUERY).await;
        assert_eq!(error_message(&res), message);
    }

    #[tokio::test]
    async fn mutation_sends_servers_to_manager() {
        let manager = manager_hostname();
        let (schema, stub) = schema_with(StubAgentManager::new()).await;
        insert_active_node(&schema.store(), "follower", 1, FOLLOWER);
        insert_active_node(&schema.store(), "manager", 1, &manager);

        let res = schema.execute_as_system_admin(SET_MUTATION).await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({"setCentralManagerTimeSources": SERVERS})
        );

        let res = schema
            .execute_as_system_admin(r"mutation { setCentralManagerTimeSources(servers: []) }")
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.into_json().unwrap(),
            json!({"setCentralManagerTimeSources": []})
        );

        assert_eq!(
            stub.calls(),
            vec![
                Call::Set(manager.clone(), servers()),
                Call::Set(manager, vec![]),
            ]
        );
    }

    #[tokio::test]
    async fn mutation_passes_refusal_through() {
        let manager = manager_hostname();
        let message = r#"entry 2: "a..b" is not a valid hostname"#;
        let mut stub = StubAgentManager::new();
        stub.set_time_sources = Err(message.to_string());
        let (schema, _) = schema_with(stub).await;
        insert_active_node(&schema.store(), "manager", 1, &manager);

        let res = schema.execute_as_system_admin(SET_MUTATION).await;
        assert_eq!(error_message(&res), message);
    }

    #[tokio::test]
    async fn mutation_is_system_administrator_only() {
        let manager = manager_hostname();
        let (schema, stub) = schema_with(StubAgentManager::new()).await;
        insert_active_node(&schema.store(), "manager", 1, &manager);

        for role in [
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            let res = schema
                .execute_with_guard(SET_MUTATION, RoleGuard::Role(role))
                .await;
            assert_eq!(error_message(&res), "Forbidden", "{role:?}");
        }
        assert_eq!(stub.calls(), vec![]);
    }

    #[tokio::test]
    async fn mutation_without_manager_node_fails() {
        let (schema, stub) = schema_with(StubAgentManager::new()).await;
        insert_active_node(&schema.store(), "follower", 1, FOLLOWER);

        let res = schema.execute_as_system_admin(SET_MUTATION).await;
        assert_eq!(error_message(&res), MANAGER_NOT_REGISTERED);
        assert_eq!(stub.calls(), vec![]);
    }

    #[test]
    fn offset_is_converted_to_seconds() {
        let status = |offset_micros| TimeSyncStatus {
            enabled: true,
            synchronized: true,
            server: None,
            offset_micros,
        };
        assert_eq!(
            NodeTimeSync::from(status(Some(2_000_000))).offset,
            Some(2.0)
        );
        assert_eq!(
            NodeTimeSync::from(status(Some(-1))).offset,
            Some(-0.000_001)
        );
        assert_eq!(NodeTimeSync::from(status(None)).offset, None);
    }

    #[tokio::test]
    async fn other_nodes_do_not_delay_operations() {
        let manager = manager_hostname();
        let mut stub = StubAgentManager::new();
        stub.stalled.insert(FOLLOWER.to_string());
        let (schema, stub) = schema_with(stub).await;
        insert_active_node(&schema.store(), "follower", 1, FOLLOWER);
        insert_active_node(&schema.store(), "manager", 1, &manager);

        let res = tokio::time::timeout(
            Duration::from_secs(1),
            schema.execute_as_system_admin(GET_QUERY),
        )
        .await
        .expect("the query asks only the manager's Host Agent");
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        let res = tokio::time::timeout(
            Duration::from_secs(1),
            schema.execute_as_system_admin(SET_MUTATION),
        )
        .await
        .expect("the mutation asks only the manager's Host Agent");
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        assert_eq!(
            stub.calls(),
            vec![Call::Get(manager.clone()), Call::Set(manager, servers())]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn query_fails_after_deadline() {
        let manager = manager_hostname();
        let mut stub = StubAgentManager::new();
        stub.stalled.insert(manager.clone());
        let (schema, stub) = schema_with(stub).await;
        insert_active_node(&schema.store(), "manager", 1, &manager);

        let start = tokio::time::Instant::now();
        let res = schema.execute_as_system_admin(GET_QUERY).await;
        assert!(start.elapsed() >= TIME_SOURCES_TIMEOUT);
        assert_eq!(error_message(&res), MANAGER_TIMED_OUT);
        assert_eq!(stub.calls(), vec![Call::Get(manager)]);
    }

    #[tokio::test(start_paused = true)]
    async fn mutation_fails_after_deadline() {
        let manager = manager_hostname();
        let mut stub = StubAgentManager::new();
        stub.stalled.insert(manager.clone());
        let (schema, stub) = schema_with(stub).await;
        insert_active_node(&schema.store(), "manager", 1, &manager);

        let start = tokio::time::Instant::now();
        let res = schema
            .execute_as_system_admin(
                r#"mutation { setCentralManagerTimeSources(servers: ["192.0.2.10"]) }"#,
            )
            .await;
        assert!(start.elapsed() >= TIME_SOURCES_TIMEOUT);
        assert_eq!(error_message(&res), MANAGER_TIMED_OUT);
        assert_eq!(
            stub.calls(),
            vec![Call::Set(manager, vec!["192.0.2.10".to_string()])]
        );
    }
}
