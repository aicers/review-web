//! The networks each customer owns, keyed by customer ID.
//!
//! The customer networks table holds a copy of every customer's owned networks
//! as the writer last sent them, and is the source of the internal network list
//! hog receives. It keeps no other customer data, so nothing here requires a
//! row in the `customers` table.

use std::collections::HashSet;

use async_graphql::{
    Context, ErrorExtensions, InputObject, Object, Result, StringNumber, types::ID,
};
use chrono::{DateTime, Utc};
use review_database::{self as database, ReplaceOutcome, Store};
use tracing::{error, info};

use super::customer::{
    HostNetworkGroup, HostNetworkGroupInput, NetworkType, NetworksTargetAgentLookupKeysPair,
    send_agent_specific_customer_networks,
};
use super::customer_access::check_customer_membership;
use super::node::SEMI_SUPERVISED_AGENT;
use super::{Role, RoleGuard, agent_lookup_keys_by_customer_id};
use crate::{error_with_username, info_with_username};

/// The most networks one customer may own.
const MAX_NETWORKS_PER_CUSTOMER: usize = 256;
/// The most hosts, networks and ranges one network may hold, together.
const MAX_ENTRIES_PER_NETWORK: usize = 1024;

#[derive(Default)]
pub(super) struct CustomerNetworkQuery;

#[Object]
impl CustomerNetworkQuery {
    /// The networks the customer owns, or null if none were stored for it.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn customer_networks(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
    ) -> Result<Option<OwnedNetworkSet>> {
        check_customer_membership(ctx, &customer_id)?;
        let customer_id = parse_customer_id(&customer_id)?;
        let store = crate::graphql::get_store(ctx)?;
        Ok(store
            .customer_networks_map()
            .get(customer_id)?
            .map(|inner| OwnedNetworkSet { customer_id, inner }))
    }
}

#[derive(Default)]
pub(super) struct CustomerNetworkMutation;

#[Object]
impl CustomerNetworkMutation {
    /// Replaces the networks the customer owns with `networks`, returning the
    /// stored revision.
    ///
    /// `networks` is the customer's full set; an empty list means it owns
    /// none. A `revision` lower than the stored one is refused with the error
    /// code `STALE_REVISION`, whose `storedRevision` extension holds the stored
    /// revision.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn replace_customer_networks(
        &self,
        ctx: &Context<'_>,
        customer_id: ID,
        revision: StringNumber<u64>,
        networks: Vec<OwnedNetworkInput>,
    ) -> Result<StringNumber<u64>> {
        check_customer_membership(ctx, &customer_id)?;
        let customer_id = parse_customer_id(&customer_id)?;
        let StringNumber(revision) = revision;
        let networks = validate_networks(networks)?;

        let set = database::OwnedNetworkSet {
            revision,
            networks,
            updated_at: Utc::now(),
        };
        let merged = set.merged_group();
        let push = {
            let store = crate::graphql::get_store(ctx)?;
            let outcome =
                store
                    .customer_networks_map()
                    .replace(customer_id, revision, set.networks)?;
            let previous = match outcome {
                ReplaceOutcome::Written { previous } => previous,
                ReplaceOutcome::Stale { stored } => return Err(stale_revision(stored)),
            };
            info_with_username!(
                ctx,
                "Networks of customer {customer_id} have been replaced at revision {revision}"
            );
            // hog restarts its workers on every push, so a write that leaves
            // the merged group as it was is not pushed.
            if previous.is_some_and(|previous| previous.merged_group() == merged) {
                None
            } else {
                hog_push(ctx, &store, customer_id, merged)
            }
        };
        if let Some(push) = push {
            send_push(ctx, customer_id, push).await;
        }

        Ok(StringNumber(revision))
    }

    /// Removes the networks the customer owns, returning whether any were
    /// stored.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_customer_networks(&self, ctx: &Context<'_>, customer_id: ID) -> Result<bool> {
        check_customer_membership(ctx, &customer_id)?;
        let customer_id = parse_customer_id(&customer_id)?;

        let push = {
            let store = crate::graphql::get_store(ctx)?;
            if !store.customer_networks_map().remove(customer_id)? {
                return Ok(false);
            }
            info_with_username!(ctx, "Networks of customer {customer_id} have been removed");
            hog_push(
                ctx,
                &store,
                customer_id,
                database::HostNetworkGroup::default(),
            )
        };
        if let Some(push) = push {
            send_push(ctx, customer_id, push).await;
        }

        Ok(true)
    }
}

/// The networks a customer owns.
struct OwnedNetworkSet {
    customer_id: u32,
    inner: database::OwnedNetworkSet,
}

#[Object]
impl OwnedNetworkSet {
    /// The ID of the customer.
    async fn customer_id(&self) -> ID {
        ID(self.customer_id.to_string())
    }

    /// The writer's revision of this set.
    async fn revision(&self) -> StringNumber<u64> {
        StringNumber(self.inner.revision)
    }

    /// The networks the customer owns.
    async fn networks(&self) -> Vec<OwnedNetwork<'_>> {
        self.inner
            .networks
            .iter()
            .map(|inner| OwnedNetwork { inner })
            .collect()
    }

    /// The time when this set was last written.
    async fn updated_at(&self) -> DateTime<Utc> {
        self.inner.updated_at
    }
}

/// A network a customer owns.
struct OwnedNetwork<'a> {
    inner: &'a database::OwnedNetwork,
}

#[Object]
impl OwnedNetwork<'_> {
    /// The name of the network, unique within its customer's set.
    async fn name(&self) -> &str {
        &self.inner.name
    }

    /// The type of the network.
    async fn network_type(&self) -> NetworkType {
        self.inner.network_type.into()
    }

    /// The hosts, networks and ranges of the network.
    async fn network_group(&self) -> HostNetworkGroup<'_> {
        (&self.inner.group).into()
    }
}

#[derive(InputObject)]
struct OwnedNetworkInput {
    name: String,
    network_type: NetworkType,
    network_group: HostNetworkGroupInput,
}

fn parse_customer_id(customer_id: &ID) -> Result<u32> {
    customer_id
        .as_str()
        .parse::<u32>()
        .map_err(|_| "invalid customer ID".into())
}

/// Checks the whole of `networks` and converts it, so that one invalid network
/// rejects the call before anything is written.
///
/// # Errors
///
/// Returns an error if there are too many networks, a name is empty or
/// repeated, or a network group is empty, too large, unparsable, or holds a
/// range that ends before it starts or mixes address families.
fn validate_networks(networks: Vec<OwnedNetworkInput>) -> Result<Vec<database::OwnedNetwork>> {
    if networks.len() > MAX_NETWORKS_PER_CUSTOMER {
        return Err(format!(
            "too many networks: at most {MAX_NETWORKS_PER_CUSTOMER} are allowed per customer"
        )
        .into());
    }
    let mut names = HashSet::with_capacity(networks.len());
    for network in &networks {
        if network.name.trim().is_empty() {
            return Err("network name must not be empty".into());
        }
        if !names.insert(network.name.as_str()) {
            return Err(format!("duplicate network name {:?}", network.name).into());
        }
    }

    networks
        .into_iter()
        .map(|network| {
            let group = validate_group(&network.network_group)
                .map_err(|e| format!("network {:?}: {e}", network.name))?;
            Ok(database::OwnedNetwork {
                name: network.name,
                network_type: network.network_type.into(),
                group,
            })
        })
        .collect()
}

fn validate_group(input: &HostNetworkGroupInput) -> Result<database::HostNetworkGroup, String> {
    let entries = input.hosts.len() + input.networks.len() + input.ranges.len();
    if entries > MAX_ENTRIES_PER_NETWORK {
        return Err(format!(
            "too many entries: at most {MAX_ENTRIES_PER_NETWORK} hosts, networks and ranges are \
             allowed per network"
        ));
    }
    let group = database::HostNetworkGroup::try_from(input).map_err(|e| format!("{e:#}"))?;
    if group.hosts().is_empty() && group.networks().is_empty() && group.ip_ranges().is_empty() {
        return Err("network group must not be empty".to_string());
    }
    for range in group.ip_ranges() {
        let (start, end) = (range.start(), range.end());
        if start.is_ipv4() != end.is_ipv4() {
            return Err(format!(
                "range {start} - {end} mixes IPv4 and IPv6 addresses"
            ));
        }
        if start > end {
            return Err(format!("range {start} - {end} ends before it starts"));
        }
    }
    Ok(group)
}

fn stale_revision(stored: u64) -> async_graphql::Error {
    async_graphql::Error::new("stale revision").extend_with(|_, extensions| {
        extensions.set("code", "STALE_REVISION");
        extensions.set("storedRevision", stored.to_string());
    })
}

/// Returns the push of `group` to the hog agents of the customer's nodes, or
/// `None` if the customer has none.
///
/// The networks are already stored when this runs, so a failure to look up
/// the agents is logged rather than failing the call; hog pulls the list again
/// when it reconnects.
fn hog_push(
    ctx: &Context<'_>,
    store: &Store,
    customer_id: u32,
    group: database::HostNetworkGroup,
) -> Option<NetworksTargetAgentLookupKeysPair> {
    let agent_lookup_keys = match agent_lookup_keys_by_customer_id(store) {
        Ok(mut by_customer) => by_customer.remove(&customer_id)?,
        Err(e) => {
            error_with_username!(
                ctx,
                "Failed to find the agents of customer {customer_id} to send its networks to: \
                 {e:?}"
            );
            return None;
        }
    };
    let push =
        NetworksTargetAgentLookupKeysPair::new(group, agent_lookup_keys, SEMI_SUPERVISED_AGENT);
    if push.target_agent_lookup_keys().is_empty() {
        None
    } else {
        Some(push)
    }
}

/// Sends `push`, logging a failure rather than returning it: the networks are
/// already stored, and hog pulls the list again when it reconnects.
async fn send_push(ctx: &Context<'_>, customer_id: u32, push: NetworksTargetAgentLookupKeysPair) {
    if let Err(e) = send_agent_specific_customer_networks(ctx, &[push]).await {
        error_with_username!(
            ctx,
            "Failed to send the networks of customer {customer_id} to its agents: {e:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use chrono::Utc;
    use review_database::{
        Agent, AgentKind, AgentStatus, HostNetworkGroup, Lifecycle, Node, NodeProfile,
        OwnedNetwork, event::NetworkType,
    };
    use serde_json::{Value, json};

    use crate::graphql::{
        AgentManager, Role, SamplingPolicy, SharedAgentManager, TestSchema,
        customer::NetworksTargetAgentLookupKeysPair, get_customer_networks,
    };

    /// One `send_agent_specific_internal_networks` call: the target lookup
    /// keys and the group of each pair it was sent.
    type Push = Vec<(Vec<String>, HostNetworkGroup)>;

    /// An `AgentManager` that records every internal network push.
    struct RecordingAgentManager {
        pushes: Arc<Mutex<Vec<Push>>>,
    }

    impl RecordingAgentManager {
        fn shared() -> (SharedAgentManager, Arc<Mutex<Vec<Push>>>) {
            let pushes = Arc::new(Mutex::new(Vec::new()));
            let manager = Self {
                pushes: Arc::clone(&pushes),
            };
            (Arc::new(manager), pushes)
        }
    }

    #[async_trait]
    impl AgentManager for RecordingAgentManager {
        #[cfg(feature = "auth-mtls")]
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
            self.pushes
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
            Ok(networks
                .iter()
                .flat_map(|pair| pair.target_agent_lookup_keys().iter().cloned())
                .collect())
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

        async fn update_config(&self, _agent_lookup_key: &str) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }
    }

    fn recorded(pushes: &Arc<Mutex<Vec<Push>>>) -> Vec<Push> {
        pushes
            .lock()
            .expect("no test thread panics while holding the lock")
            .clone()
    }

    async fn recording_schema() -> (TestSchema, Arc<Mutex<Vec<Push>>>) {
        let (agent_manager, pushes) = RecordingAgentManager::shared();
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
    fn insert_node(schema: &TestSchema, customer_id: u32, hostname: &str) {
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

    fn group(hosts: &[&str], networks: &[&str], ranges: &[(&str, &str)]) -> HostNetworkGroup {
        HostNetworkGroup::new(
            hosts.iter().map(|h| h.parse().unwrap()).collect(),
            networks.iter().map(|n| n.parse().unwrap()).collect(),
            ranges
                .iter()
                .map(|(s, e)| s.parse().unwrap()..=e.parse().unwrap())
                .collect(),
        )
    }

    fn replace(customer_id: &str, revision: &str, networks: &str) -> String {
        format!(
            r#"mutation {{ replaceCustomerNetworks(customerId: "{customer_id}", revision: "{revision}", networks: [{networks}]) }}"#
        )
    }

    fn network(name: &str, network_type: &str, group: &str) -> String {
        format!(r#"{{ name: "{name}", networkType: {network_type}, networkGroup: {group} }}"#)
    }

    const QUERY_7: &str = r#"{ customerNetworks(customerId: "7") {
        customerId revision updatedAt
        networks { name networkType networkGroup { hosts networks ranges { start end } } }
    } }"#;
    const REMOVE_7: &str = r#"mutation { removeCustomerNetworks(customerId: "7") }"#;
    const OFFICE: &str = r#"{ hosts: [], networks: ["10.0.0.0/8"], ranges: [] }"#;

    fn data(res: async_graphql::Response) -> Value {
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        res.data.into_json().unwrap()
    }

    fn error_message(res: &async_graphql::Response) -> &str {
        assert_eq!(res.errors.len(), 1, "errors: {:?}", res.errors);
        &res.errors[0].message
    }

    #[tokio::test]
    async fn security_administrator_manages_own_customer_without_customers_row() {
        let schema = TestSchema::new().await;
        let as_admin = |query: String| {
            let schema = &schema;
            async move {
                schema
                    .execute_as_scoped_user(&query, Role::SecurityAdministrator, Some(vec![7]))
                    .await
            }
        };

        let res = as_admin(QUERY_7.to_string()).await;
        assert_eq!(data(res), json!({ "customerNetworks": null }));

        let networks = [
            network("office", "INTRANET", OFFICE),
            network(
                "edge",
                "GATEWAY",
                r#"{ hosts: ["192.168.0.1"], networks: [], ranges: [{ start: "192.168.1.1", end: "192.168.1.9" }] }"#,
            ),
            network(
                "partner",
                "EXTRANET",
                r#"{ hosts: ["2001:db8::1"], networks: ["2001:db8:1::/48"], ranges: [] }"#,
            ),
        ]
        .join(", ");
        let res = as_admin(replace("7", "3", &networks)).await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "3" }));

        let res = as_admin(QUERY_7.to_string()).await;
        let mut value = data(res);
        assert!(value["customerNetworks"]["updatedAt"].is_string());
        value["customerNetworks"]
            .as_object_mut()
            .unwrap()
            .remove("updatedAt");
        assert_eq!(
            value,
            json!({ "customerNetworks": {
                "customerId": "7",
                "revision": "3",
                "networks": [
                    { "name": "office", "networkType": "INTRANET", "networkGroup": {
                        "hosts": [], "networks": ["10.0.0.0/8"], "ranges": [] } },
                    { "name": "edge", "networkType": "GATEWAY", "networkGroup": {
                        "hosts": ["192.168.0.1"], "networks": [],
                        "ranges": [{ "start": "192.168.1.1", "end": "192.168.1.9" }] } },
                    { "name": "partner", "networkType": "EXTRANET", "networkGroup": {
                        "hosts": ["2001:db8::1"], "networks": ["2001:db8:1::/48"],
                        "ranges": [] } },
                ],
            } })
        );
        assert!(
            schema
                .store()
                .customer_map()
                .get_by_id(7)
                .unwrap()
                .is_none()
        );

        let res = as_admin(REMOVE_7.to_string()).await;
        assert_eq!(data(res), json!({ "removeCustomerNetworks": true }));
        let res = as_admin(REMOVE_7.to_string()).await;
        assert_eq!(data(res), json!({ "removeCustomerNetworks": false }));
        let res = as_admin(QUERY_7.to_string()).await;
        assert_eq!(data(res), json!({ "customerNetworks": null }));
    }

    #[tokio::test]
    async fn other_customer_is_forbidden() {
        let schema = TestSchema::new().await;
        schema
            .store()
            .customer_networks_map()
            .replace(8, 1, vec![])
            .unwrap();
        for query in [
            r#"{ customerNetworks(customerId: "8") { revision } }"#.to_string(),
            replace("8", "2", ""),
            r#"mutation { removeCustomerNetworks(customerId: "8") }"#.to_string(),
        ] {
            let res = schema
                .execute_as_scoped_user(&query, Role::SecurityAdministrator, Some(vec![7]))
                .await;
            assert_eq!(error_message(&res), "Forbidden", "query: {query}");
        }
        let stored = schema.store().customer_networks_map().get(8).unwrap();
        assert_eq!(stored.map(|set| set.revision), Some(1));
    }

    #[tokio::test]
    async fn monitor_and_manager_are_refused() {
        let schema = TestSchema::new().await;
        schema
            .store()
            .customer_networks_map()
            .replace(7, 1, vec![])
            .unwrap();
        for role in [Role::SecurityMonitor, Role::SecurityManager] {
            for query in [
                QUERY_7.to_string(),
                replace("7", "2", ""),
                REMOVE_7.to_string(),
            ] {
                let res = schema
                    .execute_as_scoped_user(&query, role, Some(vec![7]))
                    .await;
                assert_eq!(
                    error_message(&res),
                    "Forbidden",
                    "{role:?} was not refused: {query}"
                );
            }
        }
        let stored = schema.store().customer_networks_map().get(7).unwrap();
        assert_eq!(stored.map(|set| set.revision), Some(1));
    }

    #[tokio::test]
    async fn system_administrator_manages_any_customer() {
        let schema = TestSchema::new().await;
        for customer_id in ["0", "8", "4294967295"] {
            let res = schema
                .execute_as_scoped_user(
                    &replace(customer_id, "1", &network("office", "INTRANET", OFFICE)),
                    Role::SystemAdministrator,
                    None,
                )
                .await;
            assert_eq!(data(res), json!({ "replaceCustomerNetworks": "1" }));
            let res = schema
                .execute_as_scoped_user(
                    &format!(
                        r#"{{ customerNetworks(customerId: "{customer_id}") {{ customerId }} }}"#
                    ),
                    Role::SystemAdministrator,
                    None,
                )
                .await;
            assert_eq!(
                data(res),
                json!({ "customerNetworks": { "customerId": customer_id } })
            );
            let res = schema
                .execute_as_scoped_user(
                    &format!(
                        r#"mutation {{ removeCustomerNetworks(customerId: "{customer_id}") }}"#
                    ),
                    Role::SystemAdministrator,
                    None,
                )
                .await;
            assert_eq!(data(res), json!({ "removeCustomerNetworks": true }));
        }
    }

    #[tokio::test]
    async fn customer_id_must_be_a_u32() {
        let schema = TestSchema::new().await;
        for customer_id in ["x", "-1", "4294967296"] {
            for query in [
                format!(r#"{{ customerNetworks(customerId: "{customer_id}") {{ revision }} }}"#),
                replace(customer_id, "1", ""),
                format!(r#"mutation {{ removeCustomerNetworks(customerId: "{customer_id}") }}"#),
            ] {
                let res = schema.execute_as_system_admin(&query).await;
                assert_eq!(error_message(&res), "invalid customer ID", "query: {query}");
            }
        }
    }

    #[tokio::test]
    async fn stale_revision_is_refused_and_pushes_nothing() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7.example.com");

        let res = schema
            .execute_as_system_admin(&replace("7", "5", &network("office", "INTRANET", OFFICE)))
            .await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "5" }));
        assert_eq!(recorded(&pushes).len(), 1);
        let before = schema.store().customer_networks_map().get(7).unwrap();

        let other = network(
            "lab",
            "GATEWAY",
            r#"{ hosts: [], networks: ["172.16.0.0/12"], ranges: [] }"#,
        );
        let res = schema
            .execute_as_system_admin(&replace("7", "4", &other))
            .await;
        assert_eq!(error_message(&res), "stale revision");
        let error = serde_json::to_value(&res.errors[0]).unwrap();
        assert_eq!(
            error["extensions"],
            json!({ "code": "STALE_REVISION", "storedRevision": "5" })
        );
        assert_eq!(
            schema.store().customer_networks_map().get(7).unwrap(),
            before
        );
        assert_eq!(recorded(&pushes).len(), 1);

        let res = schema
            .execute_as_system_admin(&replace("7", "5", &other))
            .await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "5" }));
        assert_eq!(recorded(&pushes).len(), 2);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // one case table covering every validation rule
    async fn invalid_networks_are_refused_and_nothing_is_written() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7.example.com");

        let too_many_networks = (0..257)
            .map(|i| network(&format!("n{i}"), "INTRANET", OFFICE))
            .collect::<Vec<_>>()
            .join(", ");
        let too_many_hosts = (0..1025)
            .map(|i| format!(r#""10.0.{}.{}""#, i / 256, i % 256))
            .collect::<Vec<_>>()
            .join(", ");
        let cases = [
            (
                network("  ", "INTRANET", OFFICE),
                "network name must not be empty",
            ),
            (
                [
                    network("office", "INTRANET", OFFICE),
                    network("office", "EXTRANET", OFFICE),
                ]
                .join(", "),
                "duplicate network name \"office\"",
            ),
            (
                network(
                    "office",
                    "INTRANET",
                    r#"{ hosts: ["10.0.0.256"], networks: [], ranges: [] }"#,
                ),
                "network \"office\": invalid host address",
            ),
            (
                network(
                    "office",
                    "INTRANET",
                    r#"{ hosts: [], networks: ["10.0.0.0/33"], ranges: [] }"#,
                ),
                "network \"office\": invalid network address",
            ),
            (
                network(
                    "office",
                    "INTRANET",
                    r"{ hosts: [], networks: [], ranges: [] }",
                ),
                "network \"office\": network group must not be empty",
            ),
            (
                network(
                    "office",
                    "INTRANET",
                    r#"{ hosts: [], networks: [], ranges: [{ start: "10.0.0.9", end: "10.0.0.1" }] }"#,
                ),
                "network \"office\": range 10.0.0.9 - 10.0.0.1 ends before it starts",
            ),
            (
                network(
                    "office",
                    "INTRANET",
                    r#"{ hosts: [], networks: [], ranges: [{ start: "10.0.0.1", end: "::1" }] }"#,
                ),
                "network \"office\": range 10.0.0.1 - ::1 mixes IPv4 and IPv6 addresses",
            ),
            (
                too_many_networks,
                "too many networks: at most 256 are allowed per customer",
            ),
            (
                network(
                    "office",
                    "INTRANET",
                    &format!("{{ hosts: [{too_many_hosts}], networks: [], ranges: [] }}"),
                ),
                "network \"office\": too many entries: at most 1024 hosts, networks and ranges \
                 are allowed per network",
            ),
        ];
        for (networks, expected) in cases {
            let res = schema
                .execute_as_system_admin(&replace("7", "1", &networks))
                .await;
            let message = error_message(&res);
            assert!(
                message.starts_with(expected),
                "expected {expected:?}, got {message:?}"
            );
            assert!(
                schema
                    .store()
                    .customer_networks_map()
                    .get(7)
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(recorded(&pushes), Vec::<Push>::new());

        // The limits themselves are accepted.
        let max_networks = (0..256)
            .map(|i| network(&format!("n{i}"), "INTRANET", OFFICE))
            .collect::<Vec<_>>()
            .join(", ");
        let res = schema
            .execute_as_system_admin(&replace("7", "1", &max_networks))
            .await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "1" }));
        let max_hosts = (0..1024)
            .map(|i| format!(r#""10.0.{}.{}""#, i / 256, i % 256))
            .collect::<Vec<_>>()
            .join(", ");
        let res = schema
            .execute_as_system_admin(&replace(
                "7",
                "2",
                &network(
                    "office",
                    "INTRANET",
                    &format!("{{ hosts: [{max_hosts}], networks: [], ranges: [] }}"),
                ),
            ))
            .await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "2" }));
    }

    #[tokio::test]
    async fn empty_list_and_extreme_revisions_are_accepted() {
        let schema = TestSchema::new().await;
        let res = schema.execute_as_system_admin(&replace("7", "0", "")).await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "0" }));
        let stored = schema
            .store()
            .customer_networks_map()
            .get(7)
            .unwrap()
            .unwrap();
        assert_eq!((stored.revision, stored.networks.len()), (0, 0));

        let max = u64::MAX.to_string();
        let res = schema
            .execute_as_system_admin(&replace("7", &max, ""))
            .await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": max }));
        let res = schema
            .execute_as_system_admin(r#"{ customerNetworks(customerId: "7") { revision } }"#)
            .await;
        assert_eq!(
            data(res),
            json!({ "customerNetworks": { "revision": u64::MAX.to_string() } })
        );
    }

    #[tokio::test]
    async fn replace_pushes_merged_group_to_the_customers_hog_agents() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7a.example.com");
        insert_node(&schema, 7, "n7b.example.com");
        insert_node(&schema, 8, "n8.example.com");

        let networks = [
            network("office", "INTRANET", OFFICE),
            network(
                "edge",
                "GATEWAY",
                r#"{ hosts: ["192.168.0.1"], networks: [], ranges: [] }"#,
            ),
            network(
                "partner",
                "EXTRANET",
                r#"{ hosts: [], networks: ["2001:db8::/32"], ranges: [{ start: "172.16.0.1", end: "172.16.0.9" }] }"#,
            ),
        ]
        .join(", ");
        let res = schema
            .execute_as_scoped_user(
                &replace("7", "1", &networks),
                Role::SecurityAdministrator,
                Some(vec![7]),
            )
            .await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "1" }));

        let expected = group(
            &["192.168.0.1"],
            &["10.0.0.0/8", "2001:db8::/32"],
            &[("172.16.0.1", "172.16.0.9")],
        );
        assert_eq!(
            recorded(&pushes),
            vec![vec![(
                vec![
                    "001.hog.n7a.example.com".to_string(),
                    "001.hog.n7b.example.com".to_string(),
                ],
                expected,
            )]]
        );
    }

    #[tokio::test]
    async fn unchanged_merged_group_is_not_pushed() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7.example.com");

        let res = schema
            .execute_as_system_admin(&replace("7", "1", &network("office", "INTRANET", OFFICE)))
            .await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "1" }));
        assert_eq!(recorded(&pushes).len(), 1);

        // A resend of the same revision.
        let res = schema
            .execute_as_system_admin(&replace("7", "1", &network("office", "INTRANET", OFFICE)))
            .await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "1" }));
        // Only the name and type changed, and the group was split in two.
        let split = [
            network(
                "a",
                "EXTRANET",
                r#"{ hosts: [], networks: ["10.0.0.0/8"], ranges: [] }"#,
            ),
            network(
                "b",
                "GATEWAY",
                r#"{ hosts: [], networks: ["10.0.0.0/8"], ranges: [] }"#,
            ),
        ]
        .join(", ");
        let res = schema
            .execute_as_system_admin(&replace("7", "2", &split))
            .await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "2" }));
        let stored = schema
            .store()
            .customer_networks_map()
            .get(7)
            .unwrap()
            .unwrap();
        assert_eq!(stored.revision, 2);
        assert_eq!(stored.networks.len(), 2);
        assert_eq!(recorded(&pushes).len(), 1);

        // A change to the group is pushed.
        let res = schema.execute_as_system_admin(&replace("7", "3", "")).await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "3" }));
        assert_eq!(
            recorded(&pushes)[1],
            vec![(
                vec!["001.hog.n7.example.com".to_string()],
                HostNetworkGroup::default()
            )]
        );
    }

    #[tokio::test]
    async fn remove_pushes_an_empty_group() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 7, "n7.example.com");
        schema
            .store()
            .customer_networks_map()
            .replace(
                7,
                1,
                vec![OwnedNetwork {
                    name: "office".to_string(),
                    network_type: NetworkType::Intranet,
                    group: group(&[], &["10.0.0.0/8"], &[]),
                }],
            )
            .unwrap();

        let res = schema.execute_as_system_admin(REMOVE_7).await;
        assert_eq!(data(res), json!({ "removeCustomerNetworks": true }));
        assert_eq!(
            recorded(&pushes),
            vec![vec![(
                vec!["001.hog.n7.example.com".to_string()],
                HostNetworkGroup::default()
            )]]
        );

        // Nothing was removed, so nothing is pushed.
        let res = schema.execute_as_system_admin(REMOVE_7).await;
        assert_eq!(data(res), json!({ "removeCustomerNetworks": false }));
        assert_eq!(recorded(&pushes).len(), 1);
    }

    #[tokio::test]
    async fn customer_without_nodes_gets_no_push() {
        let (schema, pushes) = recording_schema().await;
        insert_node(&schema, 8, "n8.example.com");

        let res = schema
            .execute_as_system_admin(&replace("7", "1", &network("office", "INTRANET", OFFICE)))
            .await;
        assert_eq!(data(res), json!({ "replaceCustomerNetworks": "1" }));
        let res = schema.execute_as_system_admin(REMOVE_7).await;
        assert_eq!(data(res), json!({ "removeCustomerNetworks": true }));
        assert_eq!(recorded(&pushes), Vec::<Push>::new());
    }

    #[tokio::test]
    async fn update_customer_does_not_push() {
        let (schema, pushes) = recording_schema().await;
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c0", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(data(res), json!({ "insertCustomer": "0" }));
        insert_node(&schema, 0, "n0.example.com");

        let res = schema
            .execute_as_system_admin(
                r#"mutation { updateCustomer(id: "0", old: { networks: [] }, new: { networks: [{
                    name: "n", description: "", networkType: INTRANET,
                    networkGroup: { hosts: [], networks: ["10.0.0.0/8"], ranges: [] }
                }] }) }"#,
            )
            .await;
        assert_eq!(data(res), json!({ "updateCustomer": "0" }));
        assert_eq!(recorded(&pushes), Vec::<Push>::new());
    }

    #[tokio::test]
    async fn get_customer_networks_reads_the_customer_networks_table() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c0", description: "", networks: [{
                    name: "n", description: "", networkType: INTRANET,
                    networkGroup: { hosts: [], networks: ["10.0.0.0/8"], ranges: [] }
                }]) }"#,
            )
            .await;
        assert_eq!(data(res), json!({ "insertCustomer": "0" }));

        let store = schema.store();
        assert_eq!(
            get_customer_networks(&store, 0).unwrap(),
            HostNetworkGroup::default()
        );

        store
            .customer_networks_map()
            .replace(
                0,
                1,
                vec![
                    OwnedNetwork {
                        name: "office".to_string(),
                        network_type: NetworkType::Intranet,
                        group: group(&["192.168.0.1"], &[], &[]),
                    },
                    OwnedNetwork {
                        name: "partner".to_string(),
                        network_type: NetworkType::Extranet,
                        group: group(&[], &["172.16.0.0/12"], &[("10.1.0.1", "10.1.0.9")]),
                    },
                ],
            )
            .unwrap();
        assert_eq!(
            get_customer_networks(&store, 0).unwrap(),
            group(
                &["192.168.0.1"],
                &["172.16.0.0/12"],
                &[("10.1.0.1", "10.1.0.9")]
            )
        );
    }
}
