use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Object, Result, SimpleObject, StringNumber,
    connection::{Connection, EmptyFields},
};
use chrono::{DateTime, Utc};
use review_database::{Iterable, event::Direction};
use tracing::warn;

use super::{BoxedAgentManager, Role, RoleGuard};
use crate::graphql::query_with_constraints;

#[derive(Default)]
pub(super) struct TorExitNodeQuery;

#[Object]
impl TorExitNodeQuery {
    /// A list of tor exit nodes.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn tor_exit_node_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, TorExitNode, TorExitNodeTotalCount, EmptyFields>>
    {
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }
}

#[derive(Default)]
pub(super) struct TorExitNodeMutation;

#[Object]
impl TorExitNodeMutation {
    /// Deletes all existing entries and adds new IP address(es), then sends the
    /// stored list to every connected Hog. A failed send does not fail the
    /// mutation; a Hog that missed it receives the list when it next connects.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_tor_exit_node_list(
        &self,
        ctx: &Context<'_>,
        ip_addresses: Vec<String>,
    ) -> Result<Vec<String>> {
        {
            let store = crate::graphql::get_store(ctx)?;
            let map = store.tor_exit_node_map();
            let updated_at = Utc::now();
            map.replace_all(
                ip_addresses
                    .iter()
                    .map(|ip_address| review_database::TorExitNode {
                        ip_address: ip_address.to_owned(),
                        updated_at,
                    }),
            )?;
        }

        // The table is already written, and a Hog that misses this push pulls
        // the list at its next setup, so a failed send is not the caller's
        // failure.
        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        if let Err(e) = agent_manager.broadcast_tor_exit_node_list().await {
            warn!("cannot broadcast the Tor exit node list: {e:#}");
        }
        Ok(ip_addresses)
    }
}

#[derive(SimpleObject)]
struct TorExitNode {
    ip_address: String,
    updated_at: DateTime<Utc>,
}

impl From<review_database::TorExitNode> for TorExitNode {
    fn from(input: review_database::TorExitNode) -> Self {
        Self {
            ip_address: input.ip_address,
            updated_at: input.updated_at,
        }
    }
}

struct TorExitNodeTotalCount;

#[Object]
impl TorExitNodeTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.tor_exit_node_map();
        let count = map.iter(Direction::Forward, None).count();
        Ok(StringNumber(count))
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, TorExitNode, TorExitNodeTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx)?;
    let map = store.tor_exit_node_map();

    super::load_edges(&map, after, before, first, last, TorExitNodeTotalCount)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, HashMap},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;

    use crate::graphql::{
        AgentManager, BoxedAgentManager, SamplingPolicy, TestSchema,
        customer::NetworksTargetAgentLookupKeysPair,
    };

    const TOR_EXIT_NODE_LIST_QUERY: &str =
        r"query{torExitNodeList(first:10){edges{node{ipAddress}}}}";

    /// An `AgentManager` that counts `broadcast_tor_exit_node_list` calls and
    /// answers each one with an error when `fail` is set.
    struct BroadcastAgentManager {
        broadcasts: Arc<AtomicUsize>,
        fail: bool,
    }

    impl BroadcastAgentManager {
        fn boxed(fail: bool) -> (BoxedAgentManager, Arc<AtomicUsize>) {
            let broadcasts = Arc::new(AtomicUsize::new(0));
            let manager = Self {
                broadcasts: Arc::clone(&broadcasts),
                fail,
            };
            (Box::new(manager), broadcasts)
        }
    }

    #[async_trait]
    impl AgentManager for BroadcastAgentManager {
        async fn broadcast_tor_exit_node_list(&self) -> Result<(), anyhow::Error> {
            self.broadcasts.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                anyhow::bail!("no Hog accepted the list");
            }
            Ok(())
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
        ) -> Result<review_protocol::types::ResourceUsage, anyhow::Error> {
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
            anyhow::bail!("not expected to be called")
        }
    }

    #[tokio::test]
    async fn update_broadcasts_the_stored_list_once() {
        let (agent_manager, broadcasts) = BroadcastAgentManager::boxed(false);
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation{updateTorExitNodeList(ipAddresses:["192.168.1.1"])}"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{updateTorExitNodeList: ["192.168.1.1"]}"#
        );
        assert_eq!(broadcasts.load(Ordering::SeqCst), 1);

        let res = schema
            .execute_as_system_admin(TOR_EXIT_NODE_LIST_QUERY)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{torExitNodeList: {edges: [{node: {ipAddress: "192.168.1.1"}}]}}"#
        );
    }

    #[tokio::test]
    async fn update_succeeds_when_broadcast_fails() {
        let (agent_manager, broadcasts) = BroadcastAgentManager::boxed(true);
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation{updateTorExitNodeList(ipAddresses:["192.168.1.1","192.168.1.2"])}"#,
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{updateTorExitNodeList: ["192.168.1.1", "192.168.1.2"]}"#
        );
        assert_eq!(broadcasts.load(Ordering::SeqCst), 1);

        let res = schema
            .execute_as_system_admin(TOR_EXIT_NODE_LIST_QUERY)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{torExitNodeList: {edges: [{node: {ipAddress: "192.168.1.1"}}, {node: {ipAddress: "192.168.1.2"}}]}}"#
        );
    }

    #[tokio::test]
    async fn test_query_and_mutation() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute_as_system_admin(r"query{torExitNodeList(first:10){edges{node{ipAddress}}}}")
            .await;
        assert_eq!(res.data.to_string(), r"{torExitNodeList: {edges: []}}");

        let res = schema
            .execute_as_system_admin(
                r#"mutation{updateTorExitNodeList(ipAddresses:["192.168.1.1"])}"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{updateTorExitNodeList: ["192.168.1.1"]}"#
        );

        let res = schema
            .execute_as_system_admin(r"query{torExitNodeList(first:10){edges{node{ipAddress}}}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{torExitNodeList: {edges: [{node: {ipAddress: "192.168.1.1"}}]}}"#
        );

        let res = schema
            .execute_as_system_admin(
                r#"mutation{updateTorExitNodeList(ipAddresses:["192.168.1.2"])}"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{updateTorExitNodeList: ["192.168.1.2"]}"#
        );

        let res = schema
            .execute_as_system_admin(r"query{torExitNodeList(first:10){edges{node{ipAddress}}}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{torExitNodeList: {edges: [{node: {ipAddress: "192.168.1.2"}}]}}"#
        );
    }
}
