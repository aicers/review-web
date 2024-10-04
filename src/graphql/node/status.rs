use std::time::Duration;

use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    Context, Object, Result,
};
use review_database::UniqueKey;
use roxy::ResourceUsage;

use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    matches_manager_hostname, NodeStatus, NodeStatusQuery, NodeStatusTotalCount,
};

#[Object]
impl NodeStatusQuery {
    /// A list of status of nodes.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node_status_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, NodeStatus, NodeStatusTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, NodeStatus, NodeStatusTotalCount, EmptyFields>> {
    let (node_list, has_previous, has_next) = {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.node_map();
        super::super::load_nodes(&map, after, before, first, last, None)?
    };

    let agent_manager = ctx.data::<BoxedAgentManager>()?;

    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, NodeStatusTotalCount);

    for node in node_list {
        let hostname = node
            .profile
            .as_ref()
            .map(|profile| profile.hostname.as_str())
            .unwrap_or_default();

        let is_manager = matches_manager_hostname(hostname);

        let (resource_usage, ping) =
            fetch_resource_usage_and_ping(agent_manager, hostname, is_manager).await;

        connection.edges.push(Edge::new(
            crate::graphql::encode_cursor(node.unique_key()),
            NodeStatus::new(node, &resource_usage, ping, is_manager),
        ));
    }
    Ok(connection)
}

// Returns the resource usage and ping time of the given hostname.
async fn fetch_resource_usage_and_ping(
    agent_manager: &BoxedAgentManager,
    hostname: &str,
    is_manager: bool,
) -> (Option<ResourceUsage>, Option<Duration>) {
    if is_manager {
        // Since this code is executed on the Manager server itself, we retrieve the resource
        // usage directly without making a remote call. The ping value is set to 0 without
        // performing an actual ping, because ping on the same machine should result in negligible
        // round-trip time (RTT).
        (
            Some(roxy::resource_usage().await),
            Some(Duration::from_secs(0)),
        )
    } else {
        (
            agent_manager.get_resource_usage(hostname).await.ok(),
            agent_manager.ping(hostname).await.ok(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use assert_json_diff::assert_json_include;
    use axum::async_trait;
    use roxy::ResourceUsage;
    use serde_json::json;

    use crate::graphql::{AgentManager, BoxedAgentManager, SamplingPolicy, TestSchema};

    struct MockAgentManager {
        pub online_apps_by_host_id: HashMap<String, Vec<(String, String)>>,
    }

    #[async_trait]
    impl AgentManager for MockAgentManager {
        async fn broadcast_internal_networks(
            &self,
            _networks: &[u8],
        ) -> Result<Vec<String>, anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }

        async fn broadcast_allow_networks(
            &self,
            _networks: &[u8],
        ) -> Result<Vec<String>, anyhow::Error> {
            unimplemented!()
        }

        async fn broadcast_block_networks(
            &self,
            _networks: &[u8],
        ) -> Result<Vec<String>, anyhow::Error> {
            unimplemented!()
        }

        async fn online_apps_by_host_id(
            &self,
        ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
            Ok(self.online_apps_by_host_id.clone())
        }

        async fn broadcast_crusher_sampling_policy(
            &self,
            _sampling_policies: &[SamplingPolicy],
        ) -> Result<(), anyhow::Error> {
            unimplemented!()
        }

        async fn get_config(
            &self,
            hostname: &str,
            _agent_id: &str,
        ) -> Result<review_protocol::types::Config, anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
        }

        async fn get_process_list(
            &self,
            _hostname: &str,
        ) -> Result<Vec<roxy::Process>, anyhow::Error> {
            unimplemented!()
        }

        async fn get_resource_usage(
            &self,
            _hostname: &str,
        ) -> Result<roxy::ResourceUsage, anyhow::Error> {
            Ok(ResourceUsage {
                cpu_usage: 20.0,
                total_memory: 1000,
                used_memory: 100,
                total_disk_space: 1000,
                used_disk_space: 100,
            })
        }

        async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            unimplemented!()
        }

        async fn ping(&self, _hostname: &str) -> Result<Duration, anyhow::Error> {
            Ok(Duration::from_micros(10))
        }

        async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            unimplemented!()
        }

        async fn update_config(&self, _agent_key: &str) -> Result<(), anyhow::Error> {
            Ok(())
        }
    }

    fn insert_apps(host: &str, apps: &[&str], map: &mut HashMap<String, Vec<(String, String)>>) {
        let entries = apps
            .iter()
            .map(|&app| (format!("{}@{}", app, host), app.to_string()))
            .collect();
        map.insert(host.to_string(), entries);
    }

    #[tokio::test]
    async fn test_node_status_list() {
        let mut online_apps_by_host_id = HashMap::new();

        let manager_hostname = roxy::hostname(); // Current machine's hostname is the Manager server's hostname.
        insert_apps(
            manager_hostname.as_str(),
            &["features"],
            &mut online_apps_by_host_id,
        );
        insert_apps(
            "analysis",
            &["models", "learner"],
            &mut online_apps_by_host_id,
        );

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
        });

        let schema = TestSchema::new_with(agent_manager, None).await;

        // check empty
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 0}}"#);

        // insert 2 nodes
        let mutation = format!(
            r#"
            mutation {{
                insertNode(
                    name: "node1",
                    customerId: 0,
                    description: "This node has the Manager.",
                    hostname: "{}",
                    agents: [
                        {{
                            key: "features@{}"
                            kind: PIGLET
                            status: ENABLED
                            draft: "my_val=1"
                        }}
                    ]
                    giganto: null
                )
            }}"#,
            manager_hostname, manager_hostname
        );
        let res = schema.execute(&mutation).await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    applyNode(id: "0") {
                        id
                        gigantoDraft
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{applyNode: {id: "0", gigantoDraft: null}}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "node2",
                        customerId: 0,
                        description: "This is the node for the Learner and the Models module.",
                        hostname: "analysis",
                        agents: [{
                            key: "learner@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                            draft: "my_val=2"
                        },
                        {
                            key: "models@analysis"
                            kind: HOG
                            status: ENABLED
                            draft: "my_val=2"
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "1"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    applyNode(id: "1") {
                        id
                        gigantoDraft
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{applyNode: {id: "1", gigantoDraft: null}}"#
        );

        // check node status list
        let res = schema
            .execute(
                r#"query {
                    nodeStatusList(first: 10) {
                        edges {
                            node {
                                name
                                nameDraft
                                profile {
                                    customerId
                                    description
                                    hostname
                                }
                                profileDraft {
                                    customerId
                                    description
                                    hostname
                                }
                                gigantoDraft
                                cpuUsage
                                totalMemory
                                usedMemory
                                totalDiskSpace
                                usedDiskSpace
                                ping
                                manager
                                agents {
                                    kind
                                    storedStatus
                                    config
                                    draft
                                }
                            }
                        }
                    }
                  }"#,
            )
            .await;

        assert_json_include!(
            actual: res.data.into_json().unwrap(),
            expected: json!({
                "nodeStatusList": {
                    "edges": [
                        {
                            "node": {
                                "name": "node1",
                                "nameDraft": "node1",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This node has the Manager.",
                                    "hostname": manager_hostname
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This node has the Manager.",
                                    "hostname": manager_hostname
                                },
                                "gigantoDraft": null,
                                "ping": 0.0,
                                "manager": true,
                                "agents": [
                                    {
                                        "kind": "PIGLET",
                                        "storedStatus": "ENABLED",
                                        "config": "my_val=1",
                                        "draft": "my_val=1",
                                    }
                                ]
                            }
                        },
                        {
                            "node": {
                                "name": "node2",
                                "nameDraft": "node2",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the node for the Learner and the Models module.",
                                    "hostname": "analysis"
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the node for the Learner and the Models module.",
                                    "hostname": "analysis"
                                },
                                "gigantoDraft": null,
                                "cpuUsage": 20.0,
                                "totalMemory": "1000",
                                "usedMemory": "100",
                                "totalDiskSpace": "1000",
                                "usedDiskSpace": "100",
                                "ping": 0.00001,
                                "manager": false,
                                "agents": [
                                    {
                                        "kind": "RECONVERGE",
                                        "storedStatus": "ENABLED",
                                        "config": "my_val=2",
                                        "draft": "my_val=2"
                                    },
                                    {
                                        "kind": "HOG",
                                        "storedStatus": "ENABLED",
                                        "config": "my_val=2",
                                        "draft": "my_val=2"
                                    }
                                ]
                            }
                        }
                    ]
                }
            })
        );
    }

    #[tokio::test]
    async fn check_node_status_list_ordering() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps("collect", &["features"], &mut online_apps_by_host_id);
        insert_apps(
            "analysis",
            &["models", "learner"],
            &mut online_apps_by_host_id,
        );

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
        });

        let schema = TestSchema::new_with(agent_manager, None).await;

        // Insert 5 nodes
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "test1",
                        customerId: 0,
                        description: "This node has the Learner and the Models.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "learner@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "models@analysis"
                            kind: HOG
                            status: ENABLED
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "test2",
                        customerId: 0,
                        description: "This node has the Learner and the Models.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "learner@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "models@analysis"
                            kind: HOG
                            status: ENABLED
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "1"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "test3",
                        customerId: 0,
                        description: "This node has the Learner and the Models.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "learner@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "models@analysis"
                            kind: HOG
                            status: ENABLED
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "2"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "test4",
                        customerId: 0,
                        description: "This node has the Learner and the Models.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "learner@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "modles@analysis"
                            kind: HOG
                            status: ENABLED
                        }]
                        giganto: null
                        )
                    }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "3"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "test5",
                        customerId: 0,
                        description: "This node has the Features.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "features@collect"
                            kind: PIGLET
                            status: ENABLED
                        }]
                        giganto: null
                    )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "4"}"#);

        let res = schema
            .execute(r#"{nodeStatusList(first:5){edges{node{name}}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test1"}}, {node: {name: "test2"}}, {node: {name: "test3"}}, {node: {name: "test4"}}, {node: {name: "test5"}}]}}"#
        );

        let res = schema
            .execute(r#"{nodeStatusList(last:5){edges{node{name}},pageInfo{endCursor}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test1"}}, {node: {name: "test2"}}, {node: {name: "test3"}}, {node: {name: "test4"}}, {node: {name: "test5"}}], pageInfo: {endCursor: "dGVzdDU="}}}"#
        );

        let res = schema
            .execute(r#"{nodeStatusList(last:3,before:"dGVzdDM="){edges{node{name}},pageInfo{startCursor}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test1"}}, {node: {name: "test2"}}], pageInfo: {startCursor: "dGVzdDE="}}}"#
        );

        let res = schema
            .execute(r#"{nodeStatusList(first:3,after:"dGVzdDM="){edges{node{name}},pageInfo{endCursor}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test4"}}, {node: {name: "test5"}}], pageInfo: {endCursor: "dGVzdDU="}}}"#
        );

        let res = schema
            .execute(r#"{nodeStatusList(last:2, after:"dGVzdDU="){edges{node{name}}}}"#)
            .await;
        assert!(res.is_err());

        let res = schema
            .execute(r#"{nodeStatusList(first:2, before:"dGVzdDU="){edges{node{name}}}}"#)
            .await;
        assert!(res.is_err());
    }
}
