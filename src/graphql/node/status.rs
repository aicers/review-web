use std::collections::{HashMap, HashSet};

use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    Context, Object, Result,
};
use review_database::UniqueKey;
use roxy::ResourceUsage;

use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    ModuleName, NodeStatus, NodeStatusQuery, NodeStatusTotalCount,
};

#[Object]
impl NodeStatusQuery {
    /// A list of status of all the nodes.
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

#[allow(clippy::too_many_lines)]
async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, NodeStatus, NodeStatusTotalCount, EmptyFields>> {
    let agents = ctx.data::<BoxedAgentManager>()?;
    let apps = agents.online_apps_by_host_id().await?;
    let mut usages: HashMap<String, ResourceUsage> = HashMap::new();
    let mut ping: HashMap<String, i64> = HashMap::new();
    for hostname in apps.keys() {
        if let Ok(usage) = agents.get_resource_usage(hostname).await {
            usages.insert(
                hostname.clone(),
                ResourceUsage {
                    cpu_usage: usage.cpu_usage,
                    total_memory: usage.total_memory,
                    used_memory: usage.used_memory,
                    total_disk_space: usage.total_disk_space,
                    used_disk_space: usage.used_disk_space,
                },
            );
        }
        if let Ok(rtt) = agents.ping(hostname).await {
            let clamped_micros = i64::try_from(std::cmp::min(rtt.as_micros(), i64::MAX as u128))
                .expect("within i64 range");
            ping.insert(hostname.clone(), clamped_micros);
        }
    }

    let review_usage = roxy::resource_usage().await;
    let review_hostname = roxy::hostname();

    let store = crate::graphql::get_store(ctx).await?;
    let (node_list, has_previous, has_next) = {
        let map = store.node_map();
        super::super::load_nodes(&map, after, before, first, last, None)?
    };

    let mut connection =
        Connection::with_additional_fields(has_previous, has_next, NodeStatusTotalCount);

    for ev in node_list {
        let (
            review,
            piglet,
            reconverge,
            hog,
            cpu_usage,
            total_memory,
            used_memory,
            total_disk_space,
            used_disk_space,
            ping,
            piglet_config,
            hog_config,
        ) = match ev.profile.as_ref().map(|profile| &profile.hostname) {
            Some(hostname) => {
                let matches_review_host =
                    !review_hostname.is_empty() && &review_hostname == hostname;

                // modules
                let (review, piglet, reconverge, hog) = if let Some(modules) = apps.get(hostname) {
                    let module_names = modules
                        .iter()
                        .map(|(_, m)| m.as_str())
                        .collect::<HashSet<&str>>();
                    (
                        Some(
                            matches_review_host
                                || module_names.contains(ModuleName::Review.as_ref()),
                        ),
                        Some(module_names.contains(ModuleName::Piglet.as_ref())),
                        Some(module_names.contains(ModuleName::Reconverge.as_ref())),
                        Some(module_names.contains(ModuleName::Hog.as_ref())),
                    )
                // only review is running
                } else if matches_review_host {
                    (Some(true), None, None, None)
                } else {
                    (None, None, None, None)
                };

                // configs
                let piglet_config = if let Some(true) = piglet {
                    agents
                        .get_config(hostname, ModuleName::Piglet.as_ref())
                        .await
                        .ok()
                        .and_then(|cfg| match cfg {
                            review_protocol::types::Config::Piglet(piglet_config) => {
                                Some(piglet_config.into())
                            }
                            _ => None,
                        })
                } else {
                    None
                };
                let hog_config = if let Some(true) = hog {
                    agents
                        .get_config(hostname, ModuleName::Hog.as_ref())
                        .await
                        .ok()
                        .and_then(|cfg| match cfg {
                            review_protocol::types::Config::Hog(hog_config) => {
                                Some(hog_config.into())
                            }
                            _ => None,
                        })
                } else {
                    None
                };

                // usages
                let (cpu_usage, total_memory, used_memory, total_disk_space, used_disk_space) =
                    if matches_review_host {
                        (
                            Some(review_usage.cpu_usage),
                            Some(review_usage.total_memory),
                            Some(review_usage.used_memory),
                            Some(review_usage.total_disk_space),
                            Some(review_usage.used_disk_space),
                        )
                    } else if let Some(usage) = usages.get(hostname) {
                        (
                            Some(usage.cpu_usage),
                            Some(usage.total_memory),
                            Some(usage.used_memory),
                            Some(usage.total_disk_space),
                            Some(usage.used_disk_space),
                        )
                    } else {
                        (None, None, None, None, None)
                    };

                // ping
                let ping = if matches_review_host {
                    None
                } else {
                    ping.get(hostname).copied()
                };

                (
                    review,
                    piglet,
                    reconverge,
                    hog,
                    cpu_usage,
                    total_memory,
                    used_memory,
                    total_disk_space,
                    used_disk_space,
                    ping,
                    piglet_config,
                    hog_config,
                )
            }
            None => (
                None, None, None, None, None, None, None, None, None, None, None, None,
            ),
        };
        connection.edges.push(Edge::new(
            crate::graphql::encode_cursor(&ev.unique_key()),
            NodeStatus::new(
                ev.id,
                ev.name,
                cpu_usage,
                total_memory,
                used_memory,
                total_disk_space,
                used_disk_space,
                ping,
                review,
                piglet,
                piglet_config,
                reconverge,
                hog,
                hog_config,
            ),
        ));
    }
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use assert_json_diff::assert_json_eq;
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

        async fn set_config(
            &self,
            _hostname: &str,
            _agent_id: &str,
            _config: &review_protocol::types::Config,
        ) -> Result<(), anyhow::Error> {
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
        insert_apps("host1", &["review", "piglet"], &mut online_apps_by_host_id);
        insert_apps("host2", &["hog", "reconverge"], &mut online_apps_by_host_id);

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
        });

        let schema = TestSchema::new_with(agent_manager, None).await;

        // check empty
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 0}}"#);

        // insert 2 nodes
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "node1",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "host1",
                        agents: [{
                            key: "reconverge@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "piglet@collect"
                            kind: PIGLET
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
                    applyNode(id: "0") {
                        id
                        successModules
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{applyNode: {id: "0", successModules: []}}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "node2",
                        customerId: 0,
                        description: "This is the reconverge, hog node.",
                        hostname: "host2",
                        agents: [{
                            key: "reconverge@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "piglet@collect"
                            kind: PIGLET
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
                    applyNode(id: "1") {
                        id
                        successModules
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{applyNode: {id: "1", successModules: []}}"#
        );

        // check node status list
        let res = schema
            .execute(
                r#"query {
                    nodeStatusList(first: 10) {
                      edges {
                        node {
                            name
                            cpuUsage
                            totalMemory
                            usedMemory
                            totalDiskSpace
                            usedDiskSpace
                            ping
                            review
                            piglet
                            pigletConfig {
                                gigantoIp
                                gigantoPort
                            }
                            reconverge
                            hog
                            hogConfig {
                                gigantoIp
                                gigantoPort
                            }
                        }
                      }
                    }
                  }"#,
            )
            .await;
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeStatusList": {
                    "edges": [
                        {
                            "node": {
                                "name": "node1",
                                "cpuUsage": 20.0,
                                "totalMemory": "1000",
                                "usedMemory": "100",
                                "totalDiskSpace": "1000",
                                "usedDiskSpace": "100",
                                "ping": "10",
                                "review": true,
                                "piglet": true,
                                "pigletConfig": null,
                                "reconverge": false,
                                "hog": false,
                                "hogConfig": null,
                            }
                        },
                        {
                            "node": {
                                "name": "node2",
                                "cpuUsage": 20.0,
                                "totalMemory": "1000",
                                "usedMemory": "100",
                                "totalDiskSpace": "1000",
                                "usedDiskSpace": "100",
                                "ping": "10",
                                "review": false,
                                "piglet": false,
                                "pigletConfig": null,
                                "reconverge": true,
                                "hog": true,
                                "hogConfig": null,
                            }
                        }
                    ]
                }
            })
        );
    }

    #[tokio::test]
    async fn check_node_status_list_ordering() {
        let schema = TestSchema::new().await;

        // Insert 5 nodes
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "test1",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "reconverge@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "piglet@collect"
                            kind: PIGLET
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
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "reconverge@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "piglet@collect"
                            kind: PIGLET
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
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "reconverge@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "piglet@collect"
                            kind: PIGLET
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
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "reconverge@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "piglet@collect"
                            kind: PIGLET
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
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "reconverge@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                        },
                        {
                            key: "piglet@collect"
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
