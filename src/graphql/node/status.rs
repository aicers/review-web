use std::time::Duration;

use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, Object, Result,
    connection::{Connection, Edge, EmptyFields},
};
use review_database::UniqueKey;
use roxy::ResourceUsage;
use tracing::info;

use super::{
    super::{BoxedAgentManager, Role, RoleGuard, customer_access},
    NodeStatus, NodeStatusQuery, NodeStatusTotalCount, matches_manager_hostname,
};
use crate::graphql::query_with_constraints;
use crate::info_with_username;

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
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, NodeStatus, NodeStatusTotalCount, EmptyFields>>
    {
        info_with_username!(ctx, "Node status lookup requested");
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

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, NodeStatus, NodeStatusTotalCount, EmptyFields>> {
    let users_customers = customer_access::users_customers(ctx)?;
    let users_customers = users_customers.as_deref();
    let (node_list, has_previous, has_next) = {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.node_map();
        // Apply customer filtering while collecting edges to keep pagination metadata consistent.
        let (node_list, has_previous, has_next) = super::super::process_load_edges_filtered(
            &map,
            after,
            before,
            first,
            last,
            None,
            |node| customer_access::can_access_node(users_customers, node),
        );
        let node_list = node_list
            .into_iter()
            .map(|res| res.map_err(|e| format!("{e}").into()))
            .collect::<Result<Vec<_>>>()?;
        (node_list, has_previous, has_next)
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

        let key = node.unique_key();
        connection.edges.push(Edge::new(
            OpaqueCursor(key.to_vec()),
            NodeStatus::new(node, resource_usage.as_ref(), ping, is_manager),
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
    use std::collections::HashMap;

    use assert_json_diff::assert_json_include;
    use serde_json::json;

    use super::super::test_support::{MockAgentManager, insert_active_node, insert_apps};
    use crate::graphql::{BoxedAgentManager, CustomerIds, Role, TestSchema};

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_node_status_list() {
        let mut online_apps_by_host_id = HashMap::new();

        let manager_hostname = roxy::hostname(); // Current machine's hostname is the Manager server's hostname.
        insert_apps(
            manager_hostname.as_str(),
            &["sensor"],
            &mut online_apps_by_host_id,
        );
        insert_apps(
            "analysis",
            &["semi-supervised", "unsupervised"],
            &mut online_apps_by_host_id,
        );

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // check empty
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "0"}}"#);

        // insert 2 nodes
        let mutation = format!(
            r#"
            mutation {{
                insertNode(
                    name: "node1",
                    customerId: 0,
                    description: "This node has the Manager.",
                    hostname: "{manager_hostname}",
                    agents: [
                        {{
                            key: "sensor"
                            kind: SENSOR
                            status: ENABLED
                            draft: "my_val=1"
                        }}
                    ],
                    externalServices: []
                )
            }}"#
        );
        let res = schema.execute_as_system_admin(&mutation).await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                format!(
                    r#"mutation {{
                        applyNode(
                            id: "0"
                            node: {{
                                name: "node1",
                                nameDraft: "node1",
                                profile: null,
                                profileDraft: {{
                                    customerId: 0,
                                    description: "This node has the Manager.",
                                    hostname: "{manager_hostname}"
                                }},
                                agents: [
                                    {{
                                        key: "sensor"
                                        kind: SENSOR
                                        status: ENABLED
                                        config: null
                                        draft: "my_val=1"
                                    }}],
                                externalServices: []
                            }}
                        )
                    }}"#
                )
                .as_str(),
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        let res = schema.execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "node2",
                        customerId: 0,
                        description: "This is the node for the Unsupervised and the Semi-supervised module.",
                        hostname: "analysis",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                            draft: "my_val=2"
                        },
                        {
                            key: "semi-supervised"
                            kind: SEMI_SUPERVISED
                            status: ENABLED
                            draft: "my_val=2"
                        }],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "1"}"#);

        let res = schema.execute_as_system_admin(
                r#"mutation {
                    applyNode(
                        id: "1"
                        node: {
                            name: "node2",
                            nameDraft: "node2",
                            profile: null,
                            profileDraft: {
                                customerId: 0,
                                description: "This is the node for the Unsupervised and the Semi-supervised module.",
                                hostname: "analysis"
                            },
                            agents: [{
                                key: "unsupervised"
                                kind: UNSUPERVISED
                                status: ENABLED
                                config: null
                                draft: "my_val=2"
                            },
                            {
                                key: "semi-supervised"
                                kind: SEMI_SUPERVISED
                                status: ENABLED
                                config: null
                                draft: "my_val=2"
                            }],
                            externalServices: []
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "1"}"#);

        // check node status list
        let res = schema
            .execute_as_system_admin(
                r"query {
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
                                externalServices {
                                    kind
                                    storedStatus
                                    draft
                                }
                            }
                        }
                    }
                  }",
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
                                "ping": 0.0,
                                "manager": true,
                                "agents": [
                                    {
                                        "kind": "SENSOR",
                                        "storedStatus": "ENABLED",
                                        "config": "my_val=1",
                                        "draft": "my_val=1",
                                    }
                                ],
                                "externalServices": [],
                            }
                        },
                        {
                            "node": {
                                "name": "node2",
                                "nameDraft": "node2",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the node for the Unsupervised and the Semi-supervised module.",
                                    "hostname": "analysis"
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the node for the Unsupervised and the Semi-supervised module.",
                                    "hostname": "analysis"
                                },
                                "cpuUsage": 20.0,
                                "totalMemory": "1000",
                                "usedMemory": "100",
                                "totalDiskSpace": "1000",
                                "usedDiskSpace": "100",
                                "ping": 0.00001,
                                "manager": false,
                                "agents": [
                                    {
                                        "kind": "UNSUPERVISED",
                                        "storedStatus": "ENABLED",
                                        "config": "my_val=2",
                                        "draft": "my_val=2"
                                    },
                                    {
                                        "kind": "SEMI_SUPERVISED",
                                        "storedStatus": "ENABLED",
                                        "config": "my_val=2",
                                        "draft": "my_val=2"
                                    }
                                ],
                                "externalServices": [],
                            }
                        }
                    ]
                }
            })
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn check_node_status_list_ordering() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps("collector", &["sensor1"], &mut online_apps_by_host_id);
        insert_apps(
            "analysis",
            &["semi-supervised", "unsupervised"],
            &mut online_apps_by_host_id,
        );

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // Insert 5 nodes
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "test1",
                        customerId: 0,
                        description: "This node has the Unsupervised and the Semi-supervised.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                        },
                        {
                            key: "semi-supervised"
                            kind: SEMI_SUPERVISED
                            status: ENABLED
                        }],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "test2",
                        customerId: 0,
                        description: "This node has the Unsupervised and the Semi-supervised.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                        },
                        {
                            key: "semi-supervised"
                            kind: SEMI_SUPERVISED
                            status: ENABLED
                        }],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), "null");

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "test3",
                        customerId: 0,
                        description: "This node has the Unsupervised and the Semi-supervised.",
                        hostname: "admin3.aice-security.com",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                        },
                        {
                            key: "semi-supervised"
                            kind: SEMI_SUPERVISED
                            status: ENABLED
                        }],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "1"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "test4",
                        customerId: 0,
                        description: "This node has the Unsupervised and the Semi-supervised.",
                        hostname: "admin4.aice-security.com",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                        },
                        {
                            key: "semi-supervised"
                            kind: SEMI_SUPERVISED
                            status: ENABLED
                        }],
                        externalServices: []
                        )
                    }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "2"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "test5",
                        customerId: 0,
                        description: "This node has the Sensor.",
                        hostname: "admin5.aice-security.com",
                        agents: [{
                            key: "sensor1@collector"
                            kind: SENSOR
                            status: ENABLED
                        }],
                        externalServices: []
                    )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "3"}"#);

        let res = schema
            .execute_as_system_admin(r"{nodeStatusList(first:5){edges{node{name}}}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test1"}}, {node: {name: "test3"}}, {node: {name: "test4"}}, {node: {name: "test5"}}]}}"#
        );

        let res = schema
            .execute_as_system_admin(
                r"{nodeStatusList(last:5){edges{node{name}},pageInfo{endCursor}}}",
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test1"}}, {node: {name: "test3"}}, {node: {name: "test4"}}, {node: {name: "test5"}}], pageInfo: {endCursor: "WzExNiwxMDEsMTE1LDExNiw1M10"}}}"#
        );

        let res = schema.execute_as_system_admin(r#"{nodeStatusList(last:3,before:"WzExNiwxMDEsMTE1LDExNiw1MV0"){edges{node{name}},pageInfo{startCursor}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test1"}}], pageInfo: {startCursor: "WzExNiwxMDEsMTE1LDExNiw0OV0"}}}"#
        );

        let res = schema.execute_as_system_admin(r#"{nodeStatusList(first:3,after:"WzExNiwxMDEsMTE1LDExNiw1MV0"){edges{node{name}},pageInfo{endCursor}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {edges: [{node: {name: "test4"}}, {node: {name: "test5"}}], pageInfo: {endCursor: "WzExNiwxMDEsMTE1LDExNiw1M10"}}}"#
        );

        let res = schema.execute_as_system_admin(r#"{nodeStatusList(last:2, after:"WzExNiwxMDEsMTE1LDExNiw1M10"){edges{node{name}}}}"#)
            .await;
        assert!(res.is_err());

        let res = schema.execute_as_system_admin(r#"{nodeStatusList(first:2, before:"WzExNiwxMDEsMTE1LDExNiw1M10"){edges{node{name}}}}"#)
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn node_status_customer_scoping_pagination_admin_allowed() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps("allowed-host", &["sensor"], &mut online_apps_by_host_id);
        insert_apps("customer2-host", &["sensor"], &mut online_apps_by_host_id);

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let id0 = insert_active_node(&schema.store(), "a_customer2_status", 2, "customer2-host");
        let id1 = insert_active_node(&schema.store(), "b_customer1_status", 1, "allowed-host");
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);

        let res = schema
            .execute_as_system_admin(
                r"{nodeStatusList(first: 1){edges{node{name}} pageInfo{hasNextPage hasPreviousPage}}}",
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );

        let data = res.data.into_json().unwrap();
        let edges = data["nodeStatusList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["node"]["name"], "a_customer2_status");
        assert_eq!(
            data["nodeStatusList"]["pageInfo"]["hasNextPage"],
            json!(true)
        );
        assert_eq!(
            data["nodeStatusList"]["pageInfo"]["hasPreviousPage"],
            json!(false)
        );
    }

    #[tokio::test]
    async fn node_status_customer_scoping_pagination_allowed() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps("allowed-host", &["sensor"], &mut online_apps_by_host_id);
        insert_apps("forbidden-host", &["sensor"], &mut online_apps_by_host_id);

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let id0 = insert_active_node(&schema.store(), "a_forbidden_status", 2, "forbidden-host");
        let id1 = insert_active_node(&schema.store(), "b_allowed_status", 1, "allowed-host");
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);

        let res = schema
            .execute_with_guard_and_data(
                r"{nodeStatusList(first: 1){edges{node{name}} pageInfo{hasNextPage hasPreviousPage}}}",
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
                CustomerIds(Some(vec![1])),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );

        let data = res.data.into_json().unwrap();
        let edges = data["nodeStatusList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["node"]["name"], "b_allowed_status");
        assert_eq!(
            data["nodeStatusList"]["pageInfo"]["hasNextPage"],
            json!(false)
        );
        assert_eq!(
            data["nodeStatusList"]["pageInfo"]["hasPreviousPage"],
            json!(false)
        );
    }

    #[tokio::test]
    async fn node_status_customer_scoping_pagination_forbidden() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps("forbidden-host", &["sensor"], &mut online_apps_by_host_id);

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let id0 = insert_active_node(&schema.store(), "a_forbidden_status", 2, "forbidden-host");
        assert_eq!(id0, 0);

        let res = schema
            .execute_with_guard_and_data(
                r"{nodeStatusList(first: 1){edges{node{name}} pageInfo{hasNextPage hasPreviousPage}}}",
                crate::graphql::RoleGuard::Role(Role::SecurityAdministrator),
                CustomerIds(Some(vec![1])),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );

        let data = res.data.into_json().unwrap();
        let edges = data["nodeStatusList"]["edges"].as_array().unwrap();
        assert!(edges.is_empty());
        assert_eq!(
            data["nodeStatusList"]["pageInfo"]["hasNextPage"],
            json!(false)
        );
        assert_eq!(
            data["nodeStatusList"]["pageInfo"]["hasPreviousPage"],
            json!(false)
        );
    }
}
