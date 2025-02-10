use async_graphql::{Context, Object, Result, ID};
use futures::future::join_all;
use tracing::{error, info};

use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    gen_agent_key, NodeControlMutation, SEMI_SUPERVISED_AGENT,
};
use crate::graphql::{
    customer::{send_agent_specific_customer_networks, NetworksTargetAgentKeysPair},
    get_customer_networks,
    node::input::NodeInput,
};

#[Object]
impl NodeControlMutation {
    /// Reboots the node with the given hostname as an argument.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node_reboot(&self, ctx: &Context<'_>, hostname: String) -> Result<String> {
        let agents = ctx.data::<BoxedAgentManager>()?;
        let review_hostname = roxy::hostname();
        if !review_hostname.is_empty() && review_hostname == hostname {
            Err("cannot reboot. review reboot is not allowed".into())
        } else {
            agents.reboot(&hostname).await?;
            Ok(hostname)
        }
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
    .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node_shutdown(&self, ctx: &Context<'_>, hostname: String) -> Result<String> {
        let agents = ctx.data::<BoxedAgentManager>()?;
        let review_hostname = roxy::hostname();
        if !review_hostname.is_empty() && review_hostname == hostname {
            Err("cannot shutdown. review shutdown is not allowed".into())
        } else {
            agents.halt(&hostname).await?;
            Ok(hostname)
        }
    }

    /// Applies the draft configuration to the node with the given ID.
    ///
    /// This function updates the node's `name` with `name_draft`, `profile` with `profile_draft`,
    /// and `config` values of agents with their `draft` values.
    ///
    /// Returns success as long as the database update is successful, regardless of the outcome of
    /// notifying agents or broadcasting customer ID changes.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_node(&self, ctx: &Context<'_>, id: ID, node: NodeInput) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        if node.name_draft.is_none() {
            // Since the `name` of the node is used as the key in the database, the `name_draft`
            // must be present to apply the node.
            return Err("Node is not valid for apply".into());
        }

        let apply_scope = node_apply_scope(&node);

        if apply_scope.db {
            update_db(
                ctx,
                i,
                &node,
                apply_scope.agents.as_ref().map_or(&[], |a| &a.disables),
            )
            .await?;

            info!(
                "[{}] Node ID {i} - Node's drafts are applied.\nName: {}, Name draft: {}\nProfile: {}, Profile draft: {}",
                chrono::Utc::now(),
                node.name,
                node.name_draft.as_ref().map(ToString::to_string).unwrap_or_default(),
                node.profile.as_ref().map(ToString::to_string).unwrap_or_default(),
                node.profile_draft.as_ref().map(ToString::to_string).unwrap_or_default(),
            );

            send_customer_change_if_needed(ctx, i, &node).await;
        }

        if let Some(ref target_agents) = apply_scope.agents {
            let hostname = {
                let store = crate::graphql::get_store(ctx).await?;
                let node_map = store.node_map();
                let (node, _) = node_map.get_by_id(i)?.ok_or_else(|| {
                    async_graphql::Error::new(format!("Node with ID {i} not found"))
                })?;
                node.profile.map(|p| p.hostname).unwrap_or_default()
            };

            if hostname.is_empty() {
                info!(
                    "Node ID {i} - Node's agents are not notified because the hostname is empty."
                );
            } else {
                let agent_manager = ctx.data::<BoxedAgentManager>()?;
                if let Err(e) = notify_agents(
                    agent_manager,
                    hostname.as_str(),
                    &target_agents.updates,
                    &target_agents.disables,
                )
                .await
                {
                    error!("Failed to notify agents for node {i} to be updated. This failure may impact configuration synchronization.\nDetails: {e:?}");
                }

                info!(
                    "[{}] Node ID {i} - Node's agents are notified to be updated. {:?}",
                    chrono::Utc::now(),
                    target_agents.updates,
                );
            }
        }

        Ok(id)
    }
}

async fn notify_agents(
    agent_manager: &BoxedAgentManager,
    hostname: &str,
    update_agent_ids: &[&str],
    disable_agent_ids: &[&str],
) -> Result<()> {
    let update_futures = update_agent_ids.iter().map(|agent_id| async move {
        let agent_key = format!("{agent_id}@{hostname}");
        agent_manager
            .update_config(agent_key.as_str())
            .await
            .map_err(|e| {
                async_graphql::Error::new(format!(
                    "Failed to notify agent for config update {agent_key}: {e}"
                ))
            })
    });

    // TODO: #281
    info!("Agents {disable_agent_ids:?} need to be notified to be disabled");

    let notification_results: Vec<Result<_>> = join_all(update_futures).await;

    let errors: Vec<String> = notification_results
        .into_iter()
        .filter_map(|result| result.err().map(|e| e.message))
        .collect();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(async_graphql::Error::new(errors.join("\n")))
    }
}

struct NodeApplyScope<'a> {
    db: bool,
    agents: Option<NotificationTarget<'a>>,
}

struct NotificationTarget<'a> {
    pub updates: Vec<&'a str>,
    pub disables: Vec<&'a str>,
}

fn node_apply_scope(node: &NodeInput) -> NodeApplyScope {
    let is_name_changed = node.name_draft.as_ref() != Some(&node.name);
    let is_profile_changed = node.profile_draft != node.profile;
    let is_any_agent_changed = node.agents.iter().any(|agent| agent.draft != agent.config);

    let target_agents = if is_any_agent_changed {
        let (disables, updates) = node.agents.iter().fold(
            (Vec::new(), Vec::new()),
            |(mut disables, mut updates), agent| {
                match (&agent.draft, &agent.config) {
                    (None, _) => disables.push(agent.key.as_str()),
                    (Some(draft), _)
                        if Some(draft) != agent.config.as_ref() && !draft.is_empty() =>
                    {
                        updates.push(agent.key.as_str());
                    }
                    _ => {}
                }
                (disables, updates)
            },
        );
        Some(NotificationTarget { updates, disables })
    } else {
        None
    };

    NodeApplyScope {
        db: is_name_changed || is_profile_changed || is_any_agent_changed,
        agents: target_agents,
    }
}

async fn update_db(
    ctx: &Context<'_>,
    i: u32,
    node: &NodeInput,
    disable_agent_ids: &[&str],
) -> Result<()> {
    let store = crate::graphql::get_store(ctx).await?;
    let mut map = store.node_map();

    let mut update = node.clone();
    update
        .name
        .clone_from(update.name_draft.as_ref().ok_or("Name draft must exist")?);

    update.profile.clone_from(&update.profile_draft);

    // Update agents, removing those whose keys are in `disable_agent_ids`
    update.agents = update
        .agents
        .iter()
        .filter_map(|agent| {
            if disable_agent_ids.contains(&agent.key.as_str()) {
                None
            } else {
                let mut updated_agent = agent.clone();
                updated_agent.config.clone_from(&updated_agent.draft);
                Some(updated_agent)
            }
        })
        .collect();

    let old = node.clone().try_into()?;
    let new = update.try_into()?;
    Ok(map.update(i, &old, &new)?)
}

async fn send_customer_change_if_needed(ctx: &Context<'_>, i: u32, node: &NodeInput) {
    if let Some(customer_id) = customer_id_to_send(node) {
        let hostname = node
            .profile_draft
            .as_ref()
            .expect("When customer_id exists, `nodeInput.profile_draft` means Some, which means that the values of the other fields in the `NodeProfileInput` also exist. Therefore, their values are always valid.")
            .hostname.as_str();
        let agent_keys = node
            .agents
            .iter()
            .filter_map(|agent| gen_agent_key(agent.kind, hostname).ok())
            .collect::<Vec<String>>();
        let Ok(customer_id) = customer_id.parse::<u32>() else {
            error!("Failed to parse customer ID from node {i} for broadcasting customer change");
            return;
        };
        if let Err(e) = send_customer_change(ctx, customer_id, agent_keys).await {
            error!(
                "Failed to broadcast customer change for customer ID {customer_id} on node {i}. The failure did not affect the node application operation. Error: {e:?}",
            );
        }
    }
}

fn customer_id_to_send(node: &NodeInput) -> Option<&str> {
    let old_customer_id = node.profile.as_ref().map(|s| s.customer_id.as_str());
    let new_customer_id = node.profile_draft.as_ref().map(|s| s.customer_id.as_str());

    if old_customer_id == new_customer_id {
        None
    } else {
        new_customer_id
    }
}

async fn send_customer_change(
    ctx: &Context<'_>,
    customer_id: u32,
    agent_keys: Vec<String>,
) -> Result<()> {
    let store = crate::graphql::get_store(ctx).await?;
    let networks = get_customer_networks(&store, customer_id)?;
    let network_list =
        NetworksTargetAgentKeysPair::new(networks, agent_keys, SEMI_SUPERVISED_AGENT);
    if let Err(e) = send_agent_specific_customer_networks(ctx, &[network_list]).await {
        error!("failed to broadcast internal networks. {e:?}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use assert_json_diff::assert_json_eq;
    use async_trait::async_trait;
    use ipnet::IpNet;
    use review_database::HostNetworkGroup;
    use serde_json::json;

    use crate::graphql::{
        customer::NetworksTargetAgentKeysPair, AgentManager, BoxedAgentManager, SamplingPolicy,
        TestSchema,
    };

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_apply_node() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@all-in-one", "sensor@all-in-one"],
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // check empty
        let res = schema.execute(r"{nodeList{totalCount}}").await;
        assert_eq!(res.data.to_string(), r"{nodeList: {totalCount: 0}}");

        // insert node
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "all-in-one",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                            draft: "test = 'toml'"
                        },
                        {
                            key: "sensor"
                            kind: SENSOR
                            status: ENABLED
                            draft: "test = 'toml'"
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // check node list after insert
        let res = schema
            .execute(
                r"query {
                    nodeList(first: 10) {
                      totalCount
                      edges {
                        node {
                            id
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
                            agents {
                                node
                                key
                                kind
                                status
                                config
                                draft
                            }
                            giganto {
                                status
                                draft
                            }
                        }
                      }
                    }
                  }",
            )
            .await;
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": 1,
                    "edges": [
                        {
                            "node": {
                                "id": "0",
                                "name": "admin node",
                                "nameDraft": "admin node",
                                "profile": null,
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "unsupervised",
                                      "kind": "UNSUPERVISED",
                                      "status": "ENABLED",
                                      "config": null,
                                      "draft": "test = 'toml'"
                                    },
                                    {
                                      "node": 0,
                                      "key": "sensor",
                                      "kind": "SENSOR",
                                      "status": "ENABLED",
                                      "config": null,
                                      "draft": "test = 'toml'"
                                    }
                                  ],
                                "giganto": null,
                            }
                        }
                    ]
                }
            })
        );

        // apply node - expected to update db and notify agent
        let res = schema
            .execute(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "admin node",
                            nameDraft: "admin node",
                            profile: null,
                            profileDraft: {
                                customerId: "0",
                                description: "This is the admin node running review.",
                                hostname: "all-in-one"
                            },
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: UNSUPERVISED,
                                    status: ENABLED,
                                    config: null,
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: SENSOR,
                                    status: ENABLED,
                                    config: null,
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: null
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute(
                r"query {
                    nodeList(first: 10) {
                      totalCount
                      edges {
                        node {
                            id
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
                            agents {
                                node
                                key
                                kind
                                status
                                config
                                draft
                            }
                            giganto {
                                status
                                draft
                            }
                        }
                      }
                    }
                  }",
            )
            .await;
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": 1,
                    "edges": [
                        {
                            "node": {
                                "id": "0",
                                "name": "admin node",
                                "nameDraft": "admin node",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "unsupervised",
                                      "kind": "UNSUPERVISED",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    },
                                    {
                                      "node": 0,
                                      "key": "sensor",
                                      "kind": "SENSOR",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    }
                                  ],
                                "giganto": null,
                            }
                        }
                    ]
                }
            })
        );

        // update node with name change
        let res = schema
            .execute(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "admin node",
                            nameDraft: "admin node",
                            profile: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: UNSUPERVISED,
                                    status: ENABLED,
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: SENSOR,
                                    status: ENABLED,
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: null,
                        },
                        new: {
                            nameDraft: "admin node with new name",
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: UNSUPERVISED,
                                    status: ENABLED,
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: SENSOR,
                                    status: ENABLED,
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: null,
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // check node list after update
        let res = schema
            .execute(
                r"query {
                    nodeList(first: 10) {
                      totalCount
                      edges {
                        node {
                            id
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
                            agents {
                                node
                                key
                                kind
                                status
                                config
                                draft
                            }
                            giganto {
                                status
                                draft
                            }
                        }
                      }
                    }
                  }",
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": 1,
                    "edges": [
                        {
                            "node": {
                                "id": "0",
                                "name": "admin node",
                                "nameDraft": "admin node with new name",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "unsupervised",
                                      "kind": "UNSUPERVISED",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    },
                                    {
                                      "node": 0,
                                      "key": "sensor",
                                      "kind": "SENSOR",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    }
                                  ],
                                "giganto": null,
                            }
                        }
                    ]
                }
            })
        );

        // apply node - expected to update db
        let res = schema
            .execute(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "admin node",
                            nameDraft: "admin node with new name",
                            profile: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: UNSUPERVISED,
                                    status: ENABLED,
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: SENSOR,
                                    status: ENABLED,
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: null
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute(
                r"query {
                    nodeList(first: 10) {
                      totalCount
                      edges {
                        node {
                            id
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
                            agents {
                                node
                                key
                                kind
                                status
                                config
                                draft
                            }
                            giganto {
                                status
                                draft
                            }
                        }
                      }
                    }
                  }",
            )
            .await;
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": 1,
                    "edges": [
                        {
                            "node": {
                                "id": "0",
                                "name": "admin node with new name",
                                "nameDraft": "admin node with new name",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "unsupervised",
                                      "kind": "UNSUPERVISED",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    },
                                    {
                                      "node": 0,
                                      "key": "sensor",
                                      "kind": "SENSOR",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    }
                                ],
                                "giganto": null
                            }
                        }
                    ]
                }
            })
        );

        // update giganto draft
        let res = schema
            .execute(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "admin node with new name",
                            nameDraft: "admin node with new name",
                            profile: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: UNSUPERVISED,
                                    status: ENABLED,
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: SENSOR,
                                    status: ENABLED,
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: null,
                        },
                        new: {
                            nameDraft: "admin node with new name",
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: UNSUPERVISED,
                                    status: ENABLED,
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: SENSOR,
                                    status: ENABLED,
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: {
                                status: ENABLED,
                                draft: "test = 'giganto_toml'"
                            }
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // apply node - expected to neither update nor notify agent
        let res = schema
            .execute(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "admin node with new name",
                            nameDraft: "admin node with new name",
                            profile: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: UNSUPERVISED,
                                    status: ENABLED,
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: SENSOR,
                                    status: ENABLED,
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: {
                                status: ENABLED,
                                draft: "test = 'giganto_toml'"
                            }
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute(
                r"query {
                    nodeList(first: 10) {
                        totalCount
                        edges {
                            node {
                                id
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
                                agents {
                                    node
                                    key
                                    kind
                                    status
                                    config
                                    draft
                                }
                                giganto {
                                    status
                                    draft
                                }
                            }
                        }
                    }
                }",
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": 1,
                    "edges": [
                        {
                            "node": {
                                "id": "0",
                                "name": "admin node with new name",
                                "nameDraft": "admin node with new name",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "agents": [
                                    {
                                        "node": 0,
                                        "key": "unsupervised",
                                        "kind": "UNSUPERVISED",
                                        "status": "ENABLED",
                                        "config": "test = 'toml'",
                                        "draft": "test = 'toml'"
                                    },
                                    {
                                        "node": 0,
                                        "key": "sensor",
                                        "kind": "SENSOR",
                                        "status": "ENABLED",
                                        "config": "test = 'toml'",
                                        "draft": "test = 'toml'"
                                    }
                                ],
                                "giganto": {
                                    "status": "ENABLED",
                                    "draft": "test = 'giganto_toml'"
                                }
                            }
                        }
                    ]
                }
            })
        );

        // update sensor draft
        let res = schema
            .execute(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "admin node with new name",
                            nameDraft: "admin node with new name",
                            profile: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: UNSUPERVISED,
                                    status: ENABLED,
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: SENSOR,
                                    status: ENABLED,
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: {
                                    status: ENABLED,
                                    draft: "test = 'giganto_toml'"
                            }
                        },
                        new: {
                            nameDraft: "admin node with new name",
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: UNSUPERVISED,
                                    status: ENABLED,
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: SENSOR,
                                    status: ENABLED,
                                    draft: "test = 'changed_toml'"
                                }
                            ],
                            giganto: {
                                status: ENABLED,
                                draft: "test = 'giganto_toml'"
                            }
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // check node list after update
        let res = schema
            .execute(
                r"query {
                    nodeList(first: 10) {
                      totalCount
                      edges {
                        node {
                            id
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
                            agents {
                                node
                                key
                                kind
                                status
                                config
                                draft
                            }
                            giganto {
                                status
                                draft
                            }
                        }
                      }
                    }
                  }",
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": 1,
                    "edges": [
                        {
                            "node": {
                                "id": "0",
                                "name": "admin node with new name",
                                "nameDraft": "admin node with new name",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "unsupervised",
                                      "kind": "UNSUPERVISED",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    },
                                    {
                                      "node": 0,
                                      "key": "sensor",
                                      "kind": "SENSOR",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'changed_toml'"
                                    }
                                  ],
                                "giganto": {
                                    "status": "ENABLED",
                                    "draft": "test = 'giganto_toml'"
                                },
                            }
                        }
                    ]
                }
            })
        );

        // apply node
        let res = schema
            .execute(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "admin node with new name",
                            nameDraft: "admin node with new name",
                            profile: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: "UNSUPERVISED",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
                                    draft: "test = 'changed_toml'"
                                }
                            ],
                            giganto: {
                                status: ENABLED,
                                draft: "test = 'giganto_toml'"
                            }
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute(
                r"query {
                    nodeList(first: 10) {
                        totalCount
                        edges {
                            node {
                                id
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
                                agents {
                                    node
                                    key
                                    kind
                                    status
                                    config
                                    draft
                                }
                                giganto {
                                    status
                                    draft
                                }
                            }
                        }
                    }
                }",
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": 1,
                    "edges": [
                        {
                            "node": {
                                "id": "0",
                                "name": "admin node with new name",
                                "nameDraft": "admin node with new name",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "agents": [
                                    {
                                        "node": 0,
                                        "key": "unsupervised",
                                        "kind": "UNSUPERVISED",
                                        "status": "ENABLED",
                                        "config": "test = 'toml'",
                                        "draft": "test = 'toml'"
                                    },
                                    {
                                        "node": 0,
                                        "key": "sensor",
                                        "kind": "SENSOR",
                                        "status": "ENABLED",
                                        "config": "test = 'changed_toml'",
                                        "draft": "test = 'changed_toml'"
                                    }
                                ],
                                "giganto": {
                                    "status": "ENABLED",
                                    "draft": "test = 'giganto_toml'"
                                }
                            }
                        }
                    ]
                }
            })
        );

        // update node to disable one of the agents (sensor@all-in-one) in next apply
        let res = schema
            .execute(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "admin node with new name",
                            nameDraft: "admin node with new name",
                            profile: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: "UNSUPERVISED",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED",
                                    config: "test = 'changed_toml'",
                                    draft: "test = 'changed_toml'"
                                }
                            ],
                            giganto: {
                                status: "ENABLED",
                                draft: "test = 'giganto_toml'"
                            }
                        },
                        new: {
                            nameDraft: "admin node with new name",
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: "UNSUPERVISED",
                                    status: "ENABLED",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED",
                                    draft: null
                                }
                            ],
                            giganto: {
                                status: "ENABLED",
                                draft: "test = 'giganto_toml'"
                            }
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // check node list after update
        let res = schema
            .execute(
                r"query {
                    nodeList(first: 10) {
                      totalCount
                      edges {
                        node {
                            id
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
                            agents {
                                node
                                key
                                kind
                                status
                                config
                                draft
                            }
                            giganto {
                                status
                                draft
                            }
                        }
                      }
                    }
                  }",
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": 1,
                    "edges": [
                        {
                            "node": {
                                "id": "0",
                                "name": "admin node with new name",
                                "nameDraft": "admin node with new name",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "unsupervised",
                                      "kind": "UNSUPERVISED",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    },
                                    {
                                      "node": 0,
                                      "key": "sensor",
                                      "kind": "SENSOR",
                                      "status": "ENABLED",
                                      "config": "test = 'changed_toml'",
                                      "draft": null
                                    }
                                  ],
                                "giganto": {
                                    "status": "ENABLED",
                                    "draft": "test = 'giganto_toml'"
                                },
                            }
                        }
                    ]
                }
            })
        );

        // apply node - expected to update db and notify agent, and also sensor is expected to be
        // removed from the `agents` vector.
        let res = schema
            .execute(
                r#"mutation {
                        applyNode(
                            id: "0"
                            node: {
                                name: "admin node with new name",
                                nameDraft: "admin node with new name",
                                profile: {
                                    customerId: 0,
                                    description: "This is the admin node running review.",
                                    hostname: "all-in-one",
                                }
                                profileDraft: {
                                    customerId: 0,
                                    description: "This is the admin node running review.",
                                    hostname: "all-in-one",
                                }
                                agents: [
                                    {
                                        key: "unsupervised",
                                        kind: "UNSUPERVISED",
                                        status: "ENABLED",
                                        config: "test = 'toml'",
                                        draft: "test = 'toml'"
                                    },
                                    {
                                        key: "sensor",
                                        kind: "SENSOR",
                                        status: "ENABLED",
                                        config: "test = 'changed_toml'",
                                        draft: null
                                    }
                                ],
                                giganto: {
                                    status: "ENABLED",
                                    draft: "test = 'giganto_toml'"
                                }
                            }
                        )
                    }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute(
                r"query {
                        nodeList(first: 10) {
                          totalCount
                          edges {
                            node {
                                id
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
                                agents {
                                    node
                                    key
                                    kind
                                    status
                                    config
                                    draft
                                }
                                giganto {
                                    status
                                    draft
                                }
                            }
                          }
                        }
                      }",
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": 1,
                    "edges": [
                        {
                            "node": {
                                "id": "0",
                                "name": "admin node with new name",
                                "nameDraft": "admin node with new name",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "unsupervised",
                                      "kind": "UNSUPERVISED",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    }
                                ],
                                "giganto": {
                                    "status": "ENABLED",
                                    "draft": "test = 'giganto_toml'"
                                }
                            }
                        }
                    ]
                }
            })
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_apply_node_empty_draft() {
        // This test ensures that the `applyNode` GraphQL API doesn't notify agents when the agent's
        // draft is empty. `FailingMockAgentManager` is designed to fail if notifications are
        // triggered, so we can confirm no notifications occur if the test passes.
        let agent_manager: BoxedAgentManager = Box::new(FailingMockAgentManager {
            online_apps_by_host_id: HashMap::new(),
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // insert node
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "all-in-one",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                            draft: ""
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // apply node
        let res = schema
            .execute(
                r#"mutation {
                        applyNode(
                            id: "0"
                            node: {
                                name: "admin node",
                                nameDraft: "admin node",
                                profile: null,
                                profileDraft: {
                                    customerId: "0",
                                    description: "This is the admin node running review.",
                                    hostname: "all-in-one"
                                },
                                agents: [
                                    {
                                        key: "unsupervised",
                                        kind: "UNSUPERVISED",
                                        status: "ENABLED",
                                        config: null,
                                        draft: ""
                                    }
                                ],
                                giganto: null
                            }
                        )
                    }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute(
                r"query {
                        nodeList(first: 10) {
                          totalCount
                          edges {
                            node {
                                id
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
                                agents {
                                    node
                                    key
                                    kind
                                    status
                                    config
                                    draft
                                }
                                giganto {
                                    status
                                    draft
                                }
                            }
                          }
                        }
                      }",
            )
            .await;
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "nodeList": {
                    "totalCount": 1,
                    "edges": [
                        {
                            "node": {
                                "id": "0",
                                "name": "admin node",
                                "nameDraft": "admin node",
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "all-in-one",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "unsupervised",
                                      "kind": "UNSUPERVISED",
                                      "status": "ENABLED",
                                      "config": "",
                                      "draft": ""
                                    }
                                  ],
                                "giganto": null,
                            }
                        }
                    ]
                }
            })
        );
    }

    #[tokio::test]
    async fn test_apply_node_error_due_to_invalid_drafts() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@all-in-one", "sensor@all-in-one"],
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // insert node
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "all-in-one",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                            draft: "test = 'toml'"
                        },
                        {
                            key: "sensor"
                            kind: SENSOR
                            status: ENABLED
                            draft: "test = 'toml'"
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Simulate a situation where `name_draft` is set to `None`
        let (node, _invalid_agents) = schema
            .store()
            .await
            .node_map()
            .get_by_id(0)
            .unwrap()
            .unwrap();
        let mut update = node.clone();
        update.name_draft = None;

        let old = node.clone().into();
        let new = update.into();
        let _ = schema.store().await.node_map().update(node.id, &old, &new);

        // Apply node
        let res = schema
            .execute(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "admin node",
                            nameDraft: "admin node",
                            profile: null,
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: "UNSUPERVISED",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: null
                        }
                    )
                }"#,
            )
            .await;

        // Check that the operation failed
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_apply_node_error_due_to_different_node_input() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@all-in-one", "sensor@all-in-one"],
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // insert node
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "all-in-one",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                            draft: "test = 'toml'"
                        },
                        {
                            key: "sensor"
                            kind: SENSOR
                            status: ENABLED
                            draft: "test = 'toml'"
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Apply node
        let res = schema
            .execute(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "admin node",
                            nameDraft: "admin node",
                            profile: null,
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: "UNSUPERVISED",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'different_toml'"
                                }
                            ],
                            giganto: null
                        }
                    )
                }"#,
            )
            .await;

        // Check that the operation failed
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_apply_node_empty_hostname() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@all-in-one", "sensor@all-in-one"],
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // insert node
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                            draft: "test = 'toml'"
                        },
                        {
                            key: "sensor"
                            kind: SENSOR
                            status: ENABLED
                            draft: "test = 'toml'"
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Apply node
        let res = schema
            .execute(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "admin node",
                            nameDraft: "admin node",
                            profile: null,
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: "UNSUPERVISED",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: null
                        }
                    )
                }"#,
            )
            .await;

        // Check that the operation succeeds
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_apply_node_with_agent_manager_failures() {
        let agent_manager: BoxedAgentManager = Box::new(FailingMockAgentManager {
            online_apps_by_host_id: HashMap::new(),
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // insert node
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "all-in-one",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                            draft: "test = 'toml'"
                        },
                        {
                            key: "sensor"
                            kind: SENSOR
                            status: ENABLED
                            draft: "test = 'toml'"
                        }]
                        giganto: null
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Apply node
        let res = schema
            .execute(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "admin node",
                            nameDraft: "admin node",
                            profile: null
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "all-in-one",
                            }
                            agents: [
                                {
                                    key: "unsupervised",
                                    kind: "UNSUPERVISED",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "sensor",
                                    kind: "SENSOR",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: null
                        }
                    )
                }"#,
            )
            .await;

        // Check that the operation succeeds
        assert!(res.is_ok());
    }

    struct MockAgentManager {
        pub online_apps_by_host_id: HashMap<String, Vec<(String, String)>>,
        pub available_agents: Vec<&'static str>,
    }

    #[async_trait]
    impl AgentManager for MockAgentManager {
        async fn broadcast_trusted_domains(&self) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }
        async fn broadcast_trusted_user_agent_list(
            &self,
            _list: &[String],
        ) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }
        async fn send_agent_specific_internal_networks(
            &self,
            _networks: &[NetworksTargetAgentKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(vec!["semi-supervised@hostA".to_string()])
        }

        async fn broadcast_allow_networks(
            &self,
            _networks: &HostNetworkGroup,
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(vec![])
        }

        async fn broadcast_block_networks(
            &self,
            _networks: &HostNetworkGroup,
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(vec![])
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
            Ok(())
        }

        async fn get_process_list(
            &self,
            hostname: &str,
        ) -> Result<Vec<roxy::Process>, anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
        }

        async fn get_resource_usage(
            &self,
            hostname: &str,
        ) -> Result<roxy::ResourceUsage, anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
        }

        async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            Ok(())
        }

        async fn ping(&self, hostname: &str) -> Result<Duration, anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
        }

        async fn reboot(&self, hostname: &str) -> Result<(), anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
        }

        async fn update_config(&self, agent_key: &str) -> Result<(), anyhow::Error> {
            if self.available_agents.contains(&agent_key) {
                Ok(())
            } else {
                anyhow::bail!("Notifying agent {agent_key} to update config failed")
            }
        }

        async fn update_traffic_filter_rules(
            &self,
            _key: &str,
            _rules: &[(IpNet, Option<Vec<u16>>, Option<Vec<u16>>)],
        ) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }
    }

    fn insert_apps(host: &str, apps: &[&str], map: &mut HashMap<String, Vec<(String, String)>>) {
        let entries = apps
            .iter()
            .map(|&app| (format!("{app}@{host}"), app.to_string()))
            .collect();
        map.insert(host.to_string(), entries);
    }

    struct FailingMockAgentManager {
        pub online_apps_by_host_id: HashMap<String, Vec<(String, String)>>,
    }

    #[async_trait]
    impl AgentManager for FailingMockAgentManager {
        async fn broadcast_trusted_domains(&self) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }
        async fn broadcast_trusted_user_agent_list(
            &self,
            _list: &[String],
        ) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }
        async fn send_agent_specific_internal_networks(
            &self,
            _networks: &[NetworksTargetAgentKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            anyhow::bail!("Failed to broadcast internal networks")
        }

        async fn broadcast_allow_networks(
            &self,
            _networks: &HostNetworkGroup,
        ) -> Result<Vec<String>, anyhow::Error> {
            anyhow::bail!("Failed to broadcast allow networks")
        }

        async fn broadcast_block_networks(
            &self,
            _networks: &HostNetworkGroup,
        ) -> Result<Vec<String>, anyhow::Error> {
            anyhow::bail!("Failed to broadcast block networks")
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
            anyhow::bail!("Failed to broadcast crusher sampling policy")
        }

        async fn get_process_list(
            &self,
            hostname: &str,
        ) -> Result<Vec<roxy::Process>, anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
        }

        async fn get_resource_usage(
            &self,
            hostname: &str,
        ) -> Result<roxy::ResourceUsage, anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
        }

        async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            anyhow::bail!("Failed to halt")
        }

        async fn ping(&self, hostname: &str) -> Result<Duration, anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
        }

        async fn reboot(&self, hostname: &str) -> Result<(), anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
        }

        async fn update_config(&self, agent_key: &str) -> Result<(), anyhow::Error> {
            anyhow::bail!("Notifying agent {agent_key} to update config failed")
        }

        async fn update_traffic_filter_rules(
            &self,
            _key: &str,
            _rules: &[(IpNet, Option<Vec<u16>>, Option<Vec<u16>>)],
        ) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }
    }

    #[tokio::test]
    async fn test_node_shutdown() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps(
            "analysis",
            &["semi-supervised"],
            &mut online_apps_by_host_id,
        );

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
            available_agents: vec!["semi-supervised@analysis"],
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // node_shutdown
        let res = schema
            .execute(
                r#"mutation {
                nodeShutdown(hostname:"analysis")
            }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{nodeShutdown: "analysis"}"#);
    }
}
