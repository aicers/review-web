use async_graphql::{Context, Object, Result, SimpleObject, ID};
use futures::future::join_all;
use review_database::Node;
use tracing::{error, info};

use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    NodeControlMutation,
};
use crate::graphql::{customer::broadcast_customer_networks, get_customer_networks};

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
    /// notifying agents or broadcasting customer ID changes. The response includes a `gigantoDraft`
    /// field, which represents the draft configuration of the Giganto module associated with the
    /// node.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_node(&self, ctx: &Context<'_>, id: ID) -> Result<ApplyNodeResponse> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let (node, invalid_agents) = {
            let store = crate::graphql::get_store(ctx).await?;
            let node_map = store.node_map();
            node_map
                .get_by_id(i)?
                .ok_or_else(|| async_graphql::Error::new(format!("Node with ID {i} not found")))?
        };

        if !invalid_agents.is_empty() {
            return Err(async_graphql::Error::new(format!(
                "Node {i} cannot be applied due to invalid agents: {invalid_agents:?}"
            )));
        }

        if node.name_draft.is_none() {
            // Since the `name` of the node is used as the key in the database, the `name_draft`
            // must be present to apply the node.
            return Err("Node is not valid for apply".into());
        }

        let giganto_draft = node
            .giganto
            .as_ref()
            .and_then(|g| g.draft.as_ref().map(ToString::to_string));

        let apply_scope = node_apply_scope(&node);

        if apply_scope.db {
            if let Some(ref target_agents) = apply_scope.agents {
                update_db(ctx, &node, &target_agents.updates, &target_agents.disables).await?;
            } else {
                update_db(ctx, &node, &[], &[]).await?;
            };

            info!(
                "[{}] Node ID {i} - Node's drafts are applied.\nName: {:?}, Name draft: {:?}\nProfile: {:?}, Profile draft: {:?}",
                chrono::Utc::now(),
                node.name,
                node.name_draft,
                node.profile,
                node.profile_draft,
            );

            broadcast_customer_change_if_needed(ctx, &node).await;
        }

        if let Some(ref target_agents) = apply_scope.agents {
            let agent_manager = ctx.data::<BoxedAgentManager>()?;
            if let Err(e) = notify_agents(
                agent_manager,
                &target_agents.updates,
                &target_agents.disables,
            )
            .await
            {
                error!("Failed to notify agents for node {i} to be updated. However, the failure does not affect the node application operation.\nDetails:\n{e:?}",);
            }

            info!(
                "[{}] Node ID {i} - Node's agents are notified to be updated.\n{:?}",
                chrono::Utc::now(),
                node.agents.iter().filter_map(|agent| {
                    if target_agents.updates.contains(&agent.key.as_str()) {
                        Some(format!(
                            "\nAgent key: {}, Config: {:?}, Draft: {:?}",
                            agent.key, agent.config, agent.draft
                        ))
                    } else {
                        None
                    }
                })
            );
        }

        Ok(ApplyNodeResponse { id, giganto_draft })
    }
}

#[derive(SimpleObject, Clone)]
pub struct ApplyNodeResponse {
    /// The ID of the node to which the draft was applied.
    pub id: ID,

    /// The draft of the Giganto module, associated with the node.
    ///
    /// If `None`, it means either the node does not have the Giganto module or the draft for the
    /// Giganto module is not available. In the latter case, this indicates that the Giganto should
    /// be disabled.
    pub giganto_draft: Option<String>,
}

async fn notify_agents(
    agent_manager: &BoxedAgentManager,
    update_agent_keys: &[&str],
    disable_agent_keys: &[&str],
) -> Result<()> {
    let update_futures = update_agent_keys.iter().map(|agent_key| async move {
        agent_manager.update_config(agent_key).await.map_err(|e| {
            async_graphql::Error::new(format!(
                "Failed to notify agent for config update {agent_key}: {e}"
            ))
        })
    });

    // TODO: We need to implement the logic to disable agents. For now, we will only log the
    // message.
    info!("Agents {disable_agent_keys:?} need to be notified to be disabled, but disabling logic is not yet implemented");

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

fn node_apply_scope(node: &Node) -> NodeApplyScope {
    let is_name_changed = node.name_draft.as_ref() != Some(&node.name);
    let is_profile_changed = node.profile_draft != node.profile;
    let is_any_agent_changed = node.agents.iter().any(|agent| agent.draft != agent.config);

    let target_agents = if is_any_agent_changed {
        let mut updates = Vec::new();
        let mut disables = Vec::new();
        node.agents.iter().for_each(|agent| {
            if agent.draft.is_none() {
                disables.push(agent.key.as_str());
            } else if agent.draft != agent.config {
                updates.push(agent.key.as_str());
            }
        });
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
    node: &Node,
    update_agent_keys: &[&str],
    disable_agent_keys: &[&str],
) -> Result<()> {
    let store = crate::graphql::get_store(ctx).await?;
    let mut map = store.node_map();

    let mut update = node.clone();
    update
        .name
        .clone_from(update.name_draft.as_ref().ok_or("Name draft must exist")?);

    update.profile.clone_from(&update.profile_draft);

    // Update agents, removing those whose keys are in `disable_agent_keys`
    update.agents = update
        .agents
        .iter()
        .filter_map(|agent| {
            if disable_agent_keys.contains(&agent.key.as_str()) {
                None
            } else if update_agent_keys.contains(&agent.key.as_str()) {
                let mut updated_agent = agent.clone();
                updated_agent.config.clone_from(&updated_agent.draft);
                Some(updated_agent)
            } else {
                Some(agent.clone())
            }
        })
        .collect();

    let old = node.clone().into();
    let new = update.into();
    Ok(map.update(node.id, &old, &new)?)
}

async fn broadcast_customer_change_if_needed(ctx: &Context<'_>, node: &Node) {
    if let Some(customer_id) = customer_id_to_broadcast(node) {
        if let Err(e) = broadcast_customer_change(ctx, customer_id).await {
            error!(
                "Failed to broadcast customer change for customer ID {customer_id} on node {}. The failure did not affect the node application operation. Error: {e:?}",
                node.id,
            );
        }
    }
}

fn customer_id_to_broadcast(node: &Node) -> Option<u32> {
    let is_review = node
        .profile_draft
        .as_ref()
        .is_some_and(|s| super::is_review(&s.hostname));

    let old_customer_id: Option<u32> = node.profile.as_ref().map(|s| s.customer_id);
    let new_customer_id: Option<u32> = node.profile_draft.as_ref().map(|s| s.customer_id);

    if is_review && (old_customer_id != new_customer_id) {
        new_customer_id
    } else {
        None
    }
}

async fn broadcast_customer_change(ctx: &Context<'_>, customer_id: u32) -> Result<()> {
    let store = crate::graphql::get_store(ctx).await?;
    let networks = get_customer_networks(&store, customer_id)?;
    if let Err(e) = broadcast_customer_networks(ctx, &networks).await {
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
    use serde_json::json;

    use crate::graphql::{AgentManager, BoxedAgentManager, SamplingPolicy, TestSchema};

    #[tokio::test]
    async fn test_apply_node() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["reconverge@analysis", "piglet@collect"],
        });

        let schema = TestSchema::new_with(agent_manager, None).await;

        // check empty
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 0}}"#);

        // insert node
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "reconverge@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                            config: null
                            draft: "test = 'toml'"
                        },
                        {
                            key: "piglet@collect"
                            kind: PIGLET
                            status: ENABLED
                            config: null
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
                r#"query {
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
                  }"#,
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
                                    "hostname": "admin.aice-security.com",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "reconverge@analysis",
                                      "kind": "RECONVERGE",
                                      "status": "ENABLED",
                                      "config": null,
                                      "draft": "test = 'toml'"
                                    },
                                    {
                                      "node": 0,
                                      "key": "piglet@collect",
                                      "kind": "PIGLET",
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

        // check node list after apply
        let res = schema
            .execute(
                r#"query {
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
                  }"#,
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
                                    "hostname": "admin.aice-security.com",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "reconverge@analysis",
                                      "kind": "RECONVERGE",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    },
                                    {
                                      "node": 0,
                                      "key": "piglet@collect",
                                      "kind": "PIGLET",
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
                                hostname: "admin.aice-security.com",
                            }
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                            }
                            agents: [
                                {
                                    key: "reconverge@analysis",
                                    kind: "RECONVERGE",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "piglet@collect",
                                    kind: "PIGLET",
                                    status: "ENABLED",
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
                                hostname: "admin.aice-security.com",
                            }
                            agents: [
                                {
                                    key: "reconverge@analysis",
                                    kind: "RECONVERGE",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "piglet@collect",
                                    kind: "PIGLET",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
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
                r#"query {
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
                  }"#,
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
                                    "hostname": "admin.aice-security.com",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "reconverge@analysis",
                                      "kind": "RECONVERGE",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    },
                                    {
                                      "node": 0,
                                      "key": "piglet@collect",
                                      "kind": "PIGLET",
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

        // check node list after apply
        let res = schema
            .execute(
                r#"query {
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
                  }"#,
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
                                    "hostname": "admin.aice-security.com",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "reconverge@analysis",
                                      "kind": "RECONVERGE",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    },
                                    {
                                      "node": 0,
                                      "key": "piglet@collect",
                                      "kind": "PIGLET",
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
                                hostname: "admin.aice-security.com",
                            }
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                            }
                            agents: [
                                {
                                    key: "reconverge@analysis",
                                    kind: "RECONVERGE",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "piglet@collect",
                                    kind: "PIGLET",
                                    status: "ENABLED",
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
                                hostname: "admin.aice-security.com",
                            }
                            agents: [
                                {
                                    key: "reconverge@analysis",
                                    kind: "RECONVERGE",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "piglet@collect",
                                    kind: "PIGLET",
                                    status: "ENABLED",
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

        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // apply node - expected to neither update nor notify agent, but return gigantoDraft
        // successfully
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

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "applyNode": {
                    "id": "0",
                    "gigantoDraft": "test = 'giganto_toml'"
                }
            })
        );

        // check node list after apply
        let res = schema
            .execute(
                r#"query {
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
                }"#,
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
                                    "hostname": "admin.aice-security.com",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                },
                                "agents": [
                                    {
                                        "node": 0,
                                        "key": "reconverge@analysis",
                                        "kind": "RECONVERGE",
                                        "status": "ENABLED",
                                        "config": "test = 'toml'",
                                        "draft": "test = 'toml'"
                                    },
                                    {
                                        "node": 0,
                                        "key": "piglet@collect",
                                        "kind": "PIGLET",
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

        // update node to disable one of the agents (piglet@collect) in next apply
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
                                hostname: "admin.aice-security.com",
                            }
                            profileDraft: {
                                customerId: 0,
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                            }
                            agents: [
                                {
                                    key: "reconverge@analysis",
                                    kind: "RECONVERGE",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "piglet@collect",
                                    kind: "PIGLET",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
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
                                hostname: "admin.aice-security.com",
                            }
                            agents: [
                                {
                                    key: "reconverge@analysis",
                                    kind: "RECONVERGE",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "piglet@collect",
                                    kind: "PIGLET",
                                    status: "ENABLED",
                                    config: "test = 'toml'",
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
                r#"query {
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
                  }"#,
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
                                    "hostname": "admin.aice-security.com",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "reconverge@analysis",
                                      "kind": "RECONVERGE",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
                                      "draft": "test = 'toml'"
                                    },
                                    {
                                      "node": 0,
                                      "key": "piglet@collect",
                                      "kind": "PIGLET",
                                      "status": "ENABLED",
                                      "config": "test = 'toml'",
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

        // apply node - expected to update db and notify agent, and also piglet is expected to be
        // removed from the `agents` vector.
        let res = schema
            .execute(
                r#"mutation {
                        applyNode(id: "0") {
                            id
                        }
                    }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: {id: "0"}}"#);

        // check node list after apply
        let res = schema
            .execute(
                r#"query {
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
                      }"#,
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
                                    "hostname": "admin.aice-security.com",
                                },
                                "profileDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                },
                                "agents": [
                                    {
                                      "node": 0,
                                      "key": "reconverge@analysis",
                                      "kind": "RECONVERGE",
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
    async fn test_apply_node_error_due_to_invalid_drafts() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["reconverge@analysis", "piglet@collect"],
        });

        let schema = TestSchema::new_with(agent_manager, None).await;

        // insert node
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        agents: [{
                            key: "reconverge@analysis"
                            kind: RECONVERGE
                            status: ENABLED
                            config: null
                            draft: "test = 'toml'"
                        },
                        {
                            key: "piglet@collect"
                            kind: PIGLET
                            status: ENABLED
                            config: null
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
                    applyNode(id: "0") {
                        id
                        gigantoDraft
                    }
                }"#,
            )
            .await;

        // Check that the operation failed
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_apply_node_disables_agents() {}

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
            _list: &[u8],
        ) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }
        async fn broadcast_internal_networks(
            &self,
            _networks: &[u8],
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(vec!["hog@hostA".to_string()])
        }

        async fn broadcast_allow_networks(
            &self,
            _networks: &[u8],
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(vec![])
        }

        async fn broadcast_block_networks(
            &self,
            _networks: &[u8],
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

        /// Returns the configuration of the given agent.
        async fn get_config(
            &self,
            hostname: &str,
            _agent_id: &str,
        ) -> Result<review_protocol::types::Config, anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
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
            .map(|&app| (format!("{}@{}", app, host), app.to_string()))
            .collect();
        map.insert(host.to_string(), entries);
    }

    #[tokio::test]
    async fn test_node_shutdown() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps("analysis", &["hog"], &mut online_apps_by_host_id);

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
            available_agents: vec!["hog@analysis"],
        });

        let schema = TestSchema::new_with(agent_manager, None).await;

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
