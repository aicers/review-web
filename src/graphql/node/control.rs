use std::collections::HashSet;

use async_graphql::{Context, Enum, ID, Object, Result, SimpleObject};
use futures::future::join_all;
use itertools::Itertools;
use review_database::AgentStatus;
use tracing::{error, info, warn};

use super::{
    super::{BoxedAgentManager, Role, RoleGuard, customer_access},
    Node, NodeControlMutation, SEMI_SUPERVISED_AGENT, gen_agent_lookup_key,
};
use crate::graphql::{
    customer::{NetworksTargetAgentLookupKeysPair, send_agent_specific_customer_networks},
    get_customer_networks,
    node::input::NodeInput,
};
use crate::{error_with_username, info_with_username, warn_with_username};

#[derive(SimpleObject)]
pub(super) struct AgentNotifyAttempt {
    /// The bare agent key (matching `Agent.key`).
    agent_key: String,
    /// `true` if the manager accepted the notify request. Does not imply that the agent has
    /// already applied the new config.
    succeeded: bool,
    /// Populated only when `succeeded` is `false`.
    error: Option<String>,
}

#[derive(Clone, Copy, Enum, Eq, PartialEq)]
pub(super) enum SkipReason {
    /// The agent's current DB `config` is `None`.
    NotConfigured,
    /// The agent's current DB `config` is `Some("")` (direct-setup magic-string marker).
    DirectSetup,
}

#[derive(SimpleObject)]
pub(super) struct SkippedAgent {
    /// The bare agent key (matching `Agent.key`).
    agent_key: String,
    reason: SkipReason,
}

#[derive(SimpleObject)]
pub(super) struct ApplyAgentConfigOutput {
    /// One entry per agent for whom a notify was attempted (current DB `config` is
    /// `Some(non-empty)`).
    attempts: Vec<AgentNotifyAttempt>,
    /// One entry per agent in the target set that was not notified, with the reason.
    skipped: Vec<SkippedAgent>,
}

fn update_agent_status_to_unknown(ctx: &Context<'_>, hostname: &str) {
    let Ok(store) = crate::graphql::get_store(ctx) else {
        error!("Failed to get store to update agent status for {hostname}");
        return;
    };
    let mut map = store.node_map();
    let Some(agent_keys) = map
        .iter(review_database::event::Direction::Forward, None)
        .find_map(|result| {
            let node = result.ok()?;
            if node
                .profile
                .as_ref()
                .is_some_and(|p| p.hostname == hostname)
            {
                Some(
                    node.agents
                        .iter()
                        .map(|a| a.key.clone())
                        .collect::<Vec<String>>(),
                )
            } else {
                None
            }
        })
    else {
        error!("No node found for hostname: {hostname}");
        return;
    };
    for agent_key in &agent_keys {
        if let Err(e) =
            map.update_agent_status_by_hostname(hostname, agent_key, AgentStatus::Unknown)
        {
            error!("Failed to update agent status to Unknown for {hostname}/{agent_key}: {e}");
        }
    }
}

#[Object]
impl NodeControlMutation {
    /// Reboots the node with the given hostname as an argument.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node_reboot(&self, ctx: &Context<'_>, hostname: String) -> Result<String> {
        customer_access::check_hostname_access(ctx, &hostname)?;

        let agents = ctx.data::<BoxedAgentManager>()?;
        let review_hostname = roxy::hostname();
        if !review_hostname.is_empty() && review_hostname == hostname {
            info_with_username!(ctx, "Node reboot skipped: manager is running on {hostname}");
            Err("cannot reboot. review reboot is not allowed".into())
        } else {
            info_with_username!(ctx, "Reboot request sent to {hostname}");
            agents.reboot(&hostname).await?;
            update_agent_status_to_unknown(ctx, &hostname);
            Ok(hostname)
        }
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
    .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node_shutdown(&self, ctx: &Context<'_>, hostname: String) -> Result<String> {
        customer_access::check_hostname_access(ctx, &hostname)?;

        let agents = ctx.data::<BoxedAgentManager>()?;
        let review_hostname = roxy::hostname();
        if !review_hostname.is_empty() && review_hostname == hostname {
            info_with_username!(
                ctx,
                "Node shutdown skipped: manager is running on {hostname}"
            );
            Err("cannot shutdown. review shutdown is not allowed".into())
        } else {
            info_with_username!(ctx, "Shutdown request sent to {hostname}");
            agents.halt(&hostname).await?;
            update_agent_status_to_unknown(ctx, &hostname);
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

        // Check customer scoping
        customer_access::load_accessible_node(ctx, &id)?;
        if let Some(profile_draft) = node.profile_draft.as_ref() {
            customer_access::check_customer_membership(ctx, &profile_draft.customer_id)?;
        }

        if node.name_draft.is_none() {
            // Since the `name` of the node is used as the key in the database, the `name_draft`
            // must be present to apply the node.
            return Err("Node is not valid for apply".into());
        }

        let apply_scope = node_apply_scope(&node);

        let updated_node = if apply_scope.db {
            let updated = update_db(
                ctx,
                i,
                &node,
                apply_scope.agents.as_ref().map_or(&[], |a| &a.disables),
            )
            .await?;

            info_with_username!(
                ctx,
                "[{}] Node ID {i} - Node's drafts are applied.\nName: {}, Name draft: {}\nProfile: {}, Profile draft: {}",
                chrono::Utc::now(),
                node.name,
                node.name_draft
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                node.profile
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                node.profile_draft
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
            );

            send_customer_change_if_needed(ctx, i, &node).await;
            Some(updated)
        } else {
            None
        };

        if let Some(ref target_agents) = apply_scope.agents {
            // `apply_scope.agents` is `Some` only when `is_any_agent_changed`, which also makes
            // `apply_scope.db` true, so `updated_node` is guaranteed to be `Some` here.
            let hostname = updated_node
                .as_ref()
                .and_then(|n| n.profile.as_ref().map(|p| p.hostname.clone()))
                .unwrap_or_default();

            if hostname.is_empty() {
                info_with_username!(
                    ctx,
                    "Node ID {i} - Node's agents are not notified because the hostname is empty.",
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
                    warn_with_username!(
                        ctx,
                        "Failed to notify agents for node {i} to be updated. This failure may impact configuration synchronization.\nDetails: {e:?}"
                    );
                }

                info_with_username!(
                    ctx,
                    "[{}] Node ID {i} - Node's agents are notified to be updated. {:?}",
                    chrono::Utc::now(),
                    target_agents.updates,
                );
            }
        }

        Ok(id)
    }

    /// Applies the draft configuration to the node with the given ID at the database layer.
    ///
    /// Performs the database promotions (name, profile, agent configs, external services) in a
    /// single atomic update, and broadcasts customer-specific networks when the node's
    /// `customer_id` changes. Does not send agent-config notifications — use `applyAgentConfig`
    /// for that.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_node_draft(&self, ctx: &Context<'_>, id: ID, node: NodeInput) -> Result<Node> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let current_node = customer_access::load_accessible_node(ctx, &id)?;
        if let Some(profile_draft) = node.profile_draft.as_ref() {
            customer_access::check_customer_membership(ctx, &profile_draft.customer_id)?;
        }

        if node.name_draft.is_none() {
            return Err("Node is not valid for apply".into());
        }

        let apply_scope = node_apply_scope(&node);

        if apply_scope.db {
            let updated = update_db(
                ctx,
                i,
                &node,
                apply_scope.agents.as_ref().map_or(&[], |a| &a.disables),
            )
            .await?;

            let now = chrono::Utc::now();
            let name = node.name.as_str();
            let name_draft = node
                .name_draft
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            let profile = node
                .profile
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            let profile_draft = node
                .profile_draft
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            info_with_username!(
                ctx,
                "[{now}] Node ID {i} - Node's drafts are applied.\nName: {name}, Name draft: {name_draft}\nProfile: {profile}, Profile draft: {profile_draft}",
            );

            send_customer_change_if_needed(ctx, i, &node).await;
            Ok(updated.into())
        } else {
            Ok(current_node.into())
        }
    }

    /// Notifies the agents of a node that their config has changed.
    ///
    /// Reads the current DB state of the node and, for each agent in the target set, attempts a
    /// notify when the agent's current DB `config` is `Some(non-empty)`. Skips with reason
    /// otherwise. The mutation performs no DB writes.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_agent_config(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        agent_keys: Option<Vec<String>>,
    ) -> Result<ApplyAgentConfigOutput> {
        let node = customer_access::load_accessible_node(ctx, &node_id)?;

        let hostname = node
            .profile
            .as_ref()
            .map(|p| p.hostname.as_str())
            .unwrap_or_default();
        if hostname.is_empty() {
            return Err("Node hostname is unavailable".into());
        }

        let target_agents: Vec<&review_database::Agent> = match agent_keys.as_ref() {
            None => node.agents.iter().collect(),
            Some(keys) if keys.is_empty() => Vec::new(),
            Some(keys) => {
                let mut seen: HashSet<&str> = HashSet::new();
                for key in keys {
                    if !seen.insert(key.as_str()) {
                        return Err(format!("Duplicate agent key: {key}").into());
                    }
                }
                let agent_index: std::collections::HashMap<&str, &review_database::Agent> =
                    node.agents.iter().map(|a| (a.key.as_str(), a)).collect();
                let mut selected = Vec::with_capacity(keys.len());
                for key in keys {
                    let Some(agent) = agent_index.get(key.as_str()) else {
                        return Err(format!(
                            "Agent key {key} does not belong to node {}",
                            node_id.as_str()
                        )
                        .into());
                    };
                    selected.push(*agent);
                }
                selected
            }
        };

        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        let mut attempts = Vec::new();
        let mut skipped = Vec::new();

        for agent in target_agents {
            match agent.config.as_ref() {
                None => skipped.push(SkippedAgent {
                    agent_key: agent.key.clone(),
                    reason: SkipReason::NotConfigured,
                }),
                Some(config) if config.as_ref().is_empty() => skipped.push(SkippedAgent {
                    agent_key: agent.key.clone(),
                    reason: SkipReason::DirectSetup,
                }),
                Some(_) => {
                    let agent_lookup_key = gen_agent_lookup_key(&agent.key, hostname);
                    match agent_manager.update_config(agent_lookup_key.as_str()).await {
                        Ok(()) => attempts.push(AgentNotifyAttempt {
                            agent_key: agent.key.clone(),
                            succeeded: true,
                            error: None,
                        }),
                        Err(e) => attempts.push(AgentNotifyAttempt {
                            agent_key: agent.key.clone(),
                            succeeded: false,
                            error: Some(e.to_string()),
                        }),
                    }
                }
            }
        }

        Ok(ApplyAgentConfigOutput { attempts, skipped })
    }
}

async fn notify_agents(
    agent_manager: &BoxedAgentManager,
    hostname: &str,
    update_agent_keys: &[&str],
    disable_agent_keys: &[&str],
) -> Result<()> {
    let update_futures = update_agent_keys.iter().map(|agent_key| async move {
        let agent_lookup_key = gen_agent_lookup_key(agent_key, hostname);
        agent_manager
            .update_config(agent_lookup_key.as_str())
            .await
            .map_err(|e| {
                async_graphql::Error::new(format!(
                    "Failed to notify agent for config update {agent_lookup_key}: {e}"
                ))
            })
    });

    // TODO: #281
    info!("Agents {disable_agent_keys:?} need to be notified to be disabled");

    let notification_results: Vec<Result<_>> = join_all(update_futures).await;

    let error_msg = notification_results
        .into_iter()
        .filter_map(|result| result.err().map(|e| e.message))
        .join("\n");

    if error_msg.is_empty() {
        Ok(())
    } else {
        Err(async_graphql::Error::new(error_msg))
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

fn node_apply_scope(node: &NodeInput) -> NodeApplyScope<'_> {
    let is_name_changed = node.name_draft.as_ref() != Some(&node.name);
    let is_profile_changed = node.profile_draft != node.profile;
    let is_any_agent_changed = node.agents.iter().any(|agent| agent.draft != agent.config);
    let is_any_external_service_removed = node
        .external_services
        .iter()
        .any(|service| service.draft.is_none());

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
        db: is_name_changed
            || is_profile_changed
            || is_any_agent_changed
            || is_any_external_service_removed,
        agents: target_agents,
    }
}

async fn update_db(
    ctx: &Context<'_>,
    i: u32,
    node: &NodeInput,
    disable_agent_keys: &[&str],
) -> Result<review_database::Node> {
    let store = crate::graphql::get_store(ctx)?;
    let mut map = store.node_map();

    let mut update = node.clone();
    update
        .name
        .clone_from(update.name_draft.as_ref().ok_or("Name draft must exist")?);

    update.profile.clone_from(&update.profile_draft);

    // Update agents, removing those whose keys are in `disable_agent_keys`
    update.agents = update
        .agents
        .into_iter()
        .filter_map(|mut agent| {
            if disable_agent_keys.contains(&agent.key.as_str()) {
                None
            } else {
                agent.config.clone_from(&agent.draft);
                Some(agent)
            }
        })
        .collect();

    // Update external services, removing those whose draft is set to None
    update
        .external_services
        .retain(|service| service.draft.is_some());

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
        let agent_lookup_keys = node
            .agents
            .iter()
            .map(|agent| gen_agent_lookup_key(&agent.key, hostname))
            .collect::<Vec<String>>();
        let Ok(customer_id) = customer_id.parse::<u32>() else {
            error_with_username!(
                ctx,
                "Failed to parse customer ID from node {i} for broadcasting customer change"
            );
            return;
        };
        if let Err(e) = send_customer_change(ctx, customer_id, agent_lookup_keys).await {
            error_with_username!(
                ctx,
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
    agent_lookup_keys: Vec<String>,
) -> Result<()> {
    let network_list = {
        let store = crate::graphql::get_store(ctx)?;
        let networks = get_customer_networks(&store, customer_id)?;
        NetworksTargetAgentLookupKeysPair::new(networks, agent_lookup_keys, SEMI_SUPERVISED_AGENT)
    };
    if let Err(e) = send_agent_specific_customer_networks(ctx, &[network_list]).await {
        error_with_username!(ctx, "Failed to broadcast internal networks: {e:?}");
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::await_holding_lock)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use assert_json_diff::assert_json_eq;
    use async_trait::async_trait;
    use ipnet::IpNet;
    use review_database::AgentStatus;
    use serde_json::json;

    use super::super::test_support::{insert_active_node, insert_apps, update_account_customers};
    use crate::graphql::{
        AgentManager, BoxedAgentManager, Role, SamplingPolicy, TestSchema,
        customer::NetworksTargetAgentLookupKeysPair,
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
        let res = schema
            .execute_as_system_admin(r"{nodeList{totalCount}}")
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: "0"}}"#);

        // insert node
        let res = schema
            .execute_as_system_admin(
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
                        }],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // check node list after insert
        let res = schema
            .execute_as_system_admin(
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
                            externalServices {
                                node
                                key
                                kind
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
                    "totalCount": "1",
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
                                "externalServices": []
                            }
                        }
                    ]
                }
            })
        );

        // apply node - expected to update db and notify agent
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: []
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute_as_system_admin(
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
                            externalServices {
                                node
                                key
                                kind
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
                    "totalCount": "1",
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
                                "externalServices": []
                            }
                        }
                    ]
                }
            })
        );

        // update node with name change
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: [],
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
                            externalServices: null,
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // check node list after update
        let res = schema
            .execute_as_system_admin(
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
                            externalServices {
                                node
                                key
                                kind
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
                    "totalCount": "1",
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
                                "externalServices": []
                            }
                        }
                    ]
                }
            })
        );

        // apply node - expected to update db
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: []
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute_as_system_admin(
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
                            externalServices {
                                node
                                key
                                kind
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
                    "totalCount": "1",
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
                                "externalServices": []
                            }
                        }
                    ]
                }
            })
        );

        // update data store draft
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: []
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
                            externalServices: [
                                {
                                    key: "data_store",
                                    kind: DATA_STORE,
                                    status: ENABLED,
                                    draft: "test = 'data_store_toml'"
                                }
                            ]
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // apply node - expected to neither update nor notify agent
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: [
                                {
                                    key: "data_store",
                                    kind: DATA_STORE,
                                    status: ENABLED,
                                    draft: "test = 'data_store_toml'"
                                }
                            ]
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute_as_system_admin(
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
                                externalServices {
                                    node
                                    key
                                    kind
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
                    "totalCount": "1",
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
                                "externalServices": [
                                    {
                                        "node": 0,
                                        "key": "data_store",
                                        "kind": "DATA_STORE",
                                        "status": "ENABLED",
                                        "draft": "test = 'data_store_toml'"
                                    }
                                ]
                            }
                        }
                    ]
                }
            })
        );

        // update sensor draft
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: [
                                {
                                    key: "data_store",
                                    kind: DATA_STORE,
                                    status: ENABLED,
                                    draft: "test = 'data_store_toml'"
                                }
                            ],
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
                            externalServices: [
                                {
                                    key: "data_store",
                                    kind: DATA_STORE,
                                    status: ENABLED,
                                    draft: "test = 'data_store_toml'"
                                }
                            ],
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // check node list after update
        let res = schema
            .execute_as_system_admin(
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
                            externalServices {
                                node
                                key
                                kind
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
                    "totalCount": "1",
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
                                "externalServices": [
                                    {
                                        "node": 0,
                                        "key": "data_store",
                                        "kind": "DATA_STORE",
                                        "status": "ENABLED",
                                        "draft": "test = 'data_store_toml'"
                                    }
                                ]
                            }
                        }
                    ]
                }
            })
        );

        // apply node
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: [
                                {
                                    key: "data_store",
                                    kind: DATA_STORE,
                                    status: ENABLED,
                                    draft: "test = 'data_store_toml'"
                                }
                            ]
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute_as_system_admin(
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
                                externalServices {
                                    node
                                    key
                                    kind
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
                    "totalCount": "1",
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
                                "externalServices": [
                                    {
                                        "node": 0,
                                        "key": "data_store",
                                        "kind": "DATA_STORE",
                                        "status": "ENABLED",
                                        "draft": "test = 'data_store_toml'"
                                    }
                                ]
                            }
                        }
                    ]
                }
            })
        );

        // update node to disable one of the agents (sensor@all-in-one) in next apply
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: [
                                {
                                    key: "data_store",
                                    kind: DATA_STORE,
                                    status: ENABLED,
                                    draft: "test = 'data_store_toml'"
                                }
                            ]
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
                            externalServices: [
                                {
                                    key: "data_store",
                                    kind: DATA_STORE,
                                    status: ENABLED,
                                    draft: "test = 'data_store_toml'"
                                }
                            ]
                        }
                    )
                }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // check node list after update
        let res = schema
            .execute_as_system_admin(
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
                            externalServices {
                                node
                                key
                                kind
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
                    "totalCount": "1",
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
                                "externalServices": [
                                    {
                                        "node": 0,
                                        "key": "data_store",
                                        "kind": "DATA_STORE",
                                        "status": "ENABLED",
                                        "draft": "test = 'data_store_toml'"
                                    }
                                ]
                            }
                        }
                    ]
                }
            })
        );

        // apply node - expected to update db and notify agent, and also sensor is expected to be
        // removed from the `agents` vector.
        let res = schema
            .execute_as_system_admin(
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
                                externalServices: [
                                    {
                                        key: "data_store",
                                        kind: DATA_STORE,
                                        status: ENABLED,
                                        draft: "test = 'data_store_toml'"
                                    }
                                ]
                            }
                        )
                    }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute_as_system_admin(
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
                                externalServices {
                                    node
                                    key
                                    kind
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
                    "totalCount": "1",
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
                                "externalServices": [
                                    {
                                        "node": 0,
                                        "key": "data_store",
                                        "kind": "DATA_STORE",
                                        "status": "ENABLED",
                                        "draft": "test = 'data_store_toml'"
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
            .execute_as_system_admin(
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
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // apply node
        let res = schema
            .execute_as_system_admin(
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
                                externalServices: []
                            }
                        )
                    }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // check node list after apply
        let res = schema
            .execute_as_system_admin(
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
                                externalServices {
                                    node
                                    key
                                    kind
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
                    "totalCount": "1",
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
                                "externalServices": []
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
            .execute_as_system_admin(
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
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Simulate a situation where `name_draft` is set to `None`
        let (node, _, _) = schema.store().node_map().get_by_id(0).unwrap().unwrap();
        let mut update = node.clone();
        update.name_draft = None;

        let old = node.clone().into();
        let new = update.into();
        let _ = schema.store().node_map().update(node.id, &old, &new);

        // Apply node
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: []
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
            .execute_as_system_admin(
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
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Apply node
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: []
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
            .execute_as_system_admin(
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
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Apply node
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: []
                        }
                    )
                }"#,
            )
            .await;

        // Check that the operation succeeds
        assert!(res.is_ok());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_apply_node_external_service_removal() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@all-in-one"],
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // insert node with external service
        let res = schema
            .execute_as_system_admin(
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
                        }]
                        externalServices: [{
                            key: "data_store"
                            kind: DATA_STORE
                            status: ENABLED
                            draft: "test = 'data_store_toml'"
                        }]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // apply node to save the initial state
        let res = schema
            .execute_as_system_admin(
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
                            agents: [{
                                key: "unsupervised",
                                kind: UNSUPERVISED,
                                status: ENABLED,
                                config: null,
                                draft: "test = 'toml'"
                            }],
                            externalServices: [{
                                key: "data_store",
                                kind: DATA_STORE,
                                status: ENABLED,
                                draft: "test = 'data_store_toml'"
                            }]
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // verify external service is present
        let res = schema
            .execute_as_system_admin(
                r"query {
                    nodeList(first: 10) {
                        edges {
                            node {
                                externalServices {
                                    key
                                    kind
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
                    "edges": [
                        {
                            "node": {
                                "externalServices": [
                                    {
                                        "key": "data_store",
                                        "kind": "DATA_STORE",
                                        "status": "ENABLED",
                                        "draft": "test = 'data_store_toml'"
                                    }
                                ]
                            }
                        }
                    ]
                }
            })
        );

        // apply node with external service draft set to null (should remove it)
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "admin node",
                            nameDraft: "admin node",
                            profile: {
                                customerId: "0",
                                description: "This is the admin node running review.",
                                hostname: "all-in-one"
                            },
                            profileDraft: {
                                customerId: "0",
                                description: "This is the admin node running review.",
                                hostname: "all-in-one"
                            },
                            agents: [{
                                key: "unsupervised",
                                kind: UNSUPERVISED,
                                status: ENABLED,
                                config: "test = 'toml'",
                                draft: "test = 'toml'"
                            }],
                            externalServices: [{
                                key: "data_store",
                                kind: DATA_STORE,
                                status: ENABLED,
                                draft: null
                            }]
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // verify external service is removed
        let res = schema
            .execute_as_system_admin(
                r"query {
                    nodeList(first: 10) {
                        edges {
                            node {
                                externalServices {
                                    key
                                    kind
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
                    "edges": [
                        {
                            "node": {
                                "externalServices": []
                            }
                        }
                    ]
                }
            })
        );
    }

    #[tokio::test]
    async fn test_apply_node_with_agent_manager_failures() {
        let agent_manager: BoxedAgentManager = Box::new(FailingMockAgentManager {
            online_apps_by_host_id: HashMap::new(),
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // insert node
        let res = schema
            .execute_as_system_admin(
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
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Apply node
        let res = schema
            .execute_as_system_admin(
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
                            externalServices: []
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
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(vec!["semi-supervised@hostA".to_string()])
        }

        async fn send_agent_specific_allow_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(vec![])
        }

        async fn send_agent_specific_block_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
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

        async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> {
            Ok(())
        }

        async fn update_config(&self, agent_lookup_key: &str) -> Result<(), anyhow::Error> {
            let is_available = self.available_agents.contains(&agent_lookup_key);
            #[cfg(feature = "auth-mtls")]
            let is_available = is_available
                || self
                    .available_agents
                    .iter()
                    .any(|available_agent| available_agent.replace('@', ".") == agent_lookup_key);

            if is_available {
                Ok(())
            } else {
                anyhow::bail!("Notifying agent {agent_lookup_key} to update config failed")
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
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            anyhow::bail!("Failed to broadcast internal networks")
        }

        async fn send_agent_specific_allow_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
        ) -> Result<Vec<String>, anyhow::Error> {
            anyhow::bail!("Failed to broadcast allow networks")
        }

        async fn send_agent_specific_block_networks(
            &self,
            _networks: &[NetworksTargetAgentLookupKeysPair],
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

        async fn update_config(&self, agent_lookup_key: &str) -> Result<(), anyhow::Error> {
            anyhow::bail!("Notifying agent {agent_lookup_key} to update config failed")
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
    async fn test_node_reboot() {
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

        // Insert a node with hostname "analysis" and an agent with ENABLED status
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "analysis node",
                        customerId: 0,
                        description: "Analysis node for testing reboot.",
                        hostname: "analysis",
                        agents: [{
                            key: "semi-supervised"
                            kind: SEMI_SUPERVISED
                            status: ENABLED
                            draft: "test = 'toml'"
                        }],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Apply the node so that profile (with hostname) is set from profile_draft
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "analysis node",
                            nameDraft: "analysis node",
                            profile: null,
                            profileDraft: {
                                customerId: "0",
                                description: "Analysis node for testing reboot.",
                                hostname: "analysis"
                            },
                            agents: [
                                {
                                    key: "semi-supervised",
                                    kind: SEMI_SUPERVISED,
                                    status: ENABLED,
                                    config: null,
                                    draft: "test = 'toml'"
                                }
                            ],
                            externalServices: []
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // Verify the agent status is ENABLED before reboot
        let (node, _, _) = schema.store().node_map().get_by_id(0).unwrap().unwrap();
        assert_eq!(node.agents.len(), 1);
        assert_eq!(node.agents[0].status, AgentStatus::Enabled);

        // node_reboot
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                nodeReboot(hostname:"analysis")
            }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{nodeReboot: "analysis"}"#);

        // Verify the agent status is updated to Unknown after reboot
        let (node, _, _) = schema.store().node_map().get_by_id(0).unwrap().unwrap();
        assert_eq!(node.agents[0].status, AgentStatus::Unknown);
    }

    #[tokio::test]
    async fn node_shutdown_customer_scoping_admin_allowed() {
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

        // Insert a node with hostname "analysis" and an agent with ENABLED status
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "analysis node",
                        customerId: 0,
                        description: "Analysis node for testing shutdown.",
                        hostname: "analysis",
                        agents: [{
                            key: "semi-supervised"
                            kind: SEMI_SUPERVISED
                            status: ENABLED
                            draft: "test = 'toml'"
                        }],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        // Apply the node so that profile (with hostname) is set from profile_draft
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "analysis node",
                            nameDraft: "analysis node",
                            profile: null,
                            profileDraft: {
                                customerId: "0",
                                description: "Analysis node for testing shutdown.",
                                hostname: "analysis"
                            },
                            agents: [
                                {
                                    key: "semi-supervised",
                                    kind: SEMI_SUPERVISED,
                                    status: ENABLED,
                                    config: null,
                                    draft: "test = 'toml'"
                                }
                            ],
                            externalServices: []
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

        // Verify the agent status is ENABLED before shutdown
        let (node, _, _) = schema.store().node_map().get_by_id(0).unwrap().unwrap();
        assert_eq!(node.agents.len(), 1);
        assert_eq!(node.agents[0].status, AgentStatus::Enabled);

        // node_shutdown
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                nodeShutdown(hostname:"analysis")
            }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{nodeShutdown: "analysis"}"#);

        // Verify the agent status is updated to Unknown after shutdown
        let (node, _, _) = schema.store().node_map().get_by_id(0).unwrap().unwrap();
        assert_eq!(node.agents[0].status, AgentStatus::Unknown);
    }

    #[tokio::test]
    async fn node_shutdown_customer_scoping_allowed() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps(
            "host-customer-1",
            &["semi-supervised"],
            &mut online_apps_by_host_id,
        );

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
            available_agents: vec!["semi-supervised@host-customer-1"],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let id0 = insert_active_node(&schema.store(), "shutdown_target", 1, "host-customer-1");
        assert_eq!(id0, 0);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));
        let res = schema
            .execute_as_scoped_user(
                r#"mutation { nodeShutdown(hostname: "host-customer-1") }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(res.data.to_string(), r#"{nodeShutdown: "host-customer-1"}"#);
    }

    #[tokio::test]
    async fn node_shutdown_customer_scoping_forbidden() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps(
            "host-customer-2",
            &["semi-supervised"],
            &mut online_apps_by_host_id,
        );

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
            available_agents: vec!["semi-supervised@host-customer-2"],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let id0 = insert_active_node(&schema.store(), "shutdown_target", 2, "host-customer-2");
        assert_eq!(id0, 0);

        // Scoped user with customer 1 cannot shutdown customer 2 node.
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));
        let res = schema
            .execute_as_scoped_user(
                r#"mutation { nodeShutdown(hostname: "host-customer-2") }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn node_reboot_customer_scoping_admin_allowed() {
        let agent_manager: BoxedAgentManager = Box::new(FailingMockAgentManager {
            online_apps_by_host_id: HashMap::new(),
        });

        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    nodeReboot(hostname:"analysis")
                }"#,
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "analysis is unreachable");
    }

    #[tokio::test]
    async fn node_reboot_customer_scoping_allowed() {
        let agent_manager: BoxedAgentManager = Box::new(FailingMockAgentManager {
            online_apps_by_host_id: HashMap::new(),
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let id0 = insert_active_node(&schema.store(), "reboot_target", 1, "host-customer-1");
        assert_eq!(id0, 0);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));
        let res = schema
            .execute_as_scoped_user(
                r#"mutation { nodeReboot(hostname: "host-customer-1") }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "host-customer-1 is unreachable");
    }

    #[tokio::test]
    async fn node_reboot_customer_scoping_forbidden() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps(
            "host-customer-2",
            &["semi-supervised"],
            &mut online_apps_by_host_id,
        );

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
            available_agents: vec!["semi-supervised@host-customer-2"],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let id0 = insert_active_node(&schema.store(), "reboot_target", 2, "host-customer-2");
        assert_eq!(id0, 0);

        // Scoped user with customer 1 cannot reboot customer 2 node.
        update_account_customers(&schema.store(), "testuser", Some(vec![1]));
        let res = schema
            .execute_as_scoped_user(
                r#"mutation { nodeReboot(hostname: "host-customer-2") }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn apply_node_customer_scoping_admin_allowed() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec![],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "apply_target",
                        customerId: 2,
                        description: "Target node",
                        hostname: "host-customer-2",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "apply_target",
                            nameDraft: "apply_target",
                            profile: null,
                            profileDraft: {
                                customerId: 2,
                                description: "Target node",
                                hostname: "host-customer-2",
                            },
                            agents: [],
                            externalServices: []
                        }
                    )
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);
    }

    #[tokio::test]
    async fn apply_node_customer_scoping_allowed() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec![],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "apply_target",
                        customerId: 1,
                        description: "Target node",
                        hostname: "host-customer-1",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));
        let res = schema
            .execute_as_scoped_user(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "apply_target",
                            nameDraft: "apply_target",
                            profile: null,
                            profileDraft: {
                                customerId: 1,
                                description: "Target node",
                                hostname: "host-customer-1",
                            },
                            agents: [],
                            externalServices: []
                        }
                    )
                }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);
    }

    #[tokio::test]
    async fn apply_node_customer_scoping_forbidden() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec![],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "apply_target",
                        customerId: 2,
                        description: "Target node",
                        hostname: "host-customer-2",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));
        let res = schema
            .execute_as_scoped_user(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "apply_target",
                            nameDraft: "apply_target",
                            profile: null,
                            profileDraft: {
                                customerId: 2,
                                description: "Target node",
                                hostname: "host-customer-2",
                            },
                            agents: [],
                            externalServices: []
                        }
                    )
                }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn apply_node_customer_scoping_profile_draft_customer_change_forbidden() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec![],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "apply_target",
                        customerId: 1,
                        description: "Target node",
                        hostname: "host-customer-1",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));
        let res = schema
            .execute_as_scoped_user(
                r#"mutation {
                    applyNode(
                        id: "0"
                        node: {
                            name: "apply_target",
                            nameDraft: "apply_target",
                            profile: null,
                            profileDraft: {
                                customerId: 2,
                                description: "Target node",
                                hostname: "host-customer-2",
                            },
                            agents: [],
                            externalServices: []
                        }
                    )
                }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    fn put_node_with_agents(
        store: &review_database::Store,
        name: &str,
        customer_id: u32,
        hostname: &str,
        agents: Vec<review_database::Agent>,
    ) -> u32 {
        let node = review_database::Node {
            id: u32::MAX,
            name: name.to_string(),
            name_draft: Some(name.to_string()),
            profile: Some(review_database::NodeProfile {
                customer_id,
                description: format!("Node for customer {customer_id}"),
                hostname: hostname.to_string(),
            }),
            profile_draft: Some(review_database::NodeProfile {
                customer_id,
                description: format!("Node for customer {customer_id}"),
                hostname: hostname.to_string(),
            }),
            agents,
            external_services: vec![],
            creation_time: chrono::Utc::now(),
        };
        store.node_map().put(&node).expect("insert node")
    }

    fn make_agent(
        key: &str,
        kind: review_database::AgentKind,
        config: Option<&str>,
    ) -> review_database::Agent {
        review_database::Agent {
            node: u32::MAX,
            key: key.to_string(),
            kind,
            status: AgentStatus::Enabled,
            config: config.map(|c| c.to_string().try_into().expect("valid toml")),
            draft: config.map(|c| c.to_string().try_into().expect("valid toml")),
        }
    }

    #[tokio::test]
    async fn test_apply_node_draft_db_only() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@all-in-one"],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "Description.",
                        hostname: "all-in-one",
                        agents: [{
                            key: "unsupervised"
                            kind: UNSUPERVISED
                            status: ENABLED
                            draft: "test = 'toml'"
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
                    applyNodeDraft(
                        id: "0"
                        node: {
                            name: "admin node",
                            nameDraft: "admin node",
                            profile: null,
                            profileDraft: {
                                customerId: "0",
                                description: "Description.",
                                hostname: "all-in-one"
                            },
                            agents: [{
                                key: "unsupervised",
                                kind: UNSUPERVISED,
                                status: ENABLED,
                                config: null,
                                draft: "test = 'toml'"
                            }],
                            externalServices: []
                        }
                    ) {
                        id
                        name
                        profile { hostname customerId }
                        agents { key config draft }
                    }
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "applyNodeDraft": {
                    "id": "0",
                    "name": "admin node",
                    "profile": {
                        "hostname": "all-in-one",
                        "customerId": "0",
                    },
                    "agents": [
                        {
                            "key": "unsupervised",
                            "config": "test = 'toml'",
                            "draft": "test = 'toml'",
                        }
                    ],
                }
            })
        );
    }

    #[tokio::test]
    async fn test_apply_node_draft_missing_name_draft_errors() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec![],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let store = schema.store();
        let id = put_node_with_agents(
            &store,
            "no-name-draft",
            0,
            "no-name-draft-host",
            vec![make_agent(
                "unsupervised",
                review_database::AgentKind::Unsupervised,
                Some("test = 'toml'"),
            )],
        );
        assert_eq!(id, 0);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyNodeDraft(
                        id: "0"
                        node: {
                            name: "no-name-draft",
                            nameDraft: null,
                            profile: {
                                customerId: "0",
                                description: "Node for customer 0",
                                hostname: "no-name-draft-host"
                            },
                            profileDraft: {
                                customerId: "0",
                                description: "Node for customer 0",
                                hostname: "no-name-draft-host"
                            },
                            agents: [{
                                key: "unsupervised",
                                kind: UNSUPERVISED,
                                status: ENABLED,
                                config: "test = 'toml'",
                                draft: "test = 'toml'"
                            }],
                            externalServices: []
                        }
                    ) {
                        id
                    }
                }"#,
            )
            .await;
        assert!(
            !res.errors.is_empty(),
            "Expected an error when name_draft is null"
        );
        assert!(
            res.errors
                .iter()
                .any(|e| e.message.contains("Node is not valid for apply")),
            "Expected 'Node is not valid for apply' error, got: {:?}",
            res.errors
        );
    }

    #[tokio::test]
    async fn test_apply_node_draft_customer_change() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec![],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        // Seed a node whose profile (customer 0) differs from its profile_draft (customer 1) so
        // that applyNodeDraft promotes a customer_id change and broadcasts customer networks.
        let id = {
            let store = schema.store();
            let node = review_database::Node {
                id: u32::MAX,
                name: "node-a".to_string(),
                name_draft: Some("node-a".to_string()),
                profile: Some(review_database::NodeProfile {
                    customer_id: 0,
                    description: "desc".to_string(),
                    hostname: "host-a".to_string(),
                }),
                profile_draft: Some(review_database::NodeProfile {
                    customer_id: 1,
                    description: "desc".to_string(),
                    hostname: "host-a".to_string(),
                }),
                agents: vec![make_agent(
                    "hog",
                    review_database::AgentKind::SemiSupervised,
                    Some("test = 'toml'"),
                )],
                external_services: vec![],
                creation_time: chrono::Utc::now(),
            };
            store.node_map().put(&node).expect("insert node")
        };
        assert_eq!(id, 0);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyNodeDraft(
                        id: "0"
                        node: {
                            name: "node-a",
                            nameDraft: "node-a",
                            profile: {
                                customerId: "0",
                                description: "desc",
                                hostname: "host-a"
                            },
                            profileDraft: {
                                customerId: "1",
                                description: "desc",
                                hostname: "host-a"
                            },
                            agents: [{
                                key: "hog",
                                kind: SEMI_SUPERVISED,
                                status: ENABLED,
                                config: "test = 'toml'",
                                draft: "test = 'toml'"
                            }],
                            externalServices: []
                        }
                    ) {
                        id
                        profile { customerId }
                    }
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "applyNodeDraft": {
                    "id": "0",
                    "profile": { "customerId": "1" }
                }
            })
        );
    }

    #[tokio::test]
    async fn test_apply_node_draft_no_op_short_circuit() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec![],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let store = schema.store();
        let id = put_node_with_agents(
            &store,
            "noop-node",
            7,
            "noop-host",
            vec![make_agent(
                "unsupervised",
                review_database::AgentKind::Unsupervised,
                Some("test = 'toml'"),
            )],
        );
        let (existing, _, _) = store.node_map().get_by_id(id).unwrap().unwrap();
        let creation_time = existing.creation_time;

        // Apply with input that exactly matches the current state — should short-circuit.
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyNodeDraft(
                        id: "0"
                        node: {
                            name: "noop-node",
                            nameDraft: "noop-node",
                            profile: {
                                customerId: "7",
                                description: "Node for customer 7",
                                hostname: "noop-host"
                            },
                            profileDraft: {
                                customerId: "7",
                                description: "Node for customer 7",
                                hostname: "noop-host"
                            },
                            agents: [{
                                key: "unsupervised",
                                kind: UNSUPERVISED,
                                status: ENABLED,
                                config: "test = 'toml'",
                                draft: "test = 'toml'"
                            }],
                            externalServices: []
                        }
                    ) {
                        id
                        name
                        profile { hostname customerId }
                        agents { key config draft }
                    }
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "applyNodeDraft": {
                    "id": "0",
                    "name": "noop-node",
                    "profile": { "hostname": "noop-host", "customerId": "7" },
                    "agents": [{
                        "key": "unsupervised",
                        "config": "test = 'toml'",
                        "draft": "test = 'toml'",
                    }],
                }
            })
        );

        // creation_time remains unchanged, demonstrating that the no-op path returned the DB Node
        // (a reconstruction from `NodeInput` would not preserve `creation_time`).
        let (after, _, _) = store.node_map().get_by_id(id).unwrap().unwrap();
        assert_eq!(after.creation_time, creation_time);
    }

    #[tokio::test]
    async fn test_apply_agent_config_null_keys_mixed_states() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@mixed", "sensor@mixed", "hog@mixed"],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let store = schema.store();
        let id = put_node_with_agents(
            &store,
            "mixed-node",
            0,
            "mixed",
            vec![
                make_agent(
                    "unsupervised",
                    review_database::AgentKind::Unsupervised,
                    Some("test = 'toml'"),
                ),
                make_agent("sensor", review_database::AgentKind::Sensor, Some("")),
                make_agent("hog", review_database::AgentKind::SemiSupervised, None),
            ],
        );
        assert_eq!(id, 0);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyAgentConfig(nodeId: "0") {
                        attempts { agentKey succeeded error }
                        skipped { agentKey reason }
                    }
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "applyAgentConfig": {
                    "attempts": [
                        { "agentKey": "unsupervised", "succeeded": true, "error": null }
                    ],
                    "skipped": [
                        { "agentKey": "sensor", "reason": "DIRECT_SETUP" },
                        { "agentKey": "hog", "reason": "NOT_CONFIGURED" }
                    ]
                }
            })
        );
    }

    #[tokio::test]
    async fn test_apply_agent_config_explicit_subset() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@subset", "sensor@subset"],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let store = schema.store();
        let id = put_node_with_agents(
            &store,
            "subset-node",
            0,
            "subset",
            vec![
                make_agent(
                    "unsupervised",
                    review_database::AgentKind::Unsupervised,
                    Some("test = 'toml'"),
                ),
                make_agent(
                    "sensor",
                    review_database::AgentKind::Sensor,
                    Some("test = 'toml'"),
                ),
            ],
        );
        assert_eq!(id, 0);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyAgentConfig(nodeId: "0", agentKeys: ["sensor"]) {
                        attempts { agentKey succeeded }
                        skipped { agentKey reason }
                    }
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "applyAgentConfig": {
                    "attempts": [{ "agentKey": "sensor", "succeeded": true }],
                    "skipped": []
                }
            })
        );
    }

    #[tokio::test]
    async fn test_apply_agent_config_empty_array() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@empty"],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let store = schema.store();
        let id = put_node_with_agents(
            &store,
            "empty-node",
            0,
            "empty",
            vec![make_agent(
                "unsupervised",
                review_database::AgentKind::Unsupervised,
                Some("test = 'toml'"),
            )],
        );
        assert_eq!(id, 0);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyAgentConfig(nodeId: "0", agentKeys: []) {
                        attempts { agentKey succeeded }
                        skipped { agentKey reason }
                    }
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "applyAgentConfig": {
                    "attempts": [],
                    "skipped": []
                }
            })
        );
    }

    #[tokio::test]
    async fn test_apply_agent_config_duplicate_keys() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@dup"],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let store = schema.store();
        let id = put_node_with_agents(
            &store,
            "dup-node",
            0,
            "dup",
            vec![make_agent(
                "unsupervised",
                review_database::AgentKind::Unsupervised,
                Some("test = 'toml'"),
            )],
        );
        assert_eq!(id, 0);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyAgentConfig(nodeId: "0", agentKeys: ["unsupervised", "unsupervised"]) {
                        attempts { agentKey }
                        skipped { agentKey }
                    }
                }"#,
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(
            res.errors[0].message.contains("Duplicate agent key"),
            "unexpected error: {}",
            res.errors[0].message
        );
    }

    #[tokio::test]
    async fn test_apply_agent_config_unknown_key_rejected() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@unk"],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let store = schema.store();
        let id = put_node_with_agents(
            &store,
            "unk-node",
            0,
            "unk",
            vec![make_agent(
                "unsupervised",
                review_database::AgentKind::Unsupervised,
                Some("test = 'toml'"),
            )],
        );
        assert_eq!(id, 0);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyAgentConfig(nodeId: "0", agentKeys: ["nope"]) {
                        attempts { agentKey }
                        skipped { agentKey }
                    }
                }"#,
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(
            res.errors[0].message.contains("does not belong to node"),
            "unexpected error: {}",
            res.errors[0].message
        );
    }

    #[tokio::test]
    async fn test_apply_agent_config_ordering() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec!["unsupervised@order", "sensor@order", "hog@order"],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let store = schema.store();
        // DB order is unsupervised, sensor, hog.
        let id = put_node_with_agents(
            &store,
            "order-node",
            0,
            "order",
            vec![
                make_agent(
                    "unsupervised",
                    review_database::AgentKind::Unsupervised,
                    Some("test = 'toml'"),
                ),
                make_agent("sensor", review_database::AgentKind::Sensor, Some("")),
                make_agent(
                    "hog",
                    review_database::AgentKind::SemiSupervised,
                    Some("test = 'toml'"),
                ),
            ],
        );
        assert_eq!(id, 0);

        // With agentKeys absent, ordering follows DB agent order — across `attempts` and `skipped`
        // the agent set is covered exactly once. `attempts` in DB-order: unsupervised, hog;
        // `skipped` in DB-order: sensor.
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyAgentConfig(nodeId: "0") {
                        attempts { agentKey }
                        skipped { agentKey reason }
                    }
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "applyAgentConfig": {
                    "attempts": [
                        { "agentKey": "unsupervised" },
                        { "agentKey": "hog" }
                    ],
                    "skipped": [
                        { "agentKey": "sensor", "reason": "DIRECT_SETUP" }
                    ]
                }
            })
        );

        // With agentKeys provided, ordering follows the supplied order.
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyAgentConfig(nodeId: "0", agentKeys: ["hog", "sensor", "unsupervised"]) {
                        attempts { agentKey }
                        skipped { agentKey reason }
                    }
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "applyAgentConfig": {
                    "attempts": [
                        { "agentKey": "hog" },
                        { "agentKey": "unsupervised" }
                    ],
                    "skipped": [
                        { "agentKey": "sensor", "reason": "DIRECT_SETUP" }
                    ]
                }
            })
        );
    }

    #[tokio::test]
    async fn test_apply_agent_config_missing_hostname_errors() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec![],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let store = schema.store();
        let node = review_database::Node {
            id: u32::MAX,
            name: "no-host".to_string(),
            name_draft: Some("no-host".to_string()),
            profile: None,
            profile_draft: Some(review_database::NodeProfile {
                customer_id: 0,
                description: String::new(),
                hostname: "x".to_string(),
            }),
            agents: vec![make_agent(
                "unsupervised",
                review_database::AgentKind::Unsupervised,
                Some("test = 'toml'"),
            )],
            external_services: vec![],
            creation_time: chrono::Utc::now(),
        };
        let id = store.node_map().put(&node).expect("insert node");
        assert_eq!(id, 0);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyAgentConfig(nodeId: "0") {
                        attempts { agentKey }
                        skipped { agentKey }
                    }
                }"#,
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(
            res.errors[0].message.contains("hostname"),
            "unexpected error: {}",
            res.errors[0].message
        );
    }

    #[tokio::test]
    async fn test_apply_agent_config_mixed_outcomes() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            // Only `unsupervised@mixfail` succeeds; `sensor@mixfail` will fail.
            available_agents: vec!["unsupervised@mixfail"],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let store = schema.store();
        let id = put_node_with_agents(
            &store,
            "mixfail-node",
            0,
            "mixfail",
            vec![
                make_agent(
                    "unsupervised",
                    review_database::AgentKind::Unsupervised,
                    Some("test = 'toml'"),
                ),
                make_agent(
                    "sensor",
                    review_database::AgentKind::Sensor,
                    Some("test = 'toml'"),
                ),
            ],
        );
        assert_eq!(id, 0);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyAgentConfig(nodeId: "0") {
                        attempts { agentKey succeeded }
                        skipped { agentKey }
                    }
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let data = res.data.into_json().unwrap();
        let attempts = data["applyAgentConfig"]["attempts"].as_array().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0]["agentKey"], "unsupervised");
        assert_eq!(attempts[0]["succeeded"], true);
        assert_eq!(attempts[1]["agentKey"], "sensor");
        assert_eq!(attempts[1]["succeeded"], false);
    }

    #[tokio::test]
    async fn test_apply_agent_config_multi_instance_lookup_keys() {
        #[cfg(feature = "auth-jwt")]
        let available_agents = vec!["001.hog@multi-instance"];
        #[cfg(feature = "auth-mtls")]
        let available_agents = vec!["001.hog.multi-instance", "002.hog.multi-instance"];

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents,
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let store = schema.store();
        let id = put_node_with_agents(
            &store,
            "multi-instance-node",
            0,
            "multi-instance",
            vec![
                make_agent(
                    "001.hog",
                    review_database::AgentKind::SemiSupervised,
                    Some("test = 'toml'"),
                ),
                make_agent(
                    "002.hog",
                    review_database::AgentKind::SemiSupervised,
                    Some("test = 'toml'"),
                ),
            ],
        );
        assert_eq!(id, 0);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyAgentConfig(nodeId: "0") {
                        attempts { agentKey succeeded error }
                        skipped { agentKey reason }
                    }
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );

        #[cfg(feature = "auth-jwt")]
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "applyAgentConfig": {
                    "attempts": [
                        { "agentKey": "001.hog", "succeeded": true, "error": null },
                        {
                            "agentKey": "002.hog",
                            "succeeded": false,
                            "error": "Notifying agent 002.hog@multi-instance to update config failed"
                        }
                    ],
                    "skipped": []
                }
            })
        );

        #[cfg(feature = "auth-mtls")]
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "applyAgentConfig": {
                    "attempts": [
                        { "agentKey": "001.hog", "succeeded": true, "error": null },
                        { "agentKey": "002.hog", "succeeded": true, "error": null }
                    ],
                    "skipped": []
                }
            })
        );
    }

    #[tokio::test]
    async fn apply_node_draft_customer_scoping_forbidden() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec![],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let id = put_node_with_agents(&schema.store(), "scoped-node", 2, "host-customer-2", vec![]);
        assert_eq!(id, 0);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));
        let res = schema
            .execute_as_scoped_user(
                r#"mutation {
                    applyNodeDraft(
                        id: "0"
                        node: {
                            name: "scoped-node",
                            nameDraft: "scoped-node",
                            profile: {
                                customerId: "2",
                                description: "Node for customer 2",
                                hostname: "host-customer-2"
                            },
                            profileDraft: {
                                customerId: "2",
                                description: "Node for customer 2",
                                hostname: "host-customer-2"
                            },
                            agents: [],
                            externalServices: []
                        }
                    ) { id }
                }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn apply_agent_config_customer_scoping_forbidden() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec![],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let id = put_node_with_agents(&schema.store(), "scoped-node", 2, "host-customer-2", vec![]);
        assert_eq!(id, 0);

        update_account_customers(&schema.store(), "testuser", Some(vec![1]));
        let res = schema
            .execute_as_scoped_user(
                r#"mutation {
                    applyAgentConfig(nodeId: "0") {
                        attempts { agentKey }
                        skipped { agentKey }
                    }
                }"#,
                Role::SecurityAdministrator,
                Some(vec![1]),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn apply_node_draft_customer_scoping_admin_allowed() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id: HashMap::new(),
            available_agents: vec![],
        });
        let schema = TestSchema::new_with_params(agent_manager, None, "testuser").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertNode(
                        name: "apply_target",
                        customerId: 2,
                        description: "Target node",
                        hostname: "host-customer-2",
                        agents: [],
                        externalServices: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    applyNodeDraft(
                        id: "0"
                        node: {
                            name: "apply_target",
                            nameDraft: "apply_target",
                            profile: null,
                            profileDraft: {
                                customerId: 2,
                                description: "Target node",
                                hostname: "host-customer-2",
                            },
                            agents: [],
                            externalServices: []
                        }
                    ) { id }
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
    }
}
