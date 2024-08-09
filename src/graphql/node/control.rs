use async_graphql::{Context, Object, Result, SimpleObject, ID};
use review_database::{Node, NodeProfile};
use tracing::{error, info};

use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    ModuleName, NodeControlMutation,
};
use crate::graphql::{customer::broadcast_customer_networks, get_customer_networks};

const MAX_SET_CONFIG_TRY_COUNT: u32 = 3;

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

    // TODO: Apply node issue #251
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_node(&self, ctx: &Context<'_>, id: ID) -> Result<ApplyResult> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let agents = ctx.data::<BoxedAgentManager>()?;

        let (node, _invalid_agents) = {
            let store = crate::graphql::get_store(ctx).await?;
            let node_map = store.node_map();
            node_map
                .get_by_id(i)?
                .ok_or_else(|| async_graphql::Error::new(format!("Node with ID {i} not found",)))?
        };

        if node.name_draft.is_none() && node.profile_draft.is_none() {
            return Err("There is nothing to apply.".into());
        }

        let config_setted_modules = send_set_config_requests(agents, &node).await;
        let success_modules = if let Ok(config_setted_modules) = config_setted_modules {
            update_node(ctx, i, node.clone(), &config_setted_modules).await?;

            if let Some(customer_id) = should_broadcast_customer_change(&node) {
                broadcast_customer_change(customer_id, ctx).await?;
            }
            config_setted_modules
        } else {
            return Err("Failed to apply node profile".into());
        };

        Ok(ApplyResult {
            id,
            success_modules,
        })
    }
}

#[derive(SimpleObject, Clone)]
pub struct ApplyResult {
    pub id: ID,
    pub success_modules: Vec<ModuleName>,
}

async fn send_set_config_requests(
    agents: &BoxedAgentManager,
    node: &Node,
) -> anyhow::Result<Vec<ModuleName>> {
    let profile_draft = node
        .profile_draft
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("There is nothing to be applied."))?;

    let mut result_combined: Vec<ModuleName> = vec![];

    for (module_name, config) in target_app_configs(profile_draft) {
        if send_set_config_request(
            agents,
            &profile_draft.hostname,
            module_name.as_ref(),
            &config,
        )
        .await?
        {
            result_combined.push(module_name);
        }
    }

    Ok(result_combined)
}

async fn send_set_config_request(
    agents: &BoxedAgentManager,
    hostname: &str,
    module_name: &str,
    config: &review_protocol::types::Config,
) -> anyhow::Result<bool> {
    for _ in 0..MAX_SET_CONFIG_TRY_COUNT {
        let set_config_response = agents.set_config(hostname, module_name, config).await;
        if set_config_response.is_ok() {
            return Ok(true);
        }
        info!("Failed to set config for module {module_name}. Retrying...");
    }

    Ok(false)
}

fn target_app_configs(
    _profile_draft: &NodeProfile,
) -> Vec<(ModuleName, review_protocol::types::Config)> {
    Vec::new() // TODO
}

#[allow(clippy::struct_excessive_bools)]
struct ModuleSpecificProfileUpdateIndicator {
    hog: bool,
    reconverge: bool,
    piglet: bool,
}

impl ModuleSpecificProfileUpdateIndicator {
    fn all_true(&self) -> bool {
        self.hog && self.reconverge && self.piglet
    }
}

async fn update_node(
    ctx: &Context<'_>,
    i: u32,
    node: Node,
    _config_setted_modules: &[ModuleName],
) -> Result<()> {
    let mut updated_node = node.clone();
    updated_node.name = updated_node.name_draft.take().unwrap_or(updated_node.name);

    if let Some(_profile_draft) = &updated_node.profile_draft {
        let update_module_specific_profile_indicator = ModuleSpecificProfileUpdateIndicator {
            hog: true, // TODO
            reconverge: true,
            piglet: true,
        };

        if update_module_specific_profile_indicator.all_true() {
            // All fields in the `profile` can simply be replaced with fields in `profile_draft`.
            updated_node.profile = updated_node.profile_draft.take();
        } else {
            update_common_node_profile(&mut updated_node);
            update_module_specific_profile(
                &mut updated_node,
                &update_module_specific_profile_indicator,
            );
        }
    }

    let store = crate::graphql::get_store(ctx).await?;
    let mut map = store.node_map();

    let old: review_database::NodeUpdate = node.into();
    let new: review_database::NodeUpdate = updated_node.into();
    Ok(map.update(i, &old, &new)?)
}

fn update_common_node_profile(updated_node: &mut Node) {
    let mut updated_profile = updated_node.profile.take().unwrap_or_default();
    if let Some(profile_draft) = updated_node.profile_draft.as_ref() {
        // These are common node profile fields, that are not tied to specific modules
        updated_profile.customer_id = profile_draft.customer_id;
        updated_profile
            .description
            .clone_from(&profile_draft.description);
        updated_profile.hostname.clone_from(&profile_draft.hostname);
    }
    updated_node.profile = Some(updated_profile);
}

fn update_module_specific_profile(
    updated_node: &mut Node,
    _update_module_specific_profile: &ModuleSpecificProfileUpdateIndicator,
) {
    let updated_profile = updated_node.profile.take().unwrap_or_default();

    updated_node.profile = Some(updated_profile);
}

fn should_broadcast_customer_change(node: &Node) -> Option<u32> {
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

async fn broadcast_customer_change(customer_id: u32, ctx: &Context<'_>) -> Result<()> {
    let store = crate::graphql::get_store(ctx).await?;
    let networks = get_customer_networks(&store, customer_id)?;
    if let Err(e) = broadcast_customer_networks(ctx, &networks).await {
        error!("failed to broadcast internal networks. {e:?}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_json_diff::assert_json_eq;
    use async_trait::async_trait;
    use ipnet::IpNet;
    use serde_json::json;
    use tokio::sync::mpsc::{self, Sender};

    use crate::graphql::{AgentManager, BoxedAgentManager, SamplingPolicy, TestSchema};

    #[tokio::test]
    async fn test_node_apply() {
        let schema = TestSchema::new().await;

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

        // apply node
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
                                "nameDraft": null,
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                },
                                "profileDraft": null,
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

        // update node with name change
        let res = schema
            .execute(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "admin node",
                            nameDraft: null,
                            profile: {
                                customerId: "0",
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                            },
                            profileDraft: null,
                            agents: [
                                {
                                    key: "reconverge@analysis",
                                    kind: "RECONVERGE",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'toml'"
                                },
                                {
                                    key: "piglet@collect",
                                    kind: "PIGLET",
                                    status: "ENABLED",
                                    config: null,
                                    draft: "test = 'toml'"
                                }
                            ],
                            giganto: null,
                        },
                        new: {
                            nameDraft: "admin node with new name",
                            profileDraft: {
                                customerId: "0",
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                            }
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // apply node
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
                                "nameDraft": null,
                                "profile": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                },
                                "profileDraft": null,
                            }
                        }
                    ]
                }
            })
        );
    }

    struct MockAgentManager {
        pub online_apps_by_host_id: HashMap<String, Vec<(String, String)>>,
        pub send_result_checker: Sender<String>,
    }

    impl MockAgentManager {
        pub async fn insert_result(&self, result_key: &str) {
            self.send_result_checker
                .send(result_key.to_string())
                .await
                .expect("send result failed");
        }
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

        async fn ping(&self, hostname: &str) -> Result<i64, anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
        }

        async fn reboot(&self, hostname: &str) -> Result<(), anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
        }

        async fn set_config(
            &self,
            hostname: &str,
            agent_id: &str,
            _config: &review_protocol::types::Config,
        ) -> Result<(), anyhow::Error> {
            self.insert_result(format!("{agent_id}@{hostname}").as_str())
                .await;
            Ok(())
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
        insert_apps("localhost", &["hog"], &mut online_apps_by_host_id);

        let (send_result_checker, _recv_result_checker) = mpsc::channel(10);

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
            send_result_checker,
        });

        let schema = TestSchema::new_with(agent_manager, None).await;

        // node_shutdown
        let res = schema
            .execute(
                r#"mutation {
                nodeShutdown(hostname:"localhost")
            }"#,
            )
            .await;

        assert_eq!(res.data.to_string(), r#"{nodeShutdown: "localhost"}"#);
    }
}
