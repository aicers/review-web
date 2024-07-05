use std::net::{IpAddr, SocketAddr};

use async_graphql::{Context, Object, Result, SimpleObject, ID};
use review_database::{Node, NodeSettings};
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

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_node(&self, ctx: &Context<'_>, id: ID) -> Result<ApplyResult> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let agents = ctx.data::<BoxedAgentManager>()?;

        let node = {
            let store = crate::graphql::get_store(ctx).await?;
            let node_map = store.node_map();
            node_map
                .get_by_id(i)?
                .ok_or_else(|| async_graphql::Error::new(format!("Node with ID {i} not found",)))?
        };

        if node.name_draft.is_none() && node.settings_draft.is_none() {
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
            return Err("Failed to apply node settings".into());
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
    let settings_draft = node
        .settings_draft
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("There is nothing to be applied."))?;

    let mut result_combined: Vec<ModuleName> = vec![];

    for (module_name, config) in target_app_configs(settings_draft) {
        if send_set_config_request(
            agents,
            &settings_draft.hostname,
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
    settings_draft: &NodeSettings,
) -> Vec<(ModuleName, review_protocol::types::Config)> {
    let mut configurations = Vec::new();

    if settings_draft.piglet {
        configurations.push((ModuleName::Piglet, build_piglet_config(settings_draft)));
    }

    if settings_draft.hog {
        configurations.push((ModuleName::Hog, build_hog_config(settings_draft)));
    }

    configurations
}

fn build_piglet_config(settings_draft: &NodeSettings) -> review_protocol::types::Config {
    let giganto_address = build_socket_address(
        settings_draft.piglet_giganto_ip,
        settings_draft.piglet_giganto_port,
    );
    let log_options = build_log_options(settings_draft);
    let http_file_types = build_http_file_types(settings_draft);

    review_protocol::types::Config::Piglet(review_protocol::types::PigletConfig {
        giganto_address,
        log_options,
        http_file_types,
    })
}

fn build_hog_config(settings_draft: &NodeSettings) -> review_protocol::types::Config {
    let giganto_address = build_socket_address(
        settings_draft.hog_giganto_ip,
        settings_draft.hog_giganto_port,
    );

    review_protocol::types::Config::Hog(review_protocol::types::HogConfig {
        giganto_address,
        active_protocols: settings_draft.protocols.clone(),
        active_sources: settings_draft.sensors.clone(),
    })
}

fn build_log_options(settings_draft: &NodeSettings) -> Option<Vec<String>> {
    let condition_to_log_option = [
        (settings_draft.save_packets, "dump"),
        (settings_draft.http, "http"),
        (settings_draft.smtp_eml, "eml"),
        (settings_draft.ftp, "ftp"),
    ];

    let log_options = condition_to_log_option
        .iter()
        .filter_map(|(cond, value)| {
            if *cond {
                Some((*value).to_string())
            } else {
                None
            }
        })
        .collect::<Vec<String>>();

    if log_options.is_empty() {
        None
    } else {
        Some(log_options)
    }
}

fn build_http_file_types(settings_draft: &NodeSettings) -> Option<Vec<String>> {
    let condition_to_http_file_types = [
        (settings_draft.office, "office"),
        (settings_draft.exe, "exe"),
        (settings_draft.pdf, "pdf"),
        (settings_draft.txt, "txt"),
        (settings_draft.vbs, "vbs"),
    ];

    let http_file_types = condition_to_http_file_types
        .iter()
        .filter_map(|(cond, value)| {
            if *cond {
                Some((*value).to_string())
            } else {
                None
            }
        })
        .collect::<Vec<String>>();

    if http_file_types.is_empty() {
        None
    } else {
        Some(http_file_types)
    }
}

fn build_socket_address(ip: Option<IpAddr>, port: Option<u16>) -> Option<SocketAddr> {
    ip.and_then(|ip| port.map(|port| SocketAddr::new(ip, port)))
}

#[allow(clippy::struct_excessive_bools)]
struct ModuleSpecificSettingUpdateIndicator {
    hog: bool,
    reconverge: bool,
    piglet: bool,
}

impl ModuleSpecificSettingUpdateIndicator {
    fn all_true(&self) -> bool {
        self.hog && self.reconverge && self.piglet
    }
}

fn okay_to_update_module_specific_settings(
    setting_draft_value: bool,
    config_setted_modules: &[ModuleName],
    expected_module: ModuleName,
) -> bool {
    !setting_draft_value || config_setted_modules.iter().any(|x| *x == expected_module)
}

async fn update_node(
    ctx: &Context<'_>,
    i: u32,
    node: Node,
    config_setted_modules: &[ModuleName],
) -> Result<()> {
    let mut updated_node = node.clone();
    updated_node.name = updated_node.name_draft.take().unwrap_or(updated_node.name);

    if let Some(settings_draft) = &updated_node.settings_draft {
        let update_module_specific_settings = ModuleSpecificSettingUpdateIndicator {
            hog: okay_to_update_module_specific_settings(
                settings_draft.hog,
                config_setted_modules,
                ModuleName::Hog,
            ),
            reconverge: okay_to_update_module_specific_settings(
                settings_draft.reconverge,
                config_setted_modules,
                ModuleName::Reconverge,
            ),
            piglet: okay_to_update_module_specific_settings(
                settings_draft.piglet,
                config_setted_modules,
                ModuleName::Piglet,
            ),
        };

        if update_module_specific_settings.all_true() {
            // All fields in the `settings` can simply be replaced with fields in `settings_draft`.
            updated_node.settings = updated_node.settings_draft.take();
        } else {
            update_common_node_settings(&mut updated_node);
            update_module_specfic_settings(&mut updated_node, &update_module_specific_settings);
        }
    }

    let store = crate::graphql::get_store(ctx).await?;
    let mut map = store.node_map();

    let old: review_database::NodeUpdate = node.into();
    let new: review_database::NodeUpdate = updated_node.into();
    Ok(map.update(i, &old, &new)?)
}

fn update_common_node_settings(updated_node: &mut Node) {
    let mut updated_settings = updated_node.settings.take().unwrap_or_default();
    if let Some(settings_draft) = updated_node.settings_draft.as_ref() {
        // These are common node settings fields, that are not tied to specific modules
        updated_settings.customer_id = settings_draft.customer_id;
        updated_settings
            .description
            .clone_from(&settings_draft.description);
        updated_settings
            .hostname
            .clone_from(&settings_draft.hostname);
    }
    updated_node.settings = Some(updated_settings);
}

fn update_module_specfic_settings(
    updated_node: &mut Node,
    update_module_specific_settings: &ModuleSpecificSettingUpdateIndicator,
) {
    let mut updated_settings = updated_node.settings.take().unwrap_or_default();

    if let Some(settings_draft) = updated_node.settings_draft.as_mut() {
        if update_module_specific_settings.hog {
            updated_settings.hog = settings_draft.hog;
            updated_settings.hog_giganto_ip = settings_draft.hog_giganto_ip;
            updated_settings.hog_giganto_port = settings_draft.hog_giganto_port;
            updated_settings
                .protocols
                .clone_from(&settings_draft.protocols);
            updated_settings.sensors.clone_from(&settings_draft.sensors);
        }

        if update_module_specific_settings.reconverge {
            updated_settings.reconverge = settings_draft.reconverge;
        }

        if update_module_specific_settings.piglet {
            updated_settings.piglet = settings_draft.piglet;
            updated_settings.piglet_giganto_ip = settings_draft.piglet_giganto_ip;
            updated_settings.piglet_giganto_port = settings_draft.piglet_giganto_port;
            updated_settings.save_packets = settings_draft.save_packets;
            updated_settings.http = settings_draft.http;
            updated_settings.office = settings_draft.office;
            updated_settings.exe = settings_draft.exe;
            updated_settings.pdf = settings_draft.pdf;
            updated_settings.txt = settings_draft.txt;
            updated_settings.vbs = settings_draft.vbs;
            updated_settings.smtp_eml = settings_draft.smtp_eml;
            updated_settings.ftp = settings_draft.ftp;
        }
    }

    updated_node.settings = Some(updated_settings);
}

fn should_broadcast_customer_change(node: &Node) -> Option<u32> {
    let is_review = node
        .settings_draft
        .as_ref()
        .is_some_and(|s| super::is_review(&s.hostname));

    let old_customer_id: Option<u32> = node.settings.as_ref().map(|s| s.customer_id);
    let new_customer_id: Option<u32> = node.settings_draft.as_ref().map(|s| s.customer_id);

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
                        piglet: false,
                        pigletGigantoIp: null,
                        pigletGigantoPort: null,
                        savePackets: false,
                        http: false,
                        office: false,
                        exe: false,
                        pdf: false,
                        txt: false,
                        vbs: false,
                        smtpEml: false,
                        ftp: false,
                        giganto: false,
                        gigantoIngestionIp: null,
                        gigantoIngestionPort: null,
                        gigantoPublishIp: null,
                        gigantoPublishPort: null,
                        gigantoGraphqlIp: null,
                        gigantoGraphqlPort: null,
                        retentionPeriod: null,
                        reconverge: false,
                        hog: false,
                        hogGigantoIp: null,
                        hogGigantoPort: null,
                        protocols: [],
                        sensors: [],
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
                            settings {
                                customerId
                                description
                                hostname
                                piglet
                                giganto
                                reconverge
                                hog
                                protocols
                                sensors
                            }
                            settingsDraft {
                                customerId
                                description
                                hostname
                                piglet
                                giganto
                                reconverge
                                hog
                                protocols
                                sensors
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
                                "settings": null,
                                "settingsDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                    "piglet": false,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
                                    "protocols": [],
                                    "sensors": [],
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
                            settings {
                                customerId
                                description
                                hostname
                                piglet
                                giganto
                                reconverge
                                hog
                                protocols
                                sensors
                            }
                            settingsDraft {
                                customerId
                                description
                                hostname
                                piglet
                                giganto
                                reconverge
                                hog
                                protocols
                                sensors
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
                                "settings": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                    "piglet": false,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
                                    "protocols": [],
                                    "sensors": [],
                                },
                                "settingsDraft": null,
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
                            settings: {
                                customerId: "0",
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                                piglet: false,
                                pigletGigantoIp: null,
                                pigletGigantoPort: null,
                                savePackets: false,
                                http: false,
                                office: false,
                                exe: false,
                                pdf: false,
                                txt: false,
                                vbs: false,
                                smtpEml: false,
                                ftp: false,
                                giganto: false,
                                gigantoIngestionIp: null,
                                gigantoIngestionPort: null,
                                gigantoPublishIp: null,
                                gigantoPublishPort: null,
                                gigantoGraphqlIp: null,
                                gigantoGraphqlPort: null,
                                retentionPeriod: null,
                                reconverge: false,
                                hog: false,
                                hogGigantoIp: null,
                                hogGigantoPort: null,
                                protocols: [],
                                sensors: [],
                            },
                            settingsDraft: null
                        },
                        new: {
                            nameDraft: "admin node with new name",
                            settingsDraft: {
                                customerId: "0",
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                                piglet: false,
                                pigletGigantoIp: null,
                                pigletGigantoPort: null,
                                savePackets: false,
                                http: false,
                                office: false,
                                exe: false,
                                pdf: false,
                                txt: false,
                                vbs: false,
                                smtpEml: false,
                                ftp: false,
                                giganto: false,
                                gigantoIngestionIp: null,
                                gigantoIngestionPort: null,
                                gigantoPublishIp: null,
                                gigantoPublishPort: null,
                                gigantoGraphqlIp: null,
                                gigantoGraphqlPort: null,
                                retentionPeriod: null,
                                reconverge: false,
                                hog: false,
                                hogGigantoIp: null,
                                hogGigantoPort: null,
                                protocols: [],
                                sensors: [],
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
                            settings {
                                customerId
                                description
                                hostname
                                piglet
                                giganto
                                reconverge
                                hog
                                protocols
                                sensors
                            }
                            settingsDraft {
                                customerId
                                description
                                hostname
                                piglet
                                giganto
                                reconverge
                                hog
                                protocols
                                sensors
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
                                "settings": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                    "piglet": false,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
                                    "protocols": [],
                                    "sensors": [],
                                },
                                "settingsDraft": null,
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

    #[tokio::test]
    async fn test_node_apply_with_online_apps() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps("host1", &["piglet"], &mut online_apps_by_host_id);
        insert_apps(
            "host2",
            &["giganto", "hog", "reconverge"],
            &mut online_apps_by_host_id,
        );

        let (send_result_checker, mut recv_result_checker) = mpsc::channel(10);

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
            send_result_checker,
        });

        let schema = TestSchema::new_with(agent_manager, None).await;

        // check empty
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 0}}"#);

        // insert node with piglet
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "node1",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "host1",
                        piglet: true,
                        pigletGigantoIp: "0.0.0.0",
                        pigletGigantoPort: 5555,
                        savePackets: false,
                        http: false,
                        office: false,
                        exe: false,
                        pdf: false,
                        txt: false,
                        vbs: false,
                        smtpEml: false,
                        ftp: false,
                        giganto: false,
                        gigantoIngestionIp: null,
                        gigantoIngestionPort: null,
                        gigantoPublishIp: null,
                        gigantoPublishPort: null,
                        gigantoGraphqlIp: null,
                        gigantoGraphqlPort: null,
                        retentionPeriod: null,
                        reconverge: false,
                        hog: false,
                        hogGigantoIp: null,
                        hogGigantoPort: null,
                        protocols: null,
                        sensors: null,
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
                            settings {
                                customerId
                                description
                                hostname
                                piglet
                                giganto
                                reconverge
                                hog
                            }
                            settingsDraft {
                                customerId
                                description
                                hostname
                                piglet
                                giganto
                                reconverge
                                hog
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
                                "name": "node1",
                                "nameDraft": null,
                                "settings": null,
                                "settingsDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "host1",
                                    "piglet": true,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
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
                    applyNode(id: "0") {
                        id
                        successModules
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{applyNode: {id: "0", successModules: [PIGLET]}}"#
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
                            settings {
                                customerId
                                description
                                hostname
                                piglet
                                giganto
                                reconverge
                                hog
                            }
                            settingsDraft {
                                customerId
                                description
                                hostname
                                piglet
                                giganto
                                reconverge
                                hog
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
                                "name": "node1",
                                "nameDraft": null,
                                "settings": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "host1",
                                    "piglet": true,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
                                },
                                "settingsDraft": null,
                            }
                        }
                    ]
                }
            })
        );

        let mut result_buffer: Vec<String> = Vec::with_capacity(2);
        let size = recv_result_checker.recv_many(&mut result_buffer, 2).await;
        assert_eq!(size, 1);
        assert!(result_buffer.contains(&"piglet@host1".to_string()));
        assert!(!result_buffer.contains(&"review@host1".to_string()));
    }
}
