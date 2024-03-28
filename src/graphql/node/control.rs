use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    ModuleName, NodeControlMutation,
};
use crate::graphql::{customer::broadcast_customer_networks, get_customer_networks};
use async_graphql::{Context, Object, Result, SimpleObject, ID};
use bincode::Options;
use oinq::{
    request::{HogConfig, PigletConfig, ReconvergeConfig},
    RequestCode,
};
use review_database::{Node, NodeSetting};
use std::net::{IpAddr, SocketAddr};
use tracing::{error, info};

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
            // TODO: Refactor this code to use `AgentManager::halt` after
            // `review` implements it. See #144.
            let apps = agents.online_apps_by_host_id().await?;
            let Some(apps) = apps.get(&hostname) else {
                return Err("unable to gather info of online agents".into());
            };
            let Some((key, _)) = apps.first() else {
                return Err("unable to access first of online agents".into());
            };

            let code: u32 = RequestCode::Shutdown.into();
            let msg = bincode::serialize(&code)?;
            let response = agents.send_and_recv(key, &msg).await?;
            let Ok(response) =
                bincode::DefaultOptions::new().deserialize::<Result<(), &str>>(&response)
            else {
                return Ok(hostname);
            };
            response.map_or_else(
                |e| Err(format!("unable to shutdown the system: {e}").into()),
                |()| Ok(hostname),
            )
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

        if node.name_draft.is_none() && node.setting_draft.is_none() {
            return Err("There is nothing to apply.".into());
        }

        let review_config_setted = match &node.setting_draft {
            Some(settings_draft) if settings_draft.review => {
                // TODO: Trigger `set_review_config()`; Configs that can be set
                // for REview are `revew_port` and `review_web_port`.
                // `set_review_config` is expected to exist in REview.
                // `set_review_config()` will write the update to a temporary
                // file. Until the `set_review_config()` is implemented, the
                // `review_config_setted` is temporarily fixed to true, but
                // after implementation, it should be set according to the
                // return value of `set_review_config()`.
                false
            }
            _ => false,
        };
        let config_setted_modules = send_set_config_requests(agents, &node).await;
        let success_modules = if let Ok(mut config_setted_modules) = config_setted_modules {
            if review_config_setted {
                config_setted_modules.push(ModuleName::Review);
            }
            update_node(ctx, i, node.clone(), &config_setted_modules).await?;

            if let Some(customer_id) = should_broadcast_customer_change(&node) {
                broadcast_customer_change(customer_id, ctx).await?;
            }
            config_setted_modules
        } else {
            return Err("Failed to apply node settings".into());
        };

        if review_config_setted {
            // TODO: Spawn a task to trigger `reload_review()` after a few
            // seconds like below. `reload_review()` is expected to exist in
            // REview. It reads the temp file written by `set_review_config()`.
            // At reload, the temporary file replaces the original config file.
            /*
            tokio::spawn(async {
              tokio::time::sleep(std::time::Duration::from_secs(3)).await;
              reload_review();
            });
            */
        }

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
        .setting_draft
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("There is nothing to be applied."))?;

    let mut result_combined: Vec<ModuleName> = vec![];

    for (module_name, config) in target_app_configs(settings_draft)? {
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
    config: &oinq::Config,
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
    settings_draft: &NodeSetting,
) -> anyhow::Result<Vec<(ModuleName, oinq::Config)>> {
    let mut configurations = Vec::new();

    if settings_draft.piglet {
        configurations.push((ModuleName::Piglet, build_piglet_config(settings_draft)?));
    }

    if settings_draft.hog {
        configurations.push((ModuleName::Hog, build_hog_config(settings_draft)?));
    }

    if settings_draft.reconverge {
        configurations.push((
            ModuleName::Reconverge,
            build_reconverge_config(settings_draft)?,
        ));
    }

    Ok(configurations)
}

fn build_piglet_config(settings_draft: &NodeSetting) -> anyhow::Result<oinq::Config> {
    let review_address = build_socket_address(
        settings_draft.piglet_review_ip,
        settings_draft.piglet_review_port,
    )
    .ok_or_else(|| anyhow::anyhow!("piglet review address is not set"))?;

    let giganto_address = build_socket_address(
        settings_draft.piglet_giganto_ip,
        settings_draft.piglet_giganto_port,
    );
    let log_options = build_log_options(settings_draft);
    let http_file_types = build_http_file_types(settings_draft);

    Ok(oinq::Config::Piglet(PigletConfig {
        review_address,
        giganto_address,
        log_options,
        http_file_types,
    }))
}

fn build_hog_config(settings_draft: &NodeSetting) -> anyhow::Result<oinq::Config> {
    let review_address =
        build_socket_address(settings_draft.hog_review_ip, settings_draft.hog_review_port)
            .ok_or_else(|| anyhow::anyhow!("hog review address is not set"))?;
    let giganto_address = build_socket_address(
        settings_draft.hog_giganto_ip,
        settings_draft.hog_giganto_port,
    );
    let active_protocols = build_active_protocols(settings_draft);
    let active_sources = build_active_sources(settings_draft);

    Ok(oinq::Config::Hog(HogConfig {
        review_address,
        giganto_address,
        active_protocols,
        active_sources,
    }))
}

fn build_log_options(settings_draft: &NodeSetting) -> Option<Vec<String>> {
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

fn build_http_file_types(settings_draft: &NodeSetting) -> Option<Vec<String>> {
    let condition_to_http_file_types = [
        (settings_draft.office, "office"),
        (settings_draft.exe, "exe"),
        (settings_draft.pdf, "pdf"),
        (settings_draft.html, "html"),
        (settings_draft.txt, "txt"),
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

fn build_active_protocols(settings_draft: &NodeSetting) -> Option<Vec<String>> {
    if settings_draft.protocols {
        Some(
            settings_draft
                .protocol_list
                .iter()
                .filter_map(|(k, v)| if *v { Some(k.clone()) } else { None })
                .collect::<Vec<String>>(),
        )
    } else {
        None
    }
}

fn build_active_sources(settings_draft: &NodeSetting) -> Option<Vec<String>> {
    if settings_draft.sensors {
        Some(
            settings_draft
                .sensor_list
                .iter()
                .filter_map(|(k, v)| if *v { Some(k.clone()) } else { None })
                .collect::<Vec<String>>(),
        )
    } else {
        None
    }
}

fn build_reconverge_config(settings_draft: &NodeSetting) -> anyhow::Result<oinq::Config> {
    let review_address = build_socket_address(
        settings_draft.reconverge_review_ip,
        settings_draft.reconverge_review_port,
    )
    .ok_or_else(|| anyhow::anyhow!("reconverge review address is not set"))?;

    let giganto_address = build_socket_address(
        settings_draft.reconverge_giganto_ip,
        settings_draft.reconverge_giganto_port,
    );

    Ok(oinq::Config::Reconverge(ReconvergeConfig {
        review_address,
        giganto_address,
    }))
}

fn build_socket_address(ip: Option<IpAddr>, port: Option<u16>) -> Option<SocketAddr> {
    ip.and_then(|ip| port.map(|port| SocketAddr::new(ip, port)))
}

#[allow(clippy::struct_excessive_bools)]
struct ModuleSpecificSettingUpdateIndicator {
    review: bool,
    hog: bool,
    reconverge: bool,
    piglet: bool,
}

impl ModuleSpecificSettingUpdateIndicator {
    fn all_true(&self) -> bool {
        self.review && self.hog && self.reconverge && self.piglet
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

    if let Some(settings_draft) = &updated_node.setting_draft {
        let update_module_specific_settings = ModuleSpecificSettingUpdateIndicator {
            review: okay_to_update_module_specific_settings(
                settings_draft.review,
                config_setted_modules,
                ModuleName::Review,
            ),
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
            updated_node.setting = updated_node.setting_draft.take();
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
    let mut updated_setting = updated_node.setting.take().unwrap_or_default();
    if let Some(settings_draft) = updated_node.setting_draft.as_ref() {
        // These are common node settings fields, that are not tied to specific modules
        updated_setting.customer_id = settings_draft.customer_id;
        updated_setting.description = settings_draft.description.clone();
        updated_setting.hostname = settings_draft.hostname.clone();
    }
    updated_node.setting = Some(updated_setting);
}

fn update_module_specfic_settings(
    updated_node: &mut Node,
    update_module_specific_settings: &ModuleSpecificSettingUpdateIndicator,
) {
    let mut updated_setting = updated_node.setting.take().unwrap_or_default();

    if let Some(settings_draft) = updated_node.setting_draft.as_mut() {
        if update_module_specific_settings.review {
            updated_setting.review = settings_draft.review;
            updated_setting.review_port = settings_draft.review_port;
            updated_setting.review_web_port = settings_draft.review_web_port;
        }

        if update_module_specific_settings.hog {
            updated_setting.hog = settings_draft.hog;
            updated_setting.hog_review_ip = settings_draft.hog_review_ip;
            updated_setting.hog_review_port = settings_draft.hog_review_port;
            updated_setting.hog_giganto_ip = settings_draft.hog_giganto_ip;
            updated_setting.hog_giganto_port = settings_draft.hog_giganto_port;
            updated_setting.protocols = settings_draft.protocols;
            updated_setting.protocol_list = settings_draft.protocol_list.clone();
            updated_setting.sensors = settings_draft.sensors;
            updated_setting.sensor_list = settings_draft.sensor_list.clone();
        }

        if update_module_specific_settings.reconverge {
            updated_setting.reconverge = settings_draft.reconverge;
            updated_setting.reconverge_review_ip = settings_draft.reconverge_review_ip;
            updated_setting.reconverge_review_port = settings_draft.reconverge_review_port;
            updated_setting.reconverge_giganto_ip = settings_draft.reconverge_giganto_ip;
            updated_setting.reconverge_giganto_port = settings_draft.reconverge_giganto_port;
        }

        if update_module_specific_settings.piglet {
            updated_setting.piglet = settings_draft.piglet;
            updated_setting.piglet_review_ip = settings_draft.piglet_review_ip;
            updated_setting.piglet_review_port = settings_draft.piglet_review_port;
            updated_setting.piglet_giganto_ip = settings_draft.piglet_giganto_ip;
            updated_setting.piglet_giganto_port = settings_draft.piglet_giganto_port;
            updated_setting.save_packets = settings_draft.save_packets;
            updated_setting.http = settings_draft.http;
            updated_setting.office = settings_draft.office;
            updated_setting.exe = settings_draft.exe;
            updated_setting.pdf = settings_draft.pdf;
            updated_setting.html = settings_draft.html;
            updated_setting.txt = settings_draft.txt;
            updated_setting.smtp_eml = settings_draft.smtp_eml;
            updated_setting.ftp = settings_draft.ftp;
        }
    }

    updated_node.setting = Some(updated_setting);
}

fn should_broadcast_customer_change(node: &Node) -> Option<u32> {
    let is_review = node.setting_draft.as_ref().is_some_and(|s| s.review);

    let old_customer_id: Option<u32> = node.setting.as_ref().map(|s| s.customer_id);
    let new_customer_id: Option<u32> = node.setting_draft.as_ref().map(|s| s.customer_id);

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
                        review: true,
                        reviewPort: 1111,
                        reviewWebPort: 1112,
                        piglet: false,
                        pigletGigantoIp: null,
                        pigletGigantoPort: null,
                        pigletReviewIp: null,
                        pigletReviewPort: null,
                        savePackets: false,
                        http: false,
                        office: false,
                        exe: false,
                        pdf: false,
                        html: false,
                        txt: false,
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
                        reconvergeReviewIp: null,
                        reconvergeReviewPort: null,
                        reconvergeGigantoIp: null,
                        reconvergeGigantoPort: null,
                        hog: false,
                        hogReviewIp: null,
                        hogReviewPort: null,
                        hogGigantoIp: null,
                        hogGigantoPort: null,
                        protocols: false,
                        protocolList: {},
                        sensors: false,
                        sensorList: {},
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
                                review
                                reviewPort
                                reviewWebPort
                                piglet
                                giganto
                                reconverge
                                hog
                                protocolList
                                sensorList
                            }
                            settingsDraft {
                                customerId
                                description
                                hostname
                                review
                                reviewPort
                                reviewWebPort
                                piglet
                                giganto
                                reconverge
                                hog
                                protocolList
                                sensorList
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
                                    "review": true,
                                    "reviewPort": 1111,
                                    "reviewWebPort": 1112,
                                    "piglet": false,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
                                    "protocolList": {},
                                    "sensorList": {},
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
            r#"{applyNode: {id: "0",successModules: []}}"#
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
                                review
                                reviewPort
                                reviewWebPort
                                piglet
                                giganto
                                reconverge
                                hog
                                protocolList
                                sensorList
                            }
                            settingsDraft {
                                customerId
                                description
                                hostname
                                review
                                reviewPort
                                reviewWebPort
                                piglet
                                giganto
                                reconverge
                                hog
                                protocolList
                                sensorList
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
                                    "review": false,
                                    "reviewPort": null,
                                    "reviewWebPort": null,
                                    "piglet": false,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
                                    "protocolList": {},
                                    "sensorList": {},
                                },
                                "settingsDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                    "review": true,
                                    "reviewPort": 1111,
                                    "reviewWebPort": 1112,
                                    "piglet": false,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
                                    "protocolList": {},
                                    "sensorList": {},
                                },
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
                                review: false,
                                reviewPort: null,
                                reviewWebPort: null,
                                piglet: false,
                                pigletGigantoIp: null,
                                pigletGigantoPort: null,
                                pigletReviewIp: null,
                                pigletReviewPort: null,
                                savePackets: false,
                                http: false,
                                office: false,
                                exe: false,
                                pdf: false,
                                html: false,
                                txt: false,
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
                                reconvergeReviewIp: null,
                                reconvergeReviewPort: null,
                                reconvergeGigantoIp: null,
                                reconvergeGigantoPort: null,
                                hog: false,
                                hogReviewIp: null,
                                hogReviewPort: null,
                                hogGigantoIp: null,
                                hogGigantoPort: null,
                                protocols: false,
                                protocolList: {},
                                sensors: false,
                                sensorList: {},
                            },
                            settingsDraft: {
                                customerId: "0",
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                                review: true,
                                reviewPort: 1111,
                                reviewWebPort: 1112,
                                piglet: false,
                                pigletGigantoIp: null,
                                pigletGigantoPort: null,
                                pigletReviewIp: null,
                                pigletReviewPort: null,
                                savePackets: false,
                                http: false,
                                office: false,
                                exe: false,
                                pdf: false,
                                html: false,
                                txt: false,
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
                                reconvergeReviewIp: null,
                                reconvergeReviewPort: null,
                                reconvergeGigantoIp: null,
                                reconvergeGigantoPort: null,
                                hog: false,
                                hogReviewIp: null,
                                hogReviewPort: null,
                                hogGigantoIp: null,
                                hogGigantoPort: null,
                                protocols: false,
                                protocolList: {},
                                sensors: false,
                                sensorList: {},
                            }
                        },
                        new: {
                            nameDraft: "admin node with new name",
                            settingsDraft: {
                                customerId: "0",
                                description: "This is the admin node running review.",
                                hostname: "admin.aice-security.com",
                                review: true,
                                reviewPort: 2222,
                                reviewWebPort: 2223,
                                piglet: false,
                                pigletGigantoIp: null,
                                pigletGigantoPort: null,
                                pigletReviewIp: null,
                                pigletReviewPort: null,
                                savePackets: false,
                                http: false,
                                office: false,
                                exe: false,
                                pdf: false,
                                html: false,
                                txt: false,
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
                                reconvergeReviewIp: null,
                                reconvergeReviewPort: null,
                                reconvergeGigantoIp: null,
                                reconvergeGigantoPort: null,
                                hog: false,
                                hogReviewIp: null,
                                hogReviewPort: null,
                                hogGigantoIp: null,
                                hogGigantoPort: null,
                                protocols: false,
                                protocolList: {},
                                sensors: false,
                                sensorList: {},
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
            r#"{applyNode: {id: "0",successModules: []}}"#
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
                                review
                                reviewPort
                                reviewWebPort
                                piglet
                                giganto
                                reconverge
                                hog
                                protocolList
                                sensorList
                            }
                            settingsDraft {
                                customerId
                                description
                                hostname
                                review
                                reviewPort
                                reviewWebPort
                                piglet
                                giganto
                                reconverge
                                hog
                                protocolList
                                sensorList
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
                                    "review": false,
                                    "reviewPort": null,
                                    "reviewWebPort": null,
                                    "piglet": false,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
                                    "protocolList": {},
                                    "sensorList": {},
                                },
                                "settingsDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "admin.aice-security.com",
                                    "review": true,
                                    "reviewPort": 2222,
                                    "reviewWebPort": 2223,
                                    "piglet": false,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
                                    "protocolList": {},
                                    "sensorList": {},
                                },
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
        async fn broadcast_to_crusher(&self, _msg: &[u8]) -> Result<(), anyhow::Error> {
            anyhow::bail!("not expected to be called")
        }
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

        async fn send_and_recv(&self, _key: &str, _msg: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
            anyhow::bail!("not expected to be called")
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
        ) -> Result<oinq::Config, anyhow::Error> {
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

        async fn halt(&self, hostname: &str) -> Result<(), anyhow::Error> {
            anyhow::bail!("{hostname} is unreachable")
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
            _config: &oinq::Config,
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

        let schema = TestSchema::new_with(agent_manager).await;

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
        insert_apps("host1", &["review", "piglet"], &mut online_apps_by_host_id);
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

        let schema = TestSchema::new_with(agent_manager).await;

        // check empty
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 0}}"#);

        // insert node with review, piglet
        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "node1",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "host1",
                        review: true,
                        reviewPort: 1111,
                        reviewWebPort: 1112,
                        piglet: true,
                        pigletGigantoIp: "0.0.0.0",
                        pigletGigantoPort: 5555,
                        pigletReviewIp: "0.0.0.0",
                        pigletReviewPort: 1111,
                        savePackets: false,
                        http: false,
                        office: false,
                        exe: false,
                        pdf: false,
                        html: false,
                        txt: false,
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
                        reconvergeReviewIp: null,
                        reconvergeReviewPort: null,
                        reconvergeGigantoIp: null,
                        reconvergeGigantoPort: null,
                        hog: false,
                        hogReviewIp: null,
                        hogReviewPort: null,
                        hogGigantoIp: null,
                        hogGigantoPort: null,
                        protocols: false,
                        protocolList: {},
                        sensors: false,
                        sensorList: {},
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
                                review
                                piglet
                                giganto
                                reconverge
                                hog
                            }
                            settingsDraft {
                                customerId
                                description
                                hostname
                                review
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
                                    "review": true,
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
            r#"{applyNode: {id: "0",successModules: [PIGLET]}}"#
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
                                review
                                piglet
                                giganto
                                reconverge
                                hog
                            }
                            settingsDraft {
                                customerId
                                description
                                hostname
                                review
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
                                    "review": false,
                                    "piglet": true,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
                                },
                                "settingsDraft": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "host1",
                                    "review": true,
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

        let mut result_buffer: Vec<String> = Vec::with_capacity(2);
        let size = recv_result_checker.recv_many(&mut result_buffer, 2).await;
        assert_eq!(size, 1);
        assert!(result_buffer.contains(&"piglet@host1".to_string()));
        assert!(!result_buffer.contains(&"review@host1".to_string()));
    }
}
