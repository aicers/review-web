use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use crate::graphql::{customer::broadcast_customer_networks, get_customer_networks};

use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    Node, NodeControlMutation, NodeSetting,
};
use anyhow::bail;
use async_graphql::{Context, Object, Result, ID};
use bincode::Options;
use oinq::{
    request::{HogConfig, PigletConfig, ReconvergeConfig},
    RequestCode,
};
use review_database::Indexed;
use tracing::{error, info};

const MAX_SET_CONFIG_TRY_COUNT: i32 = 3;
const PIGLET_APP_NAME: &str = "piglet";
const HOG_APP_NAME: &str = "hog";
const RECONVERGE_APP_NAME: &str = "reconverge";

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
            // TODO: Refactor this code to use `AgentManager::reboot` after
            // `review` implements it. See #144.
            let apps = agents.online_apps_by_host_id().await?;
            let Some(apps) = apps.get(&hostname) else {
                return Err("unable to gather info of online agents".into());
            };
            let Some((key, _)) = apps.first() else {
                return Err("unable to access first of online agents".into());
            };

            let code: u32 = RequestCode::Reboot.into();
            let msg = bincode::serialize(&code)?;
            let response = agents.send_and_recv(key, &msg).await?;
            let Ok(response) =
                bincode::DefaultOptions::new().deserialize::<Result<(), &str>>(&response)
            else {
                // Since the node turns off, deserialization fails.
                return Ok(hostname);
            };
            response.map_or_else(
                |e| Err(format!("unable to reboot the system: {e}").into()),
                |()| Ok(hostname),
            )
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
    async fn apply_node(&self, ctx: &Context<'_>, id: ID) -> async_graphql::Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let node: Node = {
            let store = crate::graphql::get_store(ctx).await?;
            let node_map = store.node_map();
            node_map
                .get_by_id(i)?
                .ok_or_else(|| async_graphql::Error::new(format!("Node with ID {i} not found",)))?
        };
        if node.setting_draft.is_none() {
            return Err("Cannot apply when `setting_draft` is None".into());
        }

        let agents = ctx.data::<BoxedAgentManager>()?;
        if send_set_config_requests(agents, &node).await? {
            update_node_data(ctx, i, &node).await?;
            if let (true, customer_id) = should_broadcast_customer_change(&node) {
                broadcast_customer_change(customer_id, ctx).await?;
            }
            Ok(id)
        } else {
            Err("Failed to apply node setting".into())
        }
    }
}

async fn send_set_config_requests(agents: &BoxedAgentManager, node: &Node) -> anyhow::Result<bool> {
    let online_apps = agents.online_apps_by_host_id().await?;

    let mut result_combined: bool = true;

    if let Some(setting_draft) = &node.setting_draft {
        let hostname_draft = &setting_draft.hostname;

        for (app_name, config) in target_app_configs(setting_draft)? {
            let agent_key = find_agent_key(&online_apps, hostname_draft, app_name)?;
            let result = send_set_config_request(agents, agent_key.as_str(), &config).await?;
            result_combined = result_combined && result;
        }
    } else {
        bail!("`setting_draft` is None");
    }

    Ok(result_combined)
}

async fn send_set_config_request(
    agents: &BoxedAgentManager,
    agent_key: &str,
    config: &oinq::Config,
) -> anyhow::Result<bool> {
    let set_config_request: u32 = RequestCode::SetConfig.into();
    let mut set_config_msg = bincode::serialize(&set_config_request)?;
    set_config_msg.extend(bincode::DefaultOptions::new().serialize(config)?);

    for _ in 0..MAX_SET_CONFIG_TRY_COUNT {
        let set_config_response = agents.send_and_recv(agent_key, &set_config_msg).await;

        if let Ok(response) = set_config_response {
            if response.is_empty() {
                return Ok(true);
            }
        }

        info!("set_config_response is not Ok(true). retrying");
    }

    Ok(false)
}

fn target_app_configs(setting_draft: &NodeSetting) -> anyhow::Result<Vec<(&str, oinq::Config)>> {
    let mut configurations = Vec::new();

    if setting_draft.piglet {
        configurations.push((PIGLET_APP_NAME, build_piglet_config(setting_draft)?));
    }

    if setting_draft.hog {
        configurations.push((HOG_APP_NAME, build_hog_config(setting_draft)?));
    }

    if setting_draft.reconverge {
        configurations.push((RECONVERGE_APP_NAME, build_reconverge_config(setting_draft)?));
    }

    Ok(configurations)
}

fn find_agent_key(
    online_apps: &HashMap<String, Vec<(String, String)>>,
    hostname: &str,
    app_name: &str,
) -> anyhow::Result<String> {
    online_apps
        .get(hostname)
        .and_then(|v| v.iter().find(|(_, name)| *name == app_name))
        .map(|(k, _)| k.clone())
        .ok_or_else(|| anyhow::anyhow!("{} agent not found", app_name))
}

fn build_piglet_config(setting_draft: &NodeSetting) -> anyhow::Result<oinq::Config> {
    let review_address = build_socket_address(
        setting_draft.piglet_review_ip,
        setting_draft.piglet_review_port,
    )
    .ok_or_else(|| anyhow::anyhow!("piglet review address is not set"))?;

    let giganto_address = build_socket_address(
        setting_draft.piglet_giganto_ip,
        setting_draft.piglet_giganto_port,
    );
    let log_options = build_log_options(setting_draft);
    let http_file_types = build_http_file_types(setting_draft);

    Ok(oinq::Config::Piglet(PigletConfig {
        review_address,
        giganto_address,
        log_options,
        http_file_types,
    }))
}

fn build_hog_config(setting_draft: &NodeSetting) -> anyhow::Result<oinq::Config> {
    let review_address =
        build_socket_address(setting_draft.hog_review_ip, setting_draft.hog_review_port)
            .ok_or_else(|| anyhow::anyhow!("hog review address is not set"))?;
    let giganto_address =
        build_socket_address(setting_draft.hog_giganto_ip, setting_draft.hog_giganto_port);
    let active_protocols = build_active_protocols(setting_draft);
    let active_sources = build_active_sources(setting_draft);

    Ok(oinq::Config::Hog(HogConfig {
        review_address,
        giganto_address,
        active_protocols,
        active_sources,
    }))
}

fn build_log_options(setting_draft: &NodeSetting) -> Option<Vec<String>> {
    let condition_to_log_option = [
        (setting_draft.save_packets, "dump"),
        (setting_draft.http, "http"),
        (setting_draft.smtp_eml, "eml"),
        (setting_draft.ftp, "ftp"),
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

fn build_http_file_types(setting_draft: &NodeSetting) -> Option<Vec<String>> {
    let condition_to_http_file_types = [
        (setting_draft.office, "office"),
        (setting_draft.exe, "exe"),
        (setting_draft.pdf, "pdf"),
        (setting_draft.html, "html"),
        (setting_draft.txt, "txt"),
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

fn build_active_protocols(setting_draft: &NodeSetting) -> Option<Vec<String>> {
    if setting_draft.protocols {
        Some(
            setting_draft
                .protocol_list
                .iter()
                .filter(|(_, v)| **v)
                .map(|(k, _)| k.clone())
                .collect::<Vec<String>>(),
        )
    } else {
        None
    }
}

fn build_active_sources(setting_draft: &NodeSetting) -> Option<Vec<String>> {
    if setting_draft.sensors {
        Some(
            setting_draft
                .sensor_list
                .iter()
                .filter(|(_, v)| **v)
                .map(|(k, _)| k.clone())
                .collect::<Vec<String>>(),
        )
    } else {
        None
    }
}

fn build_reconverge_config(setting_draft: &NodeSetting) -> anyhow::Result<oinq::Config> {
    let review_address = build_socket_address(
        setting_draft.reconverge_review_ip,
        setting_draft.reconverge_review_port,
    )
    .ok_or_else(|| anyhow::anyhow!("reconverge review address is not set"))?;

    let giganto_address = build_socket_address(
        setting_draft.reconverge_giganto_ip,
        setting_draft.reconverge_giganto_port,
    );

    Ok(oinq::Config::Reconverge(ReconvergeConfig {
        review_address,
        giganto_address,
    }))
}

fn build_socket_address(ip: Option<IpAddr>, port: Option<u16>) -> Option<SocketAddr> {
    ip.and_then(|ip| port.map(|port| SocketAddr::new(ip, port)))
}

async fn update_node_data(ctx: &Context<'_>, i: u32, node: &Node) -> Result<()> {
    let mut new_node = node.clone();
    new_node.name = new_node.name_draft.take().unwrap_or(new_node.name);
    new_node.setting = new_node.setting_draft.take();

    let store = crate::graphql::get_store(ctx).await?;
    let map = store.node_map();
    Ok(map.update(i, node, &new_node)?)
}

fn should_broadcast_customer_change(node: &Node) -> (bool, u32) {
    match (node.setting.as_ref(), node.setting_draft.as_ref()) {
        (None, Some(setting_draft)) => (setting_draft.review, setting_draft.customer_id),
        (Some(setting), Some(setting_draft)) => (
            setting_draft.review && setting_draft.customer_id != setting.customer_id,
            setting_draft.customer_id,
        ),
        (_, None) => {
            error!("When `setting_draft` is None, this function should not be called. Returning (false, _) to avoid broadcasting customer change.");
            (false, u32::MAX)
        }
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

    use crate::graphql::{AgentManager, BoxedAgentManager, TestSchema};

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
                            setting {
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
                            settingDraft {
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
                                "setting": null,
                                "settingDraft": {
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
                        applyNode(id: "0")
                    }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

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
                            setting {
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
                            settingDraft {
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
                                "setting": {
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
                                "settingDraft": null,
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
                    updateNode(
                        id: "0"
                        old: {
                            name: "admin node",
                            nameDraft: null,
                            setting: {
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
                            },
                            settingDraft: null
                        },
                        new: {
                            name: "admin node",
                            nameDraft: "admin node with new name",
                            setting: {
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
                            },
                            settingDraft: {
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
        assert_eq!(res.data.to_string(), r#"{updateNode: "0"}"#);

        // apply node
        let res = schema
            .execute(
                r#"mutation {
            applyNode(id: "0")
        }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

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
                            setting {
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
                            settingDraft {
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
                                "setting": {
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
                                "settingDraft": null,
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

        async fn send_and_recv(&self, key: &str, _msg: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
            self.insert_result(key).await;
            Ok(vec![])
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
                            setting {
                                customerId
                                description
                                hostname
                                review
                                piglet
                                giganto
                                reconverge
                                hog
                            }
                            settingDraft {
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
                                "setting": null,
                                "settingDraft": {
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
                        applyNode(id: "0")
                    }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{applyNode: "0"}"#);

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
                            setting {
                                customerId
                                description
                                hostname
                                review
                                piglet
                                giganto
                                reconverge
                                hog
                            }
                            settingDraft {
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
                                "setting": {
                                    "customerId": "0",
                                    "description": "This is the admin node running review.",
                                    "hostname": "host1",
                                    "review": true,
                                    "piglet": true,
                                    "giganto": false,
                                    "reconverge": false,
                                    "hog": false,
                                },
                                "settingDraft": null,
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
