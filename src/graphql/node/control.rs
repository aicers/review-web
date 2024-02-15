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
use async_graphql::{Context, Object, Result, SimpleObject, ID};
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
            roxy::reboot().map_or_else(|e| Err(e.to_string().into()), |_| Ok(hostname))
        } else {
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
    async fn apply_node(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<NodeApplyResult> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let node: Node = {
            let store = crate::graphql::get_store(ctx).await?;
            let node_map = store.node_map();
            let node = node_map
                .get_by_id(i)?
                .ok_or_else(|| async_graphql::Error::new(format!("Node with ID {i} not found",)))?;
            bincode::DefaultOptions::new().deserialize(node.as_ref())?
        };

        if node.to_be.is_none() {
            return Err("Cannot apply when `to_be` is None".into());
        }

        let agents = ctx.data::<BoxedAgentManager>()?;
        let set_config_response = send_set_config_requests(agents, &node).await;
        update_node_data(ctx, i, &node).await?;
        if let (true, customer_id) = should_broadcast_customer_change(&node) {
            broadcast_customer_change(customer_id, ctx).await?;
        }

        let result = set_config_response.map(|response| NodeApplyResult {
            id,
            result_by_agent: response,
        })?;
        Ok(result)
    }
}

#[derive(SimpleObject)]
pub struct NodeApplyResult {
    pub id: ID,
    pub result_by_agent: HashMap<String, bool>,
}

async fn send_set_config_requests(
    agents: &BoxedAgentManager,
    node: &Node,
) -> anyhow::Result<HashMap<String, bool>> {
    let online_apps = agents.online_apps_by_host_id().await?;

    let mut result_by_agent: HashMap<String, bool> = HashMap::new();

    if let Some(to_be) = &node.to_be {
        let to_be_hostname = &to_be.hostname;

        for (app_name, config) in target_app_configs(to_be) {
            let agent_key = find_agent_key(&online_apps, to_be_hostname, app_name)?;
            let set_config_response =
                send_set_config_request(agents, agent_key.as_str(), &config).await?;

            if set_config_response {
                result_by_agent.insert(agent_key, true);
            }
        }
    } else {
        bail!("to_be is None");
    }

    Ok(result_by_agent)
}

async fn send_set_config_request(
    agents: &BoxedAgentManager,
    agent_key: &str,
    config: &oinq::Configs,
) -> anyhow::Result<bool> {
    let set_config_request: u32 = RequestCode::SetConfig.into();
    let mut set_config_msg = bincode::serialize(&set_config_request)?;
    set_config_msg.extend(bincode::DefaultOptions::new().serialize(config)?);

    for _ in 0..MAX_SET_CONFIG_TRY_COUNT {
        let set_config_response = agents.send_and_recv(agent_key, &set_config_msg).await;

        if let Ok(response) = set_config_response {
            if let Ok(true) = bincode::deserialize::<bool>(response.as_slice()) {
                return Ok(true);
            }
        }

        info!("set_config_response is not Ok(true). retrying");
    }

    Ok(false)
}

fn target_app_configs(to_be: &NodeSetting) -> Vec<(&str, oinq::Configs)> {
    let mut configurations = Vec::new();

    if to_be.piglet {
        configurations.push((PIGLET_APP_NAME, build_piglet_config(to_be)));
    }

    if to_be.hog {
        configurations.push((HOG_APP_NAME, build_hog_config(to_be)));
    }

    if to_be.reconverge {
        configurations.push((RECONVERGE_APP_NAME, build_reconverge_config(to_be)));
    }

    configurations
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

fn build_piglet_config(to_be: &NodeSetting) -> oinq::Configs {
    let review_address = build_socket_address(to_be.piglet_review_ip, to_be.piglet_review_port);
    let giganto_address = build_socket_address(to_be.piglet_giganto_ip, to_be.piglet_giganto_port);
    let log_options = build_log_options(to_be);
    let http_file_types = build_http_file_types(to_be);

    oinq::Configs::Piglet(PigletConfig {
        review_address,
        giganto_address,
        log_options,
        http_file_types,
    })
}

fn build_hog_config(to_be: &NodeSetting) -> oinq::Configs {
    let review_address = build_socket_address(to_be.hog_review_ip, to_be.hog_review_port);
    let active_protocols = build_active_protocols(to_be);
    let active_sources = build_active_sources(to_be);

    oinq::Configs::Hog(HogConfig {
        review_address,
        active_protocols,
        active_sources,
    })
}

fn build_log_options(to_be: &NodeSetting) -> Option<Vec<String>> {
    let condition_to_log_option = [
        (to_be.save_packets, "dump"),
        (to_be.http, "http"),
        (to_be.smtp_eml, "eml"),
        (to_be.ftp, "ftp"),
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

fn build_http_file_types(to_be: &NodeSetting) -> Option<Vec<String>> {
    let condition_to_http_file_types = [
        (to_be.office, "office"),
        (to_be.exe, "exe"),
        (to_be.pdf, "pdf"),
        (to_be.html, "html"),
        (to_be.txt, "txt"),
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

fn build_active_protocols(to_be: &NodeSetting) -> Option<Vec<String>> {
    if to_be.protocols {
        Some(
            to_be
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

fn build_active_sources(to_be: &NodeSetting) -> Option<Vec<String>> {
    if to_be.sensors {
        Some(
            to_be
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

fn build_reconverge_config(to_be: &NodeSetting) -> oinq::Configs {
    let review_address =
        build_socket_address(to_be.reconverge_review_ip, to_be.reconverge_review_port);
    let giganto_address =
        build_socket_address(to_be.reconverge_giganto_ip, to_be.reconverge_giganto_port);

    oinq::Configs::Reconverge(ReconvergeConfig {
        review_address,
        giganto_address,
    })
}

fn build_socket_address(ip: Option<IpAddr>, port: Option<u16>) -> Option<SocketAddr> {
    ip.and_then(|ip| port.map(|port| SocketAddr::new(ip, port)))
}

async fn update_node_data(ctx: &Context<'_>, i: u32, node: &Node) -> Result<()> {
    let mut new_node = node.clone();
    new_node.as_is = new_node.to_be.take();

    let store = crate::graphql::get_store(ctx).await?;
    let map = store.node_map();
    Ok(map.update(i, node, &new_node)?)
}

fn should_broadcast_customer_change(node: &Node) -> (bool, u32) {
    match (node.as_is.as_ref(), node.to_be.as_ref()) {
        (None, Some(to_be)) => (to_be.review, to_be.customer_id),
        (Some(as_is), Some(to_be)) => (
            to_be.review && to_be.customer_id != as_is.customer_id,
            to_be.customer_id,
        ),
        (_, None) => panic!("When `to_be` is None, this function should not be called"),
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
