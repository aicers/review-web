#![allow(clippy::fn_params_excessive_bools)]

use crate::graphql::{customer::broadcast_customer_networks, get_customer_networks};

use super::{
    super::{Role, RoleGuard},
    Node, NodeInput, NodeMutation, NodeQuery, NodeTotalCount, PortNumber, ServerAddress,
    ServerPort, Setting,
};
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    types::ID,
    Context, Object, Result,
};
use bincode::Options;
use chrono::Utc;
use review_database::{Indexed, IterableMap, Store};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tracing::error;

#[Object]
impl NodeQuery {
    /// A list of nodes.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Node, NodeTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    /// A node for the given ID.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node(&self, ctx: &Context<'_>, id: ID) -> Result<Node> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.node_map();
        let Some(value) = map.get_by_id(i)? else {
            return Err("no such node".into());
        };
        Ok(bincode::DefaultOptions::new()
            .deserialize(value.as_ref())
            .map_err(|_| "invalid value in database")?)
    }
}

#[Object]
impl NodeMutation {
    /// Inserts a new node, returning the ID of the new node.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    async fn insert_node(
        &self,
        ctx: &Context<'_>,
        name: String,
        customer_id: ID,
        description: String,
        hostname: String,

        review: bool,
        review_port: Option<PortNumber>,
        review_web_port: Option<PortNumber>,

        piglet: bool,
        piglet_giganto_ip: Option<String>,
        piglet_giganto_port: Option<PortNumber>,
        piglet_review_ip: Option<String>,
        piglet_review_port: Option<PortNumber>,
        save_packets: bool,
        http: bool,
        office: bool,
        exe: bool,
        pdf: bool,
        html: bool,
        txt: bool,
        smtp_eml: bool,
        ftp: bool,

        giganto: bool,
        giganto_ingestion_ip: Option<String>,
        giganto_ingestion_port: Option<PortNumber>,
        giganto_publish_ip: Option<String>,
        giganto_publish_port: Option<PortNumber>,
        giganto_graphql_ip: Option<String>,
        giganto_graphql_port: Option<PortNumber>,
        retention_period: Option<u16>,

        reconverge: bool,
        reconverge_review_ip: Option<String>,
        reconverge_review_port: Option<PortNumber>,
        reconverge_giganto_ip: Option<String>,
        reconverge_giganto_port: Option<PortNumber>,

        hog: bool,
        hog_review_ip: Option<String>,
        hog_review_port: Option<PortNumber>,
        hog_giganto_ip: Option<String>,
        hog_giganto_port: Option<PortNumber>,
        protocols: bool,
        protocol_list: HashMap<String, bool>,
        sensors: bool,
        sensor_list: HashMap<String, bool>,
    ) -> Result<ID> {
        let (id, customer_id) = {
            let store = crate::graphql::get_store(ctx).await?;
            let map = store.node_map();
            let customer_id = customer_id
                .as_str()
                .parse::<u32>()
                .map_err(|_| "invalid customer ID")?;
            let piglet_giganto_ip = if let Some(ip) = piglet_giganto_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: storage")?,
                )
            } else {
                None
            };
            let piglet_review_ip = if let Some(ip) = piglet_review_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: administration")?,
                )
            } else {
                None
            };
            let giganto_ingestion_ip = if let Some(ip) = giganto_ingestion_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: receiving")?,
                )
            } else {
                None
            };
            let giganto_publish_ip = if let Some(ip) = giganto_publish_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: sending")?,
                )
            } else {
                None
            };
            let giganto_graphql_ip = if let Some(ip) = giganto_graphql_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: web")?,
                )
            } else {
                None
            };
            let reconverge_review_ip = if let Some(ip) = reconverge_review_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: administration")?,
                )
            } else {
                None
            };
            let reconverge_giganto_ip = if let Some(ip) = reconverge_giganto_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: storage")?,
                )
            } else {
                None
            };
            let hog_review_ip = if let Some(ip) = hog_review_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: administration")?,
                )
            } else {
                None
            };
            let hog_giganto_ip = if let Some(ip) = hog_giganto_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: storage")?,
                )
            } else {
                None
            };

            let value = Node {
                id: u32::MAX,
                customer_id,
                name,
                description,
                hostname,

                review,
                review_port,
                review_web_port,

                piglet,
                piglet_giganto_ip,
                piglet_giganto_port,
                piglet_review_ip,
                piglet_review_port,
                save_packets,
                http,
                office,
                exe,
                pdf,
                html,
                txt,
                smtp_eml,
                ftp,

                giganto,
                giganto_ingestion_ip,
                giganto_ingestion_port,
                giganto_publish_ip,
                giganto_publish_port,
                giganto_graphql_ip,
                giganto_graphql_port,
                retention_period,

                reconverge,
                reconverge_review_ip,
                reconverge_review_port,
                reconverge_giganto_ip,
                reconverge_giganto_port,

                hog,
                hog_review_ip,
                hog_review_port,
                hog_giganto_ip,
                hog_giganto_port,
                protocols,
                protocol_list,
                sensors,
                sensor_list,

                creation_time: Utc::now(),

                apply_target_id: None,
                apply_in_progress: false,
            };
            let id = map.insert(value)?;
            (id, customer_id)
        };
        if review {
            let store = crate::graphql::get_store(ctx).await?;

            if let Ok(networks) = get_customer_networks(&store, customer_id) {
                if let Err(e) = broadcast_customer_networks(ctx, &networks).await {
                    error!("failed to broadcast internal networks. {e:?}");
                }
            }
        }
        Ok(ID(id.to_string()))
    }

    /// Removes nodes, returning the node keys that no longer exist.
    ///
    /// On error, some nodes may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_nodes(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.node_map();

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let key = map.remove(i)?;

            let name = match String::from_utf8(key) {
                Ok(key) => key,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
            };
            removed.push(name);
        }
        Ok(removed)
    }

    /// Updates the given node, returning the node ID that was updated.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_node(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: NodeInput,
        new: NodeInput,
    ) -> Result<ID> {
        let (review, customer_is_changed, customer_id) = {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

            let store = crate::graphql::get_store(ctx).await?;
            let map = store.node_map();
            map.update(i, &old, &new)?;

            (
                new.review,
                new.customer_id != old.customer_id,
                new.customer_id,
            )
        };

        if review && customer_is_changed {
            if let Ok(customer_id) = customer_id.as_str().parse::<u32>() {
                let store = crate::graphql::get_store(ctx).await?;

                if let Ok(networks) = get_customer_networks(&store, customer_id) {
                    if let Err(e) = broadcast_customer_networks(ctx, &networks).await {
                        error!("failed to broadcast internal networks. {e:?}");
                    }
                }
            }
        }

        Ok(id)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Node, NodeTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.node_map();
    super::super::load(&map, after, before, first, last, NodeTotalCount)
}

/// Returns the node settings.
///
/// # Errors
///
/// Returns an error if the node settings could not be retrieved.
pub fn get_node_settings(db: &Store) -> Result<Vec<Setting>> {
    let map = db.node_map();
    let mut output = Vec::new();
    for (_key, value) in map.iter_forward()? {
        let node = bincode::DefaultOptions::new()
            .deserialize::<Node>(value.as_ref())
            .map_err(|_| "invalid value in database")?;

        let piglet: Option<ServerAddress> = if node.piglet {
            Some(ServerAddress {
                web: None,
                rpc: Some(SocketAddr::new(
                    node.piglet_review_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node.piglet_review_port.unwrap_or_default(),
                )),
                public: Some(SocketAddr::new(
                    node.piglet_giganto_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node.piglet_giganto_port.unwrap_or_default(),
                )),
                ing: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            })
        } else {
            None
        };
        let giganto = if node.giganto {
            Some(ServerAddress {
                web: Some(SocketAddr::new(
                    node.giganto_graphql_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node.giganto_graphql_port.unwrap_or_default(),
                )),
                rpc: None,
                public: Some(SocketAddr::new(
                    node.giganto_publish_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node.giganto_publish_port.unwrap_or_default(),
                )),
                ing: Some(SocketAddr::new(
                    node.giganto_ingestion_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node.giganto_ingestion_port.unwrap_or_default(),
                )),
            })
        } else {
            None
        };

        let review = if node.review {
            Some(ServerPort {
                rpc_port: node.review_port.unwrap_or_default(),
                web_port: node.review_web_port.unwrap_or_default(),
            })
        } else {
            None
        };
        let reconverge = if node.reconverge {
            Some(ServerAddress {
                web: None,
                rpc: Some(SocketAddr::new(
                    node.reconverge_review_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node.reconverge_review_port.unwrap_or_default(),
                )),
                public: Some(SocketAddr::new(
                    node.reconverge_giganto_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node.reconverge_giganto_port.unwrap_or_default(),
                )),
                ing: None,
            })
        } else {
            None
        };
        let hog = if node.hog {
            Some(ServerAddress {
                web: None,
                rpc: Some(SocketAddr::new(
                    node.hog_review_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node.hog_review_port.unwrap_or_default(),
                )),
                public: Some(SocketAddr::new(
                    node.hog_giganto_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node.hog_giganto_port.unwrap_or_default(),
                )),
                ing: None,
            })
        } else {
            None
        };

        output.push(Setting {
            name: node.hostname,
            piglet,
            giganto,
            hog,
            reconverge,
            review,
        });
    }

    Ok(output)
}

/// Returns the customer id of review node.
///
/// # Errors
///
/// Returns an error if the node settings could not be retrieved.
#[allow(clippy::module_name_repetitions)]
pub fn get_customer_id_of_review_host(db: &Store) -> Result<Option<u32>> {
    let map = db.node_map();
    for (_key, value) in map.iter_forward()? {
        let node = bincode::DefaultOptions::new()
            .deserialize::<Node>(value.as_ref())
            .map_err(|_| "invalid value in database")?;
        if node.review {
            return Ok(Some(node.customer_id));
        }
    }
    Ok(None)
}
