#![allow(clippy::fn_params_excessive_bools)]

use crate::graphql::{customer::broadcast_customer_networks, get_customer_networks};

use super::{
    super::{Role, RoleGuard},
    Nic, NicInput, Node, NodeInput, NodeMutation, NodeQuery, NodeTotalCount, PortNumber,
    ServerAddress, Setting,
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
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
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
            |after, before, first, last| async move { load(ctx, after, before, first, last) },
        )
        .await
    }

    /// A node for the given ID.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node(&self, ctx: &Context<'_>, id: ID) -> Result<Node> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let db = ctx.data::<Arc<Store>>()?;
        let map = db.node_map();
        let Some(value) = map.get_by_id(i)? else {
           return Err("no such node".into())
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
        nics: Vec<NicInput>,
        disk_usage_limit: Option<f32>,
        allow_access_from: Option<Vec<String>>,

        review_id: Option<ID>,

        // TODO: change to "ssh_port: Option<PortNumber>"
        ssh_port: PortNumber,
        dns_server_ip: Option<String>,
        dns_server_port: Option<PortNumber>,
        syslog_server_ip: Option<String>,
        syslog_server_port: Option<PortNumber>,

        review: bool,
        review_nics: Option<Vec<String>>,
        review_port: Option<PortNumber>,
        review_web_port: Option<PortNumber>,
        ntp_server_ip: Option<String>,
        ntp_server_port: Option<PortNumber>,

        piglet: bool,

        giganto: bool,
        giganto_ingestion_nics: Option<Vec<String>>,
        giganto_ingestion_port: Option<PortNumber>,
        giganto_publish_nics: Option<Vec<String>>,
        giganto_publish_port: Option<PortNumber>,
        giganto_graphql_nics: Option<Vec<String>>,
        giganto_graphql_port: Option<PortNumber>,

        reconverge: bool,

        hog: bool,
    ) -> Result<ID> {
        let (id, customer_id, review) = {
            let db = ctx.data::<Arc<Store>>()?;
            let map = db.node_map();
            let customer_id = customer_id
                .as_str()
                .parse::<u32>()
                .map_err(|_| "invalid customer ID")?;
            let mut new_nics = Vec::<Nic>::with_capacity(nics.len());
            for n in nics {
                new_nics.push(n.try_into().map_err(|_| "invalid IP address: nic")?);
            }
            let original_count = new_nics.len();
            new_nics.sort_by(|a, b| a.name.cmp(&b.name));
            new_nics.dedup_by(|a, b| a.name == b.name);
            if new_nics.len() != original_count {
                return Err("duplicate network interface name".into());
            }
            let allow_access_from = if let Some(allow_access_from) = allow_access_from {
                let mut new_allow = Vec::<IpAddr>::new();
                for ip in allow_access_from {
                    new_allow.push(
                        ip.as_str()
                            .parse::<IpAddr>()
                            .map_err(|_| "invalid IP address: access")?,
                    );
                }
                new_allow.sort_unstable();
                new_allow.dedup();
                Some(new_allow)
            } else {
                None
            };
            let review_id = if let Some(id) = review_id {
                Some(id.parse::<u32>().map_err(|_| "invalid review ID")?)
            } else {
                None
            };
            let dns_server_ip = if let Some(ip) = dns_server_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: dns server")?,
                )
            } else {
                None
            };
            let syslog_server_ip = if let Some(ip) = syslog_server_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: syslog server")?,
                )
            } else {
                None
            };
            let ntp_server_ip = if let Some(ip) = ntp_server_ip {
                Some(
                    ip.as_str()
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid IP address: ntp server")?,
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
                nics: new_nics,
                disk_usage_limit,
                allow_access_from,

                review_id,

                ssh_port,
                dns_server_ip,
                dns_server_port,
                syslog_server_ip,
                syslog_server_port,

                review,
                review_nics,
                review_port,
                review_web_port,
                ntp_server_ip,
                ntp_server_port,

                piglet,

                giganto,
                giganto_ingestion_nics,
                giganto_ingestion_port,
                giganto_publish_nics,
                giganto_publish_port,
                giganto_graphql_nics,
                giganto_graphql_port,

                reconverge,

                hog,

                creation_time: Utc::now(),
            };
            let id = map.insert(value)?;
            (id, customer_id, review)
        };
        if review {
            let db = ctx.data::<Arc<Store>>()?;
            if let Ok(networks) = get_customer_networks(db, customer_id) {
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
        let map = ctx.data::<Arc<Store>>()?.node_map();

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
    async fn replace_node(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: NodeInput,
        new: NodeInput,
    ) -> Result<ID> {
        let (review, customer_is_changed, customer_id) = {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

            let db = ctx.data::<Arc<Store>>()?;
            let map = db.node_map();
            map.update(i, &old, &new)?;

            (
                new.review,
                new.customer_id != old.customer_id,
                new.customer_id,
            )
        };

        if review && customer_is_changed {
            if let Ok(customer_id) = customer_id.as_str().parse::<u32>() {
                let db = ctx.data::<Arc<Store>>()?;
                if let Ok(networks) = get_customer_networks(db, customer_id) {
                    if let Err(e) = broadcast_customer_networks(ctx, &networks).await {
                        error!("failed to broadcast internal networks. {e:?}");
                    }
                }
            }
        }

        Ok(id)
    }
}

fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Node, NodeTotalCount, EmptyFields>> {
    let db = ctx.data::<Arc<Store>>()?;
    let map = db.node_map();
    super::super::load(&map, after, before, first, last, NodeTotalCount)
}

/// Returns the node settings.
///
/// # Errors
///
/// Returns an error if the node settings could not be retrieved.
pub fn get_node_settings(db: &Arc<Store>) -> Result<Vec<Setting>> {
    let map = db.node_map();
    let mut output = Vec::new();
    for (_key, value) in map.iter_forward()? {
        let node = bincode::DefaultOptions::new()
            .deserialize::<Node>(value.as_ref())
            .map_err(|_| "invalid value in database")?;

        let accesslist = node.allow_access_from.clone();
        let giganto = if node.giganto {
            Some(ServerAddress {
                web_addr: get_sockaddr(
                    &node.nics,
                    &node.giganto_graphql_nics,
                    node.giganto_graphql_port.unwrap_or_default(),
                ),
                rpc_addr: get_sockaddr(
                    &node.nics,
                    &node.giganto_ingestion_nics,
                    node.giganto_ingestion_port.unwrap_or_default(),
                ),
                pub_addr: get_sockaddr(
                    &node.nics,
                    &node.giganto_publish_nics,
                    node.giganto_publish_port.unwrap_or_default(),
                ),
            })
        } else {
            None
        };
        let ntp = if let Some(ntp_server_ip) = node.ntp_server_ip {
            Some(SocketAddr::new(
                ntp_server_ip,
                node.ntp_server_port.unwrap_or_default(),
            ))
        } else {
            None
        };
        let review = if node.review {
            Some(ServerAddress {
                web_addr: get_sockaddr(
                    &node.nics,
                    &node.review_nics,
                    node.review_web_port.unwrap_or_default(),
                ),
                rpc_addr: get_sockaddr(
                    &node.nics,
                    &node.review_nics,
                    node.review_port.unwrap_or_default(),
                ),
                pub_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            })
        } else {
            None
        };
        let ssh = if node.ssh_port > 0 {
            Some(node.ssh_port)
        } else {
            None
        };
        // TODO: multiple syslog servers should be configurable.
        let syslog = if let Some(syslog_server_ip) = node.syslog_server_ip {
            Some(vec![(
                true,
                SocketAddr::new(
                    syslog_server_ip,
                    node.syslog_server_port.unwrap_or_default(),
                ),
            )])
        } else {
            None
        };

        output.push(Setting {
            name: node.hostname,
            nics: node.nics,
            accesslist,
            disklimit: node.disk_usage_limit.unwrap_or_default(),
            giganto,
            hog: node.hog,
            ntp,
            piglet: node.piglet,
            reconverge: node.reconverge,
            review,
            ssh,
            syslog,
        });
    }

    Ok(output)
}

// if target has multiple values, it assumes that the server address was chosen as 0.0.0.0 address
fn get_sockaddr(nics: &[Nic], target: &Option<Vec<String>>, port: PortNumber) -> SocketAddr {
    let mut ret = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    if let Some(target_nics) = &target {
        if target_nics.len() == 1 {
            if let Some(first) = target_nics.first() {
                ret = nics.iter().find(|nic| &nic.name == first).map_or(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                    |nic| SocketAddr::new(IpAddr::V4(nic.interface.addr()), port),
                );
            }
        }
    }
    ret
}

/// Returns the customer id of review node.
///
/// # Errors
///
/// Returns an error if the node settings could not be retrieved.
#[allow(clippy::module_name_repetitions)]
pub fn get_customer_id_of_review_host(db: &Arc<Store>) -> Result<Option<u32>> {
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
