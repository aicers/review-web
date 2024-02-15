#![allow(clippy::fn_params_excessive_bools)]

use crate::graphql::{customer::broadcast_customer_networks, get_customer_networks};

use super::{
    super::{Role, RoleGuard},
    Node, NodeInput, NodeMutation, NodeQuery, NodeSetting, NodeTotalCount, PortNumber,
};
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    types::ID,
    Context, Object, Result,
};
use bincode::Options;
use chrono::Utc;
use review_database::{Indexed, IterableMap, Store};
use std::{collections::HashMap, net::IpAddr};
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

fn parse_str_to_ip<'em>(
    ip_str: Option<&str>,
    error_message: &'em str,
) -> Result<Option<IpAddr>, &'em str> {
    match ip_str {
        Some(ip_str) => ip_str
            .parse::<IpAddr>()
            .map(Some)
            .map_err(|_| error_message),
        None => Ok(None),
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

            let value = Node {
                id: u32::MAX,
                creation_time: Utc::now(),
                as_is: None,
                to_be: Some(NodeSetting {
                    name,
                    customer_id,
                    description,
                    hostname,

                    review,
                    review_port,
                    review_web_port,

                    piglet,
                    piglet_giganto_ip: parse_str_to_ip(
                        piglet_giganto_ip.as_deref(),
                        "invalid IP address: storage",
                    )?,
                    piglet_giganto_port,
                    piglet_review_ip: parse_str_to_ip(
                        piglet_review_ip.as_deref(),
                        "invalid IP address: administration",
                    )?,
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
                    giganto_ingestion_ip: parse_str_to_ip(
                        giganto_ingestion_ip.as_deref(),
                        "invalid IP address: receiving",
                    )?,
                    giganto_ingestion_port,
                    giganto_publish_ip: parse_str_to_ip(
                        giganto_publish_ip.as_deref(),
                        "invalid IP address: sending",
                    )?,
                    giganto_publish_port,
                    giganto_graphql_ip: parse_str_to_ip(
                        giganto_graphql_ip.as_deref(),
                        "invalid IP address: web",
                    )?,
                    giganto_graphql_port,
                    retention_period,

                    reconverge,
                    reconverge_review_ip: parse_str_to_ip(
                        reconverge_review_ip.as_deref(),
                        "invalid IP address: administration",
                    )?,
                    reconverge_review_port,
                    reconverge_giganto_ip: parse_str_to_ip(
                        reconverge_giganto_ip.as_deref(),
                        "invalid IP address: storage",
                    )?,
                    reconverge_giganto_port,

                    hog,
                    hog_review_ip: parse_str_to_ip(
                        hog_review_ip.as_deref(),
                        "invalid IP address: administration",
                    )?,
                    hog_review_port,
                    hog_giganto_ip: parse_str_to_ip(
                        hog_giganto_ip.as_deref(),
                        "invalid IP address: storage",
                    )?,
                    hog_giganto_port,
                    protocols,
                    protocol_list,
                    sensors,
                    sensor_list,
                }),
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
        if !validate_update_input(&old, &new) {
            return Err("Invalid combination of old and new values".into());
        }

        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.node_map();
        map.update(i, &old, &new)?;
        Ok(id)
    }
}

fn validate_update_input(old: &NodeInput, new: &NodeInput) -> bool {
    matches!(
        (
            old.as_is.as_ref(),
            old.to_be.as_ref(),
            new.as_is.as_ref(),
            new.to_be.as_ref(),
        ),
        (None, Some(_), None, Some(_))
            | (Some(_), None, Some(_), Some(_))
            | (Some(_), Some(_), Some(_), _)
    )
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

        if let Some(as_is) = &node.as_is {
            if as_is.review {
                return Ok(Some(as_is.customer_id));
            }
        }
    }
    Ok(None)
}
