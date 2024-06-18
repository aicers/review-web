#![allow(clippy::fn_params_excessive_bools)]

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use async_graphql::{
    connection::{query, Connection, EmptyFields},
    types::ID,
    Context, Object, Result,
};
use chrono::Utc;
use review_database::{Direction, Iterable, Store};
use tracing::error;

use super::{
    super::{Role, RoleGuard},
    input::NodeDraftInput,
    Node, NodeInput, NodeMutation, NodeQuery, NodeTotalCount, PortNumber, ServerAddress,
    ServerPort, Setting,
};
use crate::graphql::{customer::broadcast_customer_networks, get_customer_networks};

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
        let Some(node) = map.get_by_id(i)? else {
            return Err("no such node".into());
        };
        Ok(node.into())
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

            let value = review_database::Node {
                id: u32::MAX,
                name,
                name_draft: None,
                settings: None,
                settings_draft: Some(review_database::NodeSettings {
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
                creation_time: Utc::now(),
            };
            let id = map.put(value)?;
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
    async fn update_node_draft(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: NodeInput,
        new: NodeDraftInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let store = crate::graphql::get_store(ctx).await?;
        let mut map = store.node_map();
        let new = super::input::create_draft_update(&old, new)?;
        let old = old.try_into()?;
        map.update(i, &old, &new)?;
        Ok(id)
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

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Node, NodeTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.node_map();
    super::super::load_edges(&map, after, before, first, last, NodeTotalCount)
}

/// Returns the node settings.
///
/// # Errors
///
/// Returns an error if the node settings could not be retrieved.
#[allow(clippy::too_many_lines)]
pub fn get_node_settings(db: &Store) -> Result<Vec<Setting>> {
    let map = db.node_map();
    let mut output = Vec::new();
    for res in map.iter(Direction::Forward, None) {
        let node = res.map_err(|_| "invalid value in database")?;

        let node_settings = node.settings.ok_or("Applied node settings do not exist")?;

        let piglet: Option<ServerAddress> = if node_settings.piglet {
            Some(ServerAddress {
                web: None,
                rpc: Some(SocketAddr::new(
                    node_settings
                        .piglet_review_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node_settings.piglet_review_port.unwrap_or_default(),
                )),
                public: Some(SocketAddr::new(
                    node_settings
                        .piglet_giganto_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node_settings.piglet_giganto_port.unwrap_or_default(),
                )),
                ing: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            })
        } else {
            None
        };
        let giganto = if node_settings.giganto {
            Some(ServerAddress {
                web: Some(SocketAddr::new(
                    node_settings
                        .giganto_graphql_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node_settings.giganto_graphql_port.unwrap_or_default(),
                )),
                rpc: None,
                public: Some(SocketAddr::new(
                    node_settings
                        .giganto_publish_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node_settings.giganto_publish_port.unwrap_or_default(),
                )),
                ing: Some(SocketAddr::new(
                    node_settings
                        .giganto_ingestion_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node_settings.giganto_ingestion_port.unwrap_or_default(),
                )),
            })
        } else {
            None
        };

        let review = if node_settings.review {
            Some(ServerPort {
                rpc_port: node_settings.review_port.unwrap_or_default(),
                web_port: node_settings.review_web_port.unwrap_or_default(),
            })
        } else {
            None
        };
        let reconverge = if node_settings.reconverge {
            Some(ServerAddress {
                web: None,
                rpc: Some(SocketAddr::new(
                    node_settings
                        .reconverge_review_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node_settings.reconverge_review_port.unwrap_or_default(),
                )),
                public: Some(SocketAddr::new(
                    node_settings
                        .reconverge_giganto_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node_settings.reconverge_giganto_port.unwrap_or_default(),
                )),
                ing: None,
            })
        } else {
            None
        };
        let hog = if node_settings.hog {
            Some(ServerAddress {
                web: None,
                rpc: Some(SocketAddr::new(
                    node_settings
                        .hog_review_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node_settings.hog_review_port.unwrap_or_default(),
                )),
                public: Some(SocketAddr::new(
                    node_settings
                        .hog_giganto_ip
                        .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
                    node_settings.hog_giganto_port.unwrap_or_default(),
                )),
                ing: None,
            })
        } else {
            None
        };

        output.push(Setting {
            name: node_settings.hostname,
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
    for entry in map.iter(Direction::Forward, None) {
        let node = entry.map_err(|_| "invalid value in database")?;

        if let Some(node_settings) = &node.settings {
            if node_settings.review {
                return Ok(Some(node_settings.customer_id));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use crate::graphql::TestSchema;

    // test scenario : insert node -> update node with different name -> remove node
    #[tokio::test]
    async fn node_crud() {
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

        // check node count after insert
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 1}}"#);

        // check inserted node
        let res = schema
            .execute(
                r#"{node(id: "0") {
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
                        protocolList
                        sensorList
                    }

                }}"#,
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
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
                        "protocolList": {},
                        "sensorList": {},
                    },
                }
            })
        );

        // update node
        let res = schema
            .execute(
                r#"mutation {
                    updateNodeDraft(
                        id: "0"
                        old: {
                            name: "admin node",
                            nameDraft: null,
                            settings: null
                            settingsDraft: {
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
                            }
                        },
                        new: {
                            nameDraft: "AdminNode",
                            settingsDraft: {
                                customerId: 0,
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

        // check node count after update
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 1}}"#);

        // check updated node
        let res = schema
            .execute(
                r#"{node(id: "0") {
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
                        protocolList
                        sensorList
                    }

                }}"#,
            )
            .await;

        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "node": {
                    "id": "0",
                    "name": "admin node", // stays the same
                    "nameDraft": "AdminNode", // updated
                    "settings": null,
                    "settingsDraft": {
                        "customerId": "0",
                        "description": "This is the admin node running review.",
                        "hostname": "admin.aice-security.com",
                        "review": true,
                        "reviewPort": 2222,  // updated
                        "reviewWebPort": 2223, // updated
                        "protocolList": {},
                        "sensorList": {},
                    },
                }
            })
        );

        // try reverting node, but it should succeed even though the node is an initial draft
        let res = schema
            .execute(
                r#"mutation {
                updateNodeDraft(
                    id: "0"
                    old: {
                        name: "admin node",
                        nameDraft: "AdminNode",
                        settings: null
                        settingsDraft: {
                            customerId: 0,
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
                    },
                    new: {
                        nameDraft: null,
                        settingsDraft: null,
                    }
                )
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNodeDraft: "0"}"#);

        // remove node
        let res = schema
            .execute(
                r#"mutation {
                    removeNodes(ids: ["0"])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNodes: ["admin node"]}"#);

        // check node count after remove
        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 0}}"#);
    }
}
