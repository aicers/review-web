mod control;
mod crud;
mod input;
mod status;

use async_graphql::{types::ID, ComplexObject, Context, InputObject, Object, Result, SimpleObject};
use bincode::Options;
use chrono::{DateTime, Utc};
pub use crud::{get_customer_id_of_review_host, get_node_settings};
use input::NodeInput;
use ipnet::Ipv4Net;
use review_database::{Indexable, Indexed, Store};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

pub type PortNumber = u16;

#[derive(Default)]
pub(super) struct NodeQuery;

#[derive(Default)]
pub(super) struct NodeMutation;

#[derive(Default)]
pub(super) struct NodeStatusQuery;

#[derive(Default)]
pub(super) struct NodeControlMutation;

#[derive(Clone, Deserialize, Serialize, SimpleObject, PartialEq)]
#[graphql(complex)]
struct Nic {
    name: String,
    #[graphql(skip)]
    interface: Ipv4Net,
    #[graphql(skip)]
    gateway: IpAddr,
}

#[ComplexObject]
impl Nic {
    async fn interface(&self) -> String {
        self.interface.to_string()
    }

    async fn gateway(&self) -> String {
        self.gateway.to_string()
    }
}

#[derive(Clone, InputObject)]
struct NicInput {
    name: String,
    interface: String,
    gateway: String,
}

impl PartialEq<Nic> for NicInput {
    fn eq(&self, rhs: &Nic) -> bool {
        self.name == rhs.name
            && self
                .interface
                .as_str()
                .parse::<Ipv4Net>()
                .map_or(false, |ip| ip == rhs.interface)
            && self
                .gateway
                .as_str()
                .parse::<IpAddr>()
                .map_or(false, |ip| ip == rhs.gateway)
    }
}

impl TryFrom<NicInput> for Nic {
    type Error = anyhow::Error;

    fn try_from(input: NicInput) -> Result<Self, Self::Error> {
        (&input).try_into()
    }
}

impl TryFrom<&NicInput> for Nic {
    type Error = anyhow::Error;

    fn try_from(input: &NicInput) -> Result<Self, Self::Error> {
        let interface = input.interface.as_str().parse::<Ipv4Net>()?;
        let gateway = input.gateway.as_str().parse::<IpAddr>()?;
        Ok(Self {
            name: input.name.clone(),
            interface,
            gateway,
        })
    }
}

#[derive(Clone, Deserialize, Serialize, SimpleObject)]
#[graphql(complex)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct Node {
    #[graphql(skip)]
    id: u32,
    name: String,
    #[graphql(skip)]
    customer_id: u32,
    description: String,
    pub(super) hostname: String,
    nics: Vec<Nic>,
    disk_usage_limit: Option<f32>,
    #[graphql(skip)]
    allow_access_from: Option<Vec<IpAddr>>,

    #[graphql(skip)]
    review_id: Option<u32>,

    ssh_port: PortNumber,
    #[graphql(skip)]
    dns_server_ip: Option<IpAddr>,
    dns_server_port: Option<PortNumber>,
    #[graphql(skip)]
    syslog_server_ip: Option<IpAddr>,
    syslog_server_port: Option<PortNumber>,

    review: bool,
    review_nics: Option<Vec<String>>,
    review_port: Option<PortNumber>,
    review_web_port: Option<PortNumber>,
    #[graphql(skip)]
    ntp_server_ip: Option<IpAddr>,
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

    creation_time: DateTime<Utc>,
}

#[ComplexObject]
impl Node {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }

    async fn customer_id(&self) -> ID {
        ID(self.customer_id.to_string())
    }

    async fn allow_access_from(&self) -> Option<Vec<String>> {
        self.allow_access_from.as_ref().map(|allow| {
            allow
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<String>>()
        })
    }

    async fn review_id(&self) -> Option<ID> {
        self.review_id.map(|id| ID(id.to_string()))
    }

    async fn ntp_server_ip(&self) -> Option<String> {
        self.ntp_server_ip.as_ref().map(ToString::to_string)
    }

    async fn dns_server_ip(&self) -> Option<String> {
        self.dns_server_ip.as_ref().map(ToString::to_string)
    }

    async fn syslog_server_ip(&self) -> Option<String> {
        self.syslog_server_ip.as_ref().map(ToString::to_string)
    }
}

struct NodeTotalCount;

#[Object]
impl NodeTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let db = ctx.data::<Arc<Store>>()?;
        Ok(db.node_map().count()?)
    }
}

impl Indexable for Node {
    fn key(&self) -> &[u8] {
        self.name.as_bytes()
    }

    fn value(&self) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .serialize(self)
            .expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

#[derive(Clone, Deserialize, Serialize, SimpleObject)]
#[graphql(complex)]
pub(super) struct NodeStatus {
    #[graphql(skip)]
    id: u32,

    /// The hostname of the node.
    name: String,

    /// The average CPU usage in percent.
    cpu_usage: Option<f32>,

    /// The RAM size in KB.
    total_memory: Option<u64>,

    /// The amount of used RAM in KB.
    used_memory: Option<u64>,

    /// The total disk space in bytes.
    total_disk_space: Option<u64>,

    /// The total disk space in bytes that is currently used.
    used_disk_space: Option<u64>,

    /// Whether review is online or not.
    review: Option<bool>,

    /// Whether piglet is online or not.
    piglet: Option<bool>,

    /// Whether giganto is online or not.
    giganto: Option<bool>,

    /// Whether reconverge is online or not.
    reconverge: Option<bool>,

    /// Whether hog is online or not.
    hog: Option<bool>,
}

#[ComplexObject]
impl NodeStatus {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }
}

impl NodeStatus {
    #[allow(clippy::too_many_arguments)]
    fn new(
        id: u32,
        name: String,
        cpu_usage: Option<f32>,
        total_memory: Option<u64>,
        used_memory: Option<u64>,
        total_disk_space: Option<u64>,
        used_disk_space: Option<u64>,
        review: Option<bool>,
        piglet: Option<bool>,
        giganto: Option<bool>,
        reconverge: Option<bool>,
        hog: Option<bool>,
    ) -> Self {
        Self {
            id,
            name,
            cpu_usage,
            total_memory,
            used_memory,
            total_disk_space,
            used_disk_space,
            review,
            piglet,
            giganto,
            reconverge,
            hog,
        }
    }
}

struct NodeStatusTotalCount;

#[Object]
impl NodeStatusTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let db = ctx.data::<Arc<Store>>()?;
        Ok(db.node_map().count()?)
    }
}

impl Indexable for NodeStatus {
    fn key(&self) -> &[u8] {
        self.name.as_bytes()
    }

    fn value(&self) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .serialize(self)
            .expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

#[derive(Serialize)]
pub struct Setting {
    name: String,
    nics: Vec<Nic>,
    accesslist: Option<Vec<IpAddr>>,
    disklimit: f32,
    // graphql, ingest, publish address of Giganto
    giganto: Option<ServerAddress>,
    hog: bool,
    ntp: Option<SocketAddr>,
    piglet: bool,
    reconverge: bool,
    // rpc, web address of REview. pub_addr is not used
    review: Option<ServerAddress>,
    ssh: Option<PortNumber>,
    // True for UDP, False for TCP
    syslog: Option<Vec<(bool, SocketAddr)>>,
}

#[derive(Serialize)]
pub struct ServerAddress {
    web_addr: SocketAddr,
    rpc_addr: SocketAddr,
    pub_addr: SocketAddr,
}

#[cfg(test)]

mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_node() {
        let schema = TestSchema::new().await;

        let res = schema.execute(r#"{nodeList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{nodeList: {totalCount: 0}}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertNode(
                        name: "admin node",
                        customerId: 0,
                        description: "This is the admin node running review.",
                        hostname: "admin.aice-security.com",
                        nics: [{
                            name: "eth0",
                            interface: "192.168.0.1/24",
                            gateway: "192.168.0.254"
                        }],
                        sshPort: 22,
                        review: true,
                        reviewNics: ["eth0"],
                        reviewPort: 38390,
                        reviewWebPort: 38391,
                        piglet: false,
                        giganto: false,
                        reconverge: false,
                        hog: false
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertNode: "0"}"#);

        let res = schema
            .execute(
                r#"mutation {
                    replaceNode(
                        id: "0"
                        old: {
                            name: "admin node",
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                            nics: [{
                                name: "eth0",
                                interface: "192.168.0.1/24",
                                gateway: "192.168.0.254"
                            }],
                            sshPort: 22,
                            review: true,
                            reviewNics: ["eth0"],
                            reviewPort: 38390,
                            reviewWebPort: 38391,
                            piglet: false,
                            giganto: false,
                            reconverge: false,
                            hog: false
                        },
                        new: {
                            name: "AdminNode",
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                            nics: [{
                                name: "eth0",
                                interface: "192.168.0.1/24",
                                gateway: "192.168.0.254"
                            }],
                            sshPort: 23,
                            review: true,
                            reviewNics: ["eth0"],
                            reviewPort: 38391,
                            reviewWebPort: 38392,
                            piglet: false,
                            giganto: false,
                            reconverge: false,
                            hog: false
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{replaceNode: "0"}"#);

        let res = schema
            .execute(
                r#"query {
                    nodeList(first: 1) {
                        nodes {
                            name
                        }
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeList: {nodes: [{name: "AdminNode"}]}}"#
        );

        let res = schema
            .execute(
                r#"query {
                    nodeStatusList(first: 1) {
                        nodes {
                            name
                            cpuUsage
                            review
                        }
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{nodeStatusList: {nodes: [{name: "AdminNode",cpuUsage: null,review: null}]}}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                    removeNodes(ids: ["0"])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeNodes: ["AdminNode"]}"#);
    }
}
