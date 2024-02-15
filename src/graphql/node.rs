mod control;
mod crud;
mod input;
mod process;
mod status;

use async_graphql::{types::ID, ComplexObject, Context, InputObject, Object, Result, SimpleObject};
use bincode::Options;
use chrono::{DateTime, TimeZone, Utc};
pub use crud::get_customer_id_of_review_host;
use input::NodeInput;
use ipnet::Ipv4Net;
use review_database::{Indexable, Indexed, IndexedMapUpdate};
use roxy::Process as RoxyProcess;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
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

#[derive(Default)]
pub(super) struct ProcessListQuery;

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

#[derive(Clone, Deserialize, Serialize, SimpleObject, PartialEq)]
#[graphql(complex)]
#[allow(clippy::struct_excessive_bools, clippy::module_name_repetitions)]
pub struct NodeSetting {
    name: String,
    #[graphql(skip)]
    customer_id: u32,
    description: String,
    pub(super) hostname: String,

    review: bool,
    review_port: Option<PortNumber>,
    review_web_port: Option<PortNumber>,

    piglet: bool,
    #[graphql(skip)]
    piglet_giganto_ip: Option<IpAddr>,
    piglet_giganto_port: Option<PortNumber>,
    #[graphql(skip)]
    piglet_review_ip: Option<IpAddr>,
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
    #[graphql(skip)]
    giganto_ingestion_ip: Option<IpAddr>,
    giganto_ingestion_port: Option<PortNumber>,
    #[graphql(skip)]
    giganto_publish_ip: Option<IpAddr>,
    giganto_publish_port: Option<PortNumber>,
    #[graphql(skip)]
    giganto_graphql_ip: Option<IpAddr>,
    giganto_graphql_port: Option<PortNumber>,
    retention_period: Option<u16>,

    reconverge: bool,
    #[graphql(skip)]
    reconverge_review_ip: Option<IpAddr>,
    reconverge_review_port: Option<PortNumber>,
    #[graphql(skip)]
    reconverge_giganto_ip: Option<IpAddr>,
    reconverge_giganto_port: Option<PortNumber>,

    hog: bool,
    #[graphql(skip)]
    hog_review_ip: Option<IpAddr>,
    hog_review_port: Option<PortNumber>,
    #[graphql(skip)]
    hog_giganto_ip: Option<IpAddr>,
    hog_giganto_port: Option<PortNumber>,
    protocols: bool,
    protocol_list: HashMap<String, bool>,

    sensors: bool,
    sensor_list: HashMap<String, bool>,
}

#[derive(Clone, Deserialize, Serialize, SimpleObject, PartialEq)]
#[graphql(complex)]
pub(super) struct Node {
    #[graphql(skip)]
    id: u32,
    creation_time: DateTime<Utc>,
    pub as_is: Option<NodeSetting>,
    pub to_be: Option<NodeSetting>,
}

impl IndexedMapUpdate for Node {
    type Entry = Self;

    fn key(&self) -> Option<&[u8]> {
        Some(Indexable::key(self))
    }

    fn apply(&self, _value: Self::Entry) -> anyhow::Result<Self::Entry> {
        Ok(self.clone())
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        self == value
    }
}

#[ComplexObject]
impl Node {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }
}

impl Node {
    fn as_is_hostname_or_fallback(&self) -> &str {
        if let Some(as_is) = &self.as_is {
            &as_is.hostname
        } else if let Some(to_be) = &self.to_be {
            &to_be.hostname
        } else {
            panic!("Both `as_is` and `to_be` are `None`");
        }
    }

    fn as_is_name_or_fallback(&self) -> &str {
        if let Some(as_is) = &self.as_is {
            &as_is.name
        } else if let Some(to_be) = &self.to_be {
            &to_be.name
        } else {
            panic!("Both `as_is` and `to_be` are `None`");
        }
    }
}

#[ComplexObject]
impl NodeSetting {
    async fn customer_id(&self) -> ID {
        ID(self.customer_id.to_string())
    }

    async fn piglet_giganto_ip(&self) -> Option<String> {
        self.piglet_giganto_ip.as_ref().map(ToString::to_string)
    }
    async fn piglet_review_ip(&self) -> Option<String> {
        self.piglet_review_ip.as_ref().map(ToString::to_string)
    }
    async fn giganto_ingestion_ip(&self) -> Option<String> {
        self.giganto_ingestion_ip.as_ref().map(ToString::to_string)
    }
    async fn giganto_publish_ip(&self) -> Option<String> {
        self.giganto_publish_ip.as_ref().map(ToString::to_string)
    }
    async fn giganto_graphql_ip(&self) -> Option<String> {
        self.giganto_graphql_ip.as_ref().map(ToString::to_string)
    }
    async fn reconverge_review_ip(&self) -> Option<String> {
        self.reconverge_review_ip.as_ref().map(ToString::to_string)
    }
    async fn reconverge_giganto_ip(&self) -> Option<String> {
        self.reconverge_giganto_ip.as_ref().map(ToString::to_string)
    }
    async fn hog_review_ip(&self) -> Option<String> {
        self.hog_review_ip.as_ref().map(ToString::to_string)
    }
    async fn hog_giganto_ip(&self) -> Option<String> {
        self.hog_giganto_ip.as_ref().map(ToString::to_string)
    }
}

struct NodeTotalCount;

#[Object]
impl NodeTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        Ok(store.node_map().count()?)
    }
}

impl Indexable for Node {
    fn key(&self) -> &[u8] {
        if let Some(as_is) = &self.as_is {
            as_is.name.as_bytes()
        } else if let Some(to_be) = &self.to_be {
            to_be.name.as_bytes()
        } else {
            panic!("Both `as_is` and `to_be` are `None`");
        }
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

    /// The ping value for a specific node.
    ping: Option<i64>,

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
        ping: Option<i64>,
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
            ping,
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
        let store = crate::graphql::get_store(ctx).await?;
        Ok(store.node_map().count()?)
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
    // ingest, publish address of Piglet. web_addr is not used
    piglet: Option<ServerAddress>,
    // graphql, ingest, publish address of Giganto
    giganto: Option<ServerAddress>,
    // ingest, publish address of Hog. web_addr is not used
    hog: Option<ServerAddress>,
    // ingest, publish address of REconverge. web_addr is not used
    reconverge: Option<ServerAddress>,
    // rpc, web address of REview. pub_addr is not used
    review: Option<ServerPort>,
}

#[derive(Serialize)]
pub struct ServerAddress {
    web: Option<SocketAddr>,
    rpc: Option<SocketAddr>,
    public: Option<SocketAddr>,
    ing: Option<SocketAddr>,
}

#[derive(Serialize)]
pub struct ServerPort {
    rpc_port: PortNumber,
    web_port: PortNumber,
}

#[derive(Clone, Deserialize, Serialize, SimpleObject)]
pub struct Process {
    pub user: String,
    pub cpu_usage: String,
    pub mem_usage: String,
    pub start_time: DateTime<Utc>,
    pub command: String,
}

impl From<RoxyProcess> for Process {
    fn from(value: RoxyProcess) -> Self {
        Self {
            user: value.user,
            cpu_usage: value.cpu_usage.to_string(),
            mem_usage: value.mem_usage.to_string(),
            start_time: Utc.timestamp_nanos(value.start_time),
            command: value.command,
        }
    }
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
                        review: true,
                        reviewPort: 38390,
                        reviewWebPort: 8443,
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

        let res = schema
            .execute(
                r#"mutation {
                    updateNode(
                        id: "0"
                        old: {
                            name: "admin node",
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                            review: true,
                            reviewPort: 38390,
                            reviewWebPort: 8443,
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
                        new: {
                            name: "AdminNode",
                            customerId: 0,
                            description: "This is the admin node running review.",
                            hostname: "admin.aice-security.com",
                            review: true,
                            reviewPort: 38391,
                            reviewWebPort: 8443,
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
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateNode: "0"}"#);

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
