mod control;
mod crud;
mod input;
mod process;
mod status;

use async_graphql::{types::ID, ComplexObject, Context, InputObject, Object, Result, SimpleObject};
use bincode::Options;
use chrono::{DateTime, TimeZone, Utc};
pub use crud::{get_customer_id_of_review_host, get_node_settings};
use input::NodeInput;
use ipnet::Ipv4Net;
use review_database::Indexable;
use roxy::Process as RoxyProcess;
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
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

#[derive(Clone, Deserialize, Serialize, SimpleObject, PartialEq, Default)]
#[graphql(complex)]
#[allow(clippy::struct_excessive_bools, clippy::module_name_repetitions)]
pub struct NodeSettings {
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

impl From<review_database::NodeSetting> for NodeSettings {
    fn from(input: review_database::NodeSetting) -> Self {
        Self {
            customer_id: input.customer_id,
            description: input.description.clone(),
            hostname: input.hostname.clone(),
            review: input.review,
            review_port: input.review_port,
            review_web_port: input.review_web_port,
            piglet: input.piglet,
            piglet_giganto_ip: input.piglet_giganto_ip,
            piglet_giganto_port: input.piglet_giganto_port,
            piglet_review_ip: input.piglet_review_ip,
            piglet_review_port: input.piglet_review_port,
            save_packets: input.save_packets,
            http: input.http,
            office: input.office,
            exe: input.exe,
            pdf: input.pdf,
            html: input.html,
            txt: input.txt,
            smtp_eml: input.smtp_eml,
            ftp: input.ftp,
            giganto: input.giganto,
            giganto_ingestion_ip: input.giganto_ingestion_ip,
            giganto_ingestion_port: input.giganto_ingestion_port,
            giganto_publish_ip: input.giganto_publish_ip,
            giganto_publish_port: input.giganto_publish_port,
            giganto_graphql_ip: input.giganto_graphql_ip,
            giganto_graphql_port: input.giganto_graphql_port,
            retention_period: input.retention_period,
            reconverge: input.reconverge,
            reconverge_review_ip: input.reconverge_review_ip,
            reconverge_review_port: input.reconverge_review_port,
            reconverge_giganto_ip: input.reconverge_giganto_ip,
            reconverge_giganto_port: input.reconverge_giganto_port,
            hog: input.hog,
            hog_review_ip: input.hog_review_ip,
            hog_review_port: input.hog_review_port,
            hog_giganto_ip: input.hog_giganto_ip,
            hog_giganto_port: input.hog_giganto_port,
            protocols: input.protocols,
            protocol_list: input.protocol_list.clone(),
            sensors: input.sensors,
            sensor_list: input.sensor_list.clone(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, SimpleObject, PartialEq)]
#[graphql(complex)]
pub(super) struct Node {
    #[graphql(skip)]
    pub id: u32,
    name: String,
    name_draft: Option<String>,
    pub settings: Option<NodeSettings>,
    pub settings_draft: Option<NodeSettings>,
    creation_time: DateTime<Utc>,
}

impl From<review_database::Node> for Node {
    fn from(input: review_database::Node) -> Self {
        Self {
            id: input.id,
            name: input.name,
            name_draft: input.name_draft,
            settings: input.setting.map(Into::into),
            settings_draft: input.setting_draft.map(Into::into),
            creation_time: input.creation_time,
        }
    }
}

#[ComplexObject]
impl Node {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }
}

#[ComplexObject]
impl NodeSettings {
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

#[derive(Debug, SimpleObject, Serialize, Deserialize, Clone)]
#[graphql(complex)]
struct HogConfig {
    #[graphql(skip)]
    review_ip: IpAddr,
    review_port: PortNumber,
    #[graphql(skip)]
    giganto_ip: Option<IpAddr>,
    giganto_port: Option<PortNumber>,
    active_protocols: Option<Vec<String>>,
    active_sources: Option<Vec<String>>,
}

#[ComplexObject]
impl HogConfig {
    async fn review_ip(&self) -> String {
        self.review_ip.to_string()
    }

    async fn giganto_ip(&self) -> Option<String> {
        self.giganto_ip.as_ref().map(ToString::to_string)
    }
}

impl From<oinq::request::HogConfig> for HogConfig {
    fn from(value: oinq::request::HogConfig) -> Self {
        Self {
            review_ip: value.review_address.ip(),
            review_port: value.review_address.port(),
            giganto_ip: value.giganto_address.as_ref().map(SocketAddr::ip),
            giganto_port: value.giganto_address.as_ref().map(SocketAddr::port),
            active_protocols: value.active_protocols,
            active_sources: value.active_sources,
        }
    }
}

#[derive(Debug, SimpleObject, Serialize, Deserialize, Clone)]
#[graphql(complex)]
struct PigletConfig {
    #[graphql(skip)]
    review_ip: IpAddr,
    review_port: PortNumber,
    #[graphql(skip)]
    giganto_ip: Option<IpAddr>,
    giganto_port: Option<PortNumber>,
    log_options: Option<Vec<String>>,
    http_file_types: Option<Vec<String>>,
}

#[ComplexObject]
impl PigletConfig {
    async fn review_ip(&self) -> String {
        self.review_ip.to_string()
    }

    async fn giganto_ip(&self) -> Option<String> {
        self.giganto_ip.as_ref().map(ToString::to_string)
    }
}

impl From<oinq::request::PigletConfig> for PigletConfig {
    fn from(value: oinq::request::PigletConfig) -> Self {
        Self {
            review_ip: value.review_address.ip(),
            review_port: value.review_address.port(),
            giganto_ip: value.giganto_address.as_ref().map(SocketAddr::ip),
            giganto_port: value.giganto_address.as_ref().map(SocketAddr::port),
            log_options: value.log_options,
            http_file_types: value.http_file_types,
        }
    }
}

#[derive(Debug, SimpleObject, Serialize, Deserialize, Clone)]
#[graphql(complex)]
struct ReconvergeConfig {
    #[graphql(skip)]
    review_ip: IpAddr,
    review_port: PortNumber,
    #[graphql(skip)]
    giganto_ip: Option<IpAddr>,
    giganto_port: Option<PortNumber>,
}

#[ComplexObject]
impl ReconvergeConfig {
    async fn review_ip(&self) -> String {
        self.review_ip.to_string()
    }

    async fn giganto_ip(&self) -> Option<String> {
        self.giganto_ip.as_ref().map(ToString::to_string)
    }
}

impl From<oinq::request::ReconvergeConfig> for ReconvergeConfig {
    fn from(value: oinq::request::ReconvergeConfig) -> Self {
        Self {
            review_ip: value.review_address.ip(),
            review_port: value.review_address.port(),
            giganto_ip: value.giganto_address.as_ref().map(SocketAddr::ip),
            giganto_port: value.giganto_address.as_ref().map(SocketAddr::port),
        }
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

    /// actual piglet configuration
    piglet_config: Option<PigletConfig>,

    /// Whether giganto is online or not.
    giganto: Option<bool>,

    /// Whether reconverge is online or not.
    reconverge: Option<bool>,

    /// actual reconverge configuration
    reconverge_config: Option<ReconvergeConfig>,

    /// Whether hog is online or not.
    hog: Option<bool>,

    /// actual hog configuration
    hog_config: Option<HogConfig>,
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
        piglet_config: Option<PigletConfig>,
        giganto: Option<bool>,
        reconverge: Option<bool>,
        reconverge_config: Option<ReconvergeConfig>,
        hog: Option<bool>,
        hog_config: Option<HogConfig>,
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
            piglet_config,
            giganto,
            reconverge,
            reconverge_config,
            hog,
            hog_config,
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
    fn key(&self) -> Cow<[u8]> {
        Cow::Borrowed(self.name.as_bytes())
    }

    fn index(&self) -> u32 {
        self.id
    }

    fn make_indexed_key(key: Cow<[u8]>, _index: u32) -> Cow<[u8]> {
        key
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

#[derive(
    async_graphql::Enum,
    Copy,
    Clone,
    Eq,
    PartialEq,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::AsRefStr,
)]
#[strum(serialize_all = "snake_case")]
pub enum ModuleName {
    Hog,
    Piglet,
    Reconverge,
    Review,
    Giganto,
}
