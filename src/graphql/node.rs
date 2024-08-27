mod control;
mod crud;
mod input;
mod process;
mod status;

use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use async_graphql::{
    types::ID, ComplexObject, Context, Enum, InputObject, Object, Result, SimpleObject,
    StringNumber,
};
use bincode::Options;
use chrono::{DateTime, TimeZone, Utc};
#[allow(clippy::module_name_repetitions)]
pub use crud::get_customer_id_of_node;
use database::Indexable;
use input::NodeInput;
use ipnet::Ipv4Net;
use review_database as database;
use roxy::Process as RoxyProcess;
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Deserialize, PartialEq, Serialize, Copy, Eq, Enum)]
#[graphql(remote = "database::AgentKind")]
pub enum AgentKind {
    Reconverge,
    Piglet,
    Hog,
}

#[derive(Clone, PartialEq, Deserialize, Serialize, Enum, Copy, Eq)]
#[graphql(remote = "database::AgentStatus")]
pub enum AgentStatus {
    Disabled,
    Enabled,
    ReloadFailed,
    Unknown,
}

#[derive(Clone, Deserialize, Serialize, SimpleObject, PartialEq)]
pub struct Agent {
    pub node: u32,
    pub key: String,
    pub kind: AgentKind,
    pub status: AgentStatus,
    pub config: Option<String>,
    pub draft: Option<String>,
}

impl From<&database::Agent> for Agent {
    fn from(input: &database::Agent) -> Self {
        Self {
            node: input.node,
            key: input.key.clone(),
            kind: input.kind.into(),
            status: input.status.into(),
            config: input.config.clone().map(|c| c.to_string()),
            draft: input.draft.clone().map(|c| c.to_string()),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, SimpleObject, PartialEq)]
pub struct Giganto {
    pub status: AgentStatus,
    pub draft: Option<String>,
}

impl From<database::Giganto> for Giganto {
    fn from(input: database::Giganto) -> Self {
        Self {
            status: input.status.into(),
            draft: input.draft.map(|c| c.to_string()),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct NodeProfile {
    pub inner: review_database::NodeProfile,
}

impl From<&review_database::NodeProfile> for NodeProfile {
    fn from(inner: &review_database::NodeProfile) -> Self {
        Self {
            inner: inner.clone(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub(super) struct Node {
    pub inner: review_database::Node,
}

impl From<review_database::Node> for Node {
    fn from(inner: review_database::Node) -> Self {
        Self { inner }
    }
}

#[Object]
impl Node {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn name_draft(&self) -> Option<&str> {
        self.inner.name_draft.as_deref()
    }

    async fn profile(&self) -> Option<NodeProfile> {
        self.inner.profile.as_ref().map(Into::into)
    }

    async fn profile_draft(&self) -> Option<NodeProfile> {
        self.inner.profile_draft.as_ref().map(Into::into)
    }

    async fn agents(&self) -> Vec<Agent> {
        self.inner.agents.iter().map(Into::into).collect()
    }

    async fn giganto(&self) -> Option<Giganto> {
        self.inner.giganto.clone().map(Into::into)
    }
}

#[Object]
impl NodeProfile {
    async fn customer_id(&self) -> ID {
        ID(self.inner.customer_id.to_string())
    }

    async fn description(&self) -> &str {
        &self.inner.description
    }

    async fn hostname(&self) -> &str {
        &self.inner.hostname
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
    giganto_ip: Option<IpAddr>,
    giganto_port: Option<PortNumber>,
    active_protocols: Option<Vec<String>>,
    active_sources: Option<Vec<String>>,
}

#[ComplexObject]
impl HogConfig {
    async fn giganto_ip(&self) -> Option<String> {
        self.giganto_ip.as_ref().map(ToString::to_string)
    }
}

impl From<review_protocol::types::HogConfig> for HogConfig {
    fn from(value: review_protocol::types::HogConfig) -> Self {
        Self {
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
    giganto_ip: Option<IpAddr>,
    giganto_port: Option<PortNumber>,
    log_options: Option<Vec<String>>,
    http_file_types: Option<Vec<String>>,
}

#[ComplexObject]
impl PigletConfig {
    async fn giganto_ip(&self) -> Option<String> {
        self.giganto_ip.as_ref().map(ToString::to_string)
    }
}

impl From<review_protocol::types::PigletConfig> for PigletConfig {
    fn from(value: review_protocol::types::PigletConfig) -> Self {
        Self {
            giganto_ip: value.giganto_address.as_ref().map(SocketAddr::ip),
            giganto_port: value.giganto_address.as_ref().map(SocketAddr::port),
            log_options: value.log_options,
            http_file_types: value.http_file_types,
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

    /// The RAM size in bytes.
    #[graphql(skip)]
    total_memory: Option<u64>,

    /// The amount of used RAM in bytes.
    #[graphql(skip)]
    used_memory: Option<u64>,

    /// The total disk space in bytes.
    #[graphql(skip)]
    total_disk_space: Option<u64>,

    /// The total disk space in bytes that is currently used.
    #[graphql(skip)]
    used_disk_space: Option<u64>,

    /// The round-trip time to the node.
    #[graphql(skip)]
    ping: Option<Duration>,

    /// Whether review is online or not.
    review: Option<bool>,

    /// Whether piglet is online or not.
    piglet: Option<bool>,

    /// actual piglet configuration
    piglet_config: Option<PigletConfig>,

    /// Whether reconverge is online or not.
    reconverge: Option<bool>,

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
    /// The RAM size in bytes within the range representable by a `u64`
    async fn total_memory(&self) -> Option<StringNumber<u64>> {
        self.total_memory.map(StringNumber)
    }
    /// The amount of used RAM in bytes within the range representable by a `u64`
    async fn used_memory(&self) -> Option<StringNumber<u64>> {
        self.used_memory.map(StringNumber)
    }
    /// The total disk space in bytes within the range representable by a `u64`
    async fn total_disk_space(&self) -> Option<StringNumber<u64>> {
        self.total_disk_space.map(StringNumber)
    }
    /// The total disk space in bytes that is currently used within the range representable by a `u64`
    async fn used_disk_space(&self) -> Option<StringNumber<u64>> {
        self.used_disk_space.map(StringNumber)
    }
    /// The round-trip time to the node in seconds.
    async fn ping(&self) -> Option<f64> {
        self.ping.map(|d| d.as_secs_f64())
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
        ping: Option<Duration>,
        review: Option<bool>,
        piglet: Option<bool>,
        piglet_config: Option<PigletConfig>,
        reconverge: Option<bool>,
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
            reconverge,
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
}

pub fn is_review(hostname: &str) -> bool {
    let review_hostname = roxy::hostname();

    !review_hostname.is_empty() && review_hostname == hostname
}
