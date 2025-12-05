use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use itertools::Itertools;
use review_database::event as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistDhcp {
    inner: database::BlocklistDhcp,
}

#[Object]
impl BlocklistDhcp {
    /// Event Generation Time
    pub async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    pub async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Source IP (Address)
    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// Source Country
    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    /// Source Customer
    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    /// Source Network
    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    /// Source Port (Number)
    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    /// Destination IP (Address)
    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// Destination Country
    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    /// Destination Customer
    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    /// Destination Network
    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    /// Destination Port (Number)
    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Duration
    ///
    /// It is measured in nanoseconds.
    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.inner.duration)
    }

    /// Packets Sent (by Source)
    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_pkts)
    }

    /// Packets Received (by Destination)
    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_pkts)
    }

    /// Layer 2 Bytes Sent (by Source)
    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_l2_bytes)
    }

    /// Layer 2 Bytes Received (by Destination)
    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_l2_bytes)
    }

    /// Message Type
    async fn msg_type(&self) -> u8 {
        self.inner.msg_type
    }

    /// Client IP (Address)
    async fn ciaddr(&self) -> String {
        self.inner.ciaddr.to_string()
    }

    /// Your IP (Address)
    async fn yiaddr(&self) -> String {
        self.inner.yiaddr.to_string()
    }

    /// Server IP (Address)
    async fn siaddr(&self) -> String {
        self.inner.siaddr.to_string()
    }

    /// Gateway IP (Address)
    async fn giaddr(&self) -> String {
        self.inner.giaddr.to_string()
    }

    /// Subnet Mask
    async fn subnet_mask(&self) -> String {
        self.inner.subnet_mask.to_string()
    }

    /// Routers
    async fn router(&self) -> String {
        self.inner.router.iter().join(", ")
    }

    /// Domain Name Servers
    async fn domain_name_server(&self) -> String {
        self.inner.domain_name_server.iter().join(", ")
    }

    /// Request IP (Address)
    async fn req_ip_addr(&self) -> String {
        self.inner.req_ip_addr.to_string()
    }

    /// Lease Time
    async fn lease_time(&self) -> StringNumber<u32> {
        StringNumber(self.inner.lease_time)
    }

    /// Server ID
    async fn server_id(&self) -> String {
        self.inner.server_id.to_string()
    }

    /// Parameter Request List
    async fn param_req_list(&self) -> String {
        self.inner.param_req_list.iter().join(", ")
    }

    /// Message
    async fn message(&self) -> &str {
        &self.inner.message
    }

    /// Renewal Time
    async fn renewal_time(&self) -> StringNumber<u32> {
        StringNumber(self.inner.renewal_time)
    }

    /// Rebinding Time
    async fn rebinding_time(&self) -> StringNumber<u32> {
        StringNumber(self.inner.rebinding_time)
    }

    /// Class ID List
    async fn class_id(&self) -> String {
        format!("{:02x}", self.inner.class_id.iter().format(":"))
    }

    /// Client ID Type
    async fn client_id_type(&self) -> u8 {
        self.inner.client_id_type
    }

    /// Client ID List
    async fn client_id(&self) -> String {
        format!("{:02x}", self.inner.client_id.iter().format(":"))
    }

    /// MITRE Tactic
    pub async fn category(&self) -> Option<ThreatCategory> {
        self.inner.category.map(Into::into)
    }

    /// Confidence
    pub async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// Triage Scores
    pub async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level
    pub async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl From<database::BlocklistDhcp> for BlocklistDhcp {
    fn from(inner: database::BlocklistDhcp) -> Self {
        Self { inner }
    }
}
