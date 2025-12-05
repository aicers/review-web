use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use itertools::Itertools;
use review_database::event as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistBootp {
    inner: database::BlocklistBootp,
}

#[Object]
impl BlocklistBootp {
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

    /// Operation Code
    /// 1: BOOTREQUEST, 2 = BOOTREPLY
    async fn op(&self) -> u8 {
        self.inner.op
    }

    /// Hardware Type
    async fn htype(&self) -> u8 {
        self.inner.htype
    }

    /// Hop Count
    async fn hops(&self) -> u8 {
        self.inner.hops
    }

    /// Transaction ID
    async fn xid(&self) -> StringNumber<u32> {
        StringNumber(self.inner.xid)
    }

    /// Client IP Address
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

    /// Client Hardware IP (Address)
    async fn chaddr(&self) -> String {
        format!("{:02x}", self.inner.chaddr.iter().format(":"))
    }

    /// Server Hostname
    async fn sname(&self) -> &str {
        &self.inner.sname
    }

    /// Boot Filename
    async fn file(&self) -> &str {
        &self.inner.file
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

impl From<database::BlocklistBootp> for BlocklistBootp {
    fn from(inner: database::BlocklistBootp) -> Self {
        Self { inner }
    }
}
