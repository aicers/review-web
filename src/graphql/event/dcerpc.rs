use async_graphql::{Context, Object, Result, SimpleObject, StringNumber};
use chrono::{DateTime, Utc};
use review_database::event as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistDceRpc {
    inner: database::BlocklistDceRpc,
}

/// A single DCE/RPC context entry.
#[derive(SimpleObject)]
struct DceRpcContext {
    id: i32,
    abstract_syntax: StringNumber<u128>,
    abstract_major: i32,
    abstract_minor: i32,
    transfer_syntax: StringNumber<u128>,
    transfer_major: i32,
    transfer_minor: i32,
    acceptance: i32,
    reason: i32,
}

impl From<&database::DceRpcContext> for DceRpcContext {
    fn from(c: &database::DceRpcContext) -> Self {
        Self {
            id: i32::from(c.id),
            abstract_syntax: StringNumber(c.abstract_syntax),
            abstract_major: i32::from(c.abstract_major),
            abstract_minor: i32::from(c.abstract_minor),
            transfer_syntax: StringNumber(c.transfer_syntax),
            transfer_major: i32::from(c.transfer_major),
            transfer_minor: i32::from(c.transfer_minor),
            acceptance: i32::from(c.acceptance),
            reason: i32::from(c.reason),
        }
    }
}

#[Object]
impl BlocklistDceRpc {
    /// Event Generation Time
    pub async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    pub async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Originator IP (Address)
    async fn orig_addr(&self) -> String {
        self.inner.orig_addr.to_string()
    }

    /// Originator Country
    /// The two-letter country code of the originator IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn orig_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.orig_addr)
    }

    /// Originator Customer
    async fn orig_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.orig_addr)
    }

    /// Originator Network
    async fn orig_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.orig_addr)
    }

    /// Originator Port (Number)
    async fn orig_port(&self) -> u16 {
        self.inner.orig_port
    }

    /// Responder IP (Address)
    async fn resp_addr(&self) -> String {
        self.inner.resp_addr.to_string()
    }

    /// Responder Country
    /// The two-letter country code of the responder IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn resp_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.resp_addr)
    }

    /// Responder Customer
    async fn resp_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.resp_addr)
    }

    /// Responder Network
    async fn resp_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.resp_addr)
    }

    /// Responder Port (Number)
    async fn resp_port(&self) -> u16 {
        self.inner.resp_port
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

    /// DCE/RPC Context Entries
    async fn context(&self) -> Vec<DceRpcContext> {
        self.inner.context.iter().map(Into::into).collect()
    }

    /// DCE/RPC Request Strings
    async fn request(&self) -> &[String] {
        &self.inner.request
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
        database::BlocklistDceRpc::threat_level().into()
    }
}

impl From<database::BlocklistDceRpc> for BlocklistDceRpc {
    fn from(inner: database::BlocklistDceRpc) -> Self {
        Self { inner }
    }
}
