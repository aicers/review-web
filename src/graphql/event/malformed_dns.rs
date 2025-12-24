use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use itertools::Itertools;
use review_database::event as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistMalformedDns {
    inner: database::BlocklistMalformedDns,
}

#[Object]
impl BlocklistMalformedDns {
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

    /// Packets Sent by Source
    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_pkts)
    }

    /// Packets Received by Destination
    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_pkts)
    }

    /// Layer 2 Bytes Sent by Source
    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_l2_bytes)
    }

    /// Layer 2 Bytes Received by Destination
    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_l2_bytes)
    }

    /// Transaction ID
    async fn trans_id(&self) -> u16 {
        self.inner.trans_id
    }

    /// Flags
    async fn flags(&self) -> u16 {
        self.inner.flags
    }

    /// Question Count
    async fn question_count(&self) -> u16 {
        self.inner.question_count
    }

    /// Answer Count
    async fn answer_count(&self) -> u16 {
        self.inner.answer_count
    }

    /// Authority Count
    async fn authority_count(&self) -> u16 {
        self.inner.authority_count
    }

    /// Additional Count
    async fn additional_count(&self) -> u16 {
        self.inner.additional_count
    }

    /// Query Count
    async fn query_count(&self) -> StringNumber<u32> {
        StringNumber(self.inner.query_count)
    }

    /// Response Count
    async fn resp_count(&self) -> StringNumber<u32> {
        StringNumber(self.inner.resp_count)
    }

    /// Query Bytes
    async fn query_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.query_bytes)
    }

    /// Response Bytes
    async fn resp_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_bytes)
    }

    /// Query Body
    async fn query_body(&self) -> Vec<String> {
        self.inner
            .query_body
            .iter()
            .map(|bytes| format!("{:02x}", bytes.iter().format(":")))
            .collect()
    }

    /// Response Body
    async fn resp_body(&self) -> Vec<String> {
        self.inner
            .resp_body
            .iter()
            .map(|bytes| format!("{:02x}", bytes.iter().format(":")))
            .collect()
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

impl From<database::BlocklistMalformedDns> for BlocklistMalformedDns {
    fn from(inner: database::BlocklistMalformedDns) -> Self {
        Self { inner }
    }
}
