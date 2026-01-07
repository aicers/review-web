use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database::event as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistSsh {
    inner: database::BlocklistSsh,
}

#[Object]
impl BlocklistSsh {
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

    /// Client
    async fn client(&self) -> &str {
        &self.inner.client
    }

    /// Server
    async fn server(&self) -> &str {
        &self.inner.server
    }

    /// Cipher Algorithm
    async fn cipher_alg(&self) -> &str {
        &self.inner.cipher_alg
    }

    /// MAC Algorithms
    async fn mac_alg(&self) -> &str {
        &self.inner.mac_alg
    }

    /// Compression Algorithm
    async fn compression_alg(&self) -> &str {
        &self.inner.compression_alg
    }

    /// Key Exchange Algorithm
    async fn kex_alg(&self) -> &str {
        &self.inner.kex_alg
    }

    /// Host Key Algorithm
    async fn host_key_alg(&self) -> &str {
        &self.inner.host_key_alg
    }

    /// HASSH Algorithms
    async fn hassh_algorithms(&self) -> &str {
        &self.inner.hassh_algorithms
    }

    /// HASSH
    async fn hassh(&self) -> &str {
        &self.inner.hassh
    }

    /// HASSH Server Algorithm
    async fn hassh_server_algorithms(&self) -> &str {
        &self.inner.hassh_server_algorithms
    }

    /// HASSH Server
    async fn hassh_server(&self) -> &str {
        &self.inner.hassh_server
    }

    /// Client Signed Host Key Algorithm
    async fn client_shka(&self) -> &str {
        &self.inner.client_shka
    }

    /// Server Signed Host Key Algorithm
    async fn server_shka(&self) -> &str {
        &self.inner.server_shka
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

impl From<database::BlocklistSsh> for BlocklistSsh {
    fn from(inner: database::BlocklistSsh) -> Self {
        Self { inner }
    }
}
