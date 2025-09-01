use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database::event as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistSsh {
    inner: database::BlocklistSsh,
}

#[Object]
impl BlocklistSsh {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    async fn sensor(&self) -> &str {
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
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    /// Source Network
    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
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
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    /// Destination Network
    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
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

    /// End Time
    async fn end_time(&self) -> i64 {
        self.inner.end_time
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
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// Confidence
    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// Triage Scores
    async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level
    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl From<database::BlocklistSsh> for BlocklistSsh {
    fn from(inner: database::BlocklistSsh) -> Self {
        Self { inner }
    }
}
