use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database::event as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

#[allow(clippy::module_name_repetitions)]
pub(super) struct RdpBruteForce {
    inner: database::RdpBruteForce,
}

#[Object]
impl RdpBruteForce {
    /// Start Time
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

    /// Destination IP (Address) List
    async fn dst_addrs(&self) -> Vec<String> {
        self.inner
            .dst_addrs
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Destination Country List
    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_countries(&self, ctx: &Context<'_>) -> Vec<String> {
        self.inner
            .dst_addrs
            .iter()
            .map(|dst_addr| country_code(ctx, *dst_addr))
            .collect()
    }

    /// Destination Customer List
    async fn dst_customers(&self, ctx: &Context<'_>) -> Result<Vec<Option<Customer>>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        let mut customers = vec![];
        for dst_addr in &self.inner.dst_addrs {
            customers.push(find_ip_customer(&map, *dst_addr)?);
        }
        Ok(customers)
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Detection Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Detection End Time
    async fn end_time(&self) -> DateTime<Utc> {
        self.inner.end_time
    }

    /// Confidence
    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// MITRE Tactic
    async fn category(&self) -> Option<ThreatCategory> {
        self.inner.category.map(Into::into)
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

impl From<database::RdpBruteForce> for RdpBruteForce {
    fn from(inner: database::RdpBruteForce) -> Self {
        Self { inner }
    }
}

pub(super) struct BlocklistRdp {
    inner: database::BlocklistRdp,
}

#[Object]
impl BlocklistRdp {
    /// Start Time
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

    /// Cookie
    async fn cookie(&self) -> String {
        self.inner.cookie.clone()
    }

    /// MITRE Tactic
    async fn category(&self) -> Option<ThreatCategory> {
        self.inner.category.map(Into::into)
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

impl From<database::BlocklistRdp> for BlocklistRdp {
    fn from(inner: database::BlocklistRdp) -> Self {
        Self { inner }
    }
}
