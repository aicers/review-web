use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

#[allow(clippy::module_name_repetitions)]
pub(super) struct RdpBruteForce {
    inner: database::RdpBruteForce,
}

#[Object]
impl RdpBruteForce {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn dst_addrs(&self) -> Vec<String> {
        self.inner
            .dst_addrs
            .iter()
            .map(ToString::to_string)
            .collect()
    }

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

    async fn dst_customers(&self, ctx: &Context<'_>) -> Result<Vec<Option<Customer>>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        let mut customers = vec![];
        for dst_addr in &self.inner.dst_addrs {
            customers.push(find_ip_customer(&map, *dst_addr)?);
        }
        Ok(customers)
    }

    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    async fn last_time(&self) -> DateTime<Utc> {
        self.inner.last_time
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::RdpBruteForce> for RdpBruteForce {
    fn from(inner: database::RdpBruteForce) -> Self {
        Self { inner }
    }
}

pub(super) struct BlockListRdp {
    inner: database::BlockListRdp,
}

#[Object]
impl BlockListRdp {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    // The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn last_time(&self) -> i64 {
        self.inner.last_time
    }

    async fn cookie(&self) -> String {
        self.inner.cookie.to_string()
    }

    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::BlockListRdp> for BlockListRdp {
    fn from(inner: database::BlockListRdp) -> Self {
        Self { inner }
    }
}
