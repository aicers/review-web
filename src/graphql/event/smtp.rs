use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistSmtp {
    inner: database::BlocklistSmtp,
}

#[Object]
impl BlocklistSmtp {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
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

    async fn end_time(&self) -> i64 {
        self.inner.end_time
    }

    async fn mailfrom(&self) -> &str {
        &self.inner.mailfrom
    }

    async fn date(&self) -> &str {
        &self.inner.date
    }

    async fn from(&self) -> &str {
        &self.inner.from
    }

    async fn to(&self) -> &str {
        &self.inner.to
    }

    async fn subject(&self) -> &str {
        &self.inner.subject
    }

    async fn agent(&self) -> &str {
        &self.inner.agent
    }

    async fn state(&self) -> &str {
        &self.inner.state
    }

    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl From<database::BlocklistSmtp> for BlocklistSmtp {
    fn from(inner: database::BlocklistSmtp) -> Self {
        Self { inner }
    }
}
