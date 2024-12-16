use async_graphql::{Context, Object, Result, StringNumber, ID};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{country_code, find_ip_customer, find_ip_network, TriageScore};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

#[allow(clippy::module_name_repetitions)]
pub(super) struct NetworkThreat {
    inner: database::NetworkThreat,
}

#[Object]
impl NetworkThreat {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    async fn src_addr(&self) -> String {
        self.inner.orig_addr.to_string()
    }

    async fn src_port(&self) -> u16 {
        self.inner.orig_port
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.orig_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.orig_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.orig_addr)
    }

    async fn dst_addr(&self) -> String {
        self.inner.resp_addr.to_string()
    }

    async fn dst_port(&self) -> u16 {
        self.inner.resp_port
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.resp_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.resp_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.resp_addr)
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn service(&self) -> &str {
        &self.inner.service
    }

    /// The last time the event was seen in string within the representable
    /// range of `i64`.
    async fn last_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.last_time)
    }

    async fn content(&self) -> &str {
        &self.inner.content
    }

    async fn db_name(&self) -> &str {
        &self.inner.db_name
    }

    /// The rule ID of the event in string within the representable
    /// range of `u32`.
    async fn rule_id(&self) -> ID {
        ID(self.inner.rule_id.to_string())
    }

    async fn matched_to(&self) -> &str {
        &self.inner.matched_to
    }

    /// The cluster ID of the event in string within the representable
    /// range of `usize`.
    async fn cluster_id(&self) -> ID {
        ID(self.inner.cluster_id.to_string())
    }

    async fn attack_kind(&self) -> &str {
        &self.inner.attack_kind
    }

    async fn confidence(&self) -> f32 {
        self.inner.confidence
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

impl From<database::NetworkThreat> for NetworkThreat {
    fn from(inner: database::NetworkThreat) -> Self {
        Self { inner }
    }
}
