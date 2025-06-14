use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistSmb {
    inner: database::BlocklistSmb,
}

#[Object]
impl BlocklistSmb {
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
        self.inner.last_time
    }

    async fn command(&self) -> u8 {
        self.inner.command
    }

    async fn path(&self) -> &str {
        &self.inner.path
    }

    async fn service(&self) -> &str {
        &self.inner.service
    }

    async fn file_name(&self) -> &str {
        &self.inner.file_name
    }

    async fn file_size(&self) -> StringNumber<u64> {
        StringNumber(self.inner.file_size)
    }

    async fn resource_type(&self) -> u16 {
        self.inner.resource_type
    }

    async fn fid(&self) -> u16 {
        self.inner.fid
    }

    async fn create_time(&self) -> i64 {
        self.inner.create_time
    }

    async fn access_time(&self) -> i64 {
        self.inner.access_time
    }

    async fn write_time(&self) -> i64 {
        self.inner.write_time
    }

    async fn change_time(&self) -> i64 {
        self.inner.change_time
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

impl From<database::BlocklistSmb> for BlocklistSmb {
    fn from(inner: database::BlocklistSmb) -> Self {
        Self { inner }
    }
}
