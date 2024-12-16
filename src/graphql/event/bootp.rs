use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{country_code, find_ip_customer, find_ip_network, TriageScore};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlockListBootp {
    inner: database::BlockListBootp,
}

#[Object]
impl BlockListBootp {
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

    async fn last_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.last_time)
    }

    async fn op(&self) -> u8 {
        self.inner.op
    }

    async fn htype(&self) -> u8 {
        self.inner.htype
    }

    async fn hops(&self) -> u8 {
        self.inner.hops
    }

    async fn xid(&self) -> StringNumber<u32> {
        StringNumber(self.inner.xid)
    }

    async fn ciaddr(&self) -> String {
        self.inner.ciaddr.to_string()
    }

    async fn yiaddr(&self) -> String {
        self.inner.yiaddr.to_string()
    }

    async fn siaddr(&self) -> String {
        self.inner.siaddr.to_string()
    }

    async fn giaddr(&self) -> String {
        self.inner.giaddr.to_string()
    }

    async fn chaddr(&self) -> String {
        self.inner
            .chaddr
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<String>>()
            .join(":")
    }

    async fn sname(&self) -> &str {
        &self.inner.sname
    }

    async fn file(&self) -> &str {
        &self.inner.file
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

impl From<database::BlockListBootp> for BlockListBootp {
    fn from(inner: database::BlockListBootp) -> Self {
        Self { inner }
    }
}
