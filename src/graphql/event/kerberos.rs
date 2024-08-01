use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{country_code, find_ip_customer, find_ip_network, TriageScore};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlockListKerberos {
    inner: database::BlockListKerberos,
}

#[Object]
impl BlockListKerberos {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
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

    /// The last time the event was seen in string wthin the range
    /// representable by a `i64`.
    async fn last_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.last_time)
    }

    /// The client time in string wthin the range representable
    /// by a `i64`.
    async fn client_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.client_time)
    }

    /// The server time in string wthin the range representable
    /// by a `i64`.
    async fn server_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.server_time)
    }

    /// The error code in string wthin the range representable
    /// by a `u32`.
    async fn error_code(&self) -> StringNumber<u32> {
        StringNumber(self.inner.error_code)
    }

    async fn client_realm(&self) -> &str {
        &self.inner.client_realm
    }

    async fn cname_type(&self) -> u8 {
        self.inner.cname_type
    }

    async fn client_name(&self) -> Vec<String> {
        self.inner.client_name.clone()
    }

    async fn realm(&self) -> &str {
        &self.inner.realm
    }

    async fn sname_type(&self) -> u8 {
        self.inner.sname_type
    }

    async fn service_name(&self) -> Vec<String> {
        self.inner.service_name.clone()
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

impl From<database::BlockListKerberos> for BlockListKerberos {
    fn from(inner: database::BlockListKerberos) -> Self {
        Self { inner }
    }
}
