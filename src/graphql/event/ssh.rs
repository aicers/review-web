use super::{country_code, find_ip_customer, find_ip_network, TriageScore};
use crate::graphql::{customer::Customer, network::Network};
use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database as database;

pub(super) struct BlockListSsh {
    inner: database::BlockListSsh,
}

#[Object]
impl BlockListSsh {
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

    async fn last_time(&self) -> i64 {
        self.inner.last_time
    }

    async fn version(&self) -> i64 {
        self.inner.version
    }

    async fn auth_success(&self) -> &str {
        &self.inner.auth_success
    }

    async fn auth_attempts(&self) -> i64 {
        self.inner.auth_attempts
    }

    async fn direction(&self) -> &str {
        &self.inner.direction
    }

    async fn client(&self) -> &str {
        &self.inner.client
    }

    async fn server(&self) -> &str {
        &self.inner.server
    }

    async fn cipher_alg(&self) -> &str {
        &self.inner.cipher_alg
    }

    async fn mac_alg(&self) -> &str {
        &self.inner.mac_alg
    }

    async fn compression_alg(&self) -> &str {
        &self.inner.compression_alg
    }

    async fn kex_alg(&self) -> &str {
        &self.inner.kex_alg
    }

    async fn host_key_alg(&self) -> &str {
        &self.inner.host_key_alg
    }

    async fn host_key(&self) -> &str {
        &self.inner.host_key
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::BlockListSsh> for BlockListSsh {
    fn from(inner: database::BlockListSsh) -> Self {
        Self { inner }
    }
}
