use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{country_code, find_ip_customer, find_ip_network, TriageScore};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlockListDhcp {
    inner: database::BlockListDhcp,
}

#[Object]
impl BlockListDhcp {
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

    async fn msg_type(&self) -> u8 {
        self.inner.msg_type
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

    async fn subnet_mask(&self) -> String {
        self.inner.subnet_mask.to_string()
    }

    async fn router(&self) -> String {
        vector_to_string(&self.inner.router)
    }

    async fn domain_name_server(&self) -> String {
        vector_to_string(&self.inner.domain_name_server)
    }

    async fn req_ip_addr(&self) -> String {
        self.inner.req_ip_addr.to_string()
    }

    async fn lease_time(&self) -> u32 {
        self.inner.lease_time
    }

    async fn server_id(&self) -> String {
        self.inner.server_id.to_string()
    }

    async fn param_req_list(&self) -> String {
        vector_to_string(&self.inner.param_req_list)
    }

    async fn message(&self) -> &str {
        &self.inner.message
    }

    async fn renewal_time(&self) -> u32 {
        self.inner.renewal_time
    }

    async fn rebinding_time(&self) -> u32 {
        self.inner.rebinding_time
    }

    async fn class_id(&self) -> String {
        to_hex_string(&self.inner.class_id)
    }

    async fn client_id_type(&self) -> u8 {
        self.inner.client_id_type
    }

    async fn client_id(&self) -> String {
        to_hex_string(&self.inner.client_id)
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

impl From<database::BlockListDhcp> for BlockListDhcp {
    fn from(inner: database::BlockListDhcp) -> Self {
        Self { inner }
    }
}

fn to_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<String>>()
        .join(":")
}

fn vector_to_string<T: std::fmt::Display>(vec: &[T]) -> String {
    vec.iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(", ")
}
