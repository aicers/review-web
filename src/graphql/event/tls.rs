use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{country_code, find_ip_customer, find_ip_network, TriageScore};
use crate::graphql::{customer::Customer, network::Network};

pub(super) struct BlockListTls {
    inner: database::BlockListTls,
}

#[Object]
impl BlockListTls {
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

    async fn server_name(&self) -> &str {
        &self.inner.server_name
    }

    async fn alpn_protocol(&self) -> &str {
        &self.inner.alpn_protocol
    }

    async fn ja3(&self) -> &str {
        &self.inner.ja3
    }

    async fn version(&self) -> &str {
        &self.inner.version
    }

    async fn client_cipher_suites(&self) -> Vec<u16> {
        self.inner.client_cipher_suites.clone()
    }

    async fn client_extensions(&self) -> Vec<u16> {
        self.inner.client_extensions.clone()
    }

    async fn cipher(&self) -> u16 {
        self.inner.cipher
    }

    async fn extensions(&self) -> Vec<u16> {
        self.inner.extensions.clone()
    }

    async fn ja3s(&self) -> &str {
        &self.inner.ja3s
    }

    async fn serial(&self) -> &str {
        &self.inner.serial
    }

    async fn subject_country(&self) -> &str {
        &self.inner.subject_country
    }

    async fn subject_org_name(&self) -> &str {
        &self.inner.subject_org_name
    }

    async fn subject_common_name(&self) -> &str {
        &self.inner.subject_common_name
    }

    async fn validity_not_before(&self) -> i64 {
        self.inner.validity_not_before
    }

    async fn validity_not_after(&self) -> i64 {
        self.inner.validity_not_after
    }

    async fn subject_alt_name(&self) -> &str {
        &self.inner.subject_alt_name
    }

    async fn issuer_country(&self) -> &str {
        &self.inner.issuer_country
    }

    async fn issuer_org_name(&self) -> &str {
        &self.inner.issuer_org_name
    }

    async fn issuer_org_unit_name(&self) -> &str {
        &self.inner.issuer_org_unit_name
    }

    async fn issuer_common_name(&self) -> &str {
        &self.inner.issuer_common_name
    }

    async fn last_alert(&self) -> u8 {
        self.inner.last_alert
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

impl From<database::BlockListTls> for BlockListTls {
    fn from(inner: database::BlockListTls) -> Self {
        Self { inner }
    }
}

pub(super) struct SuspiciousTlsTraffic {
    inner: database::SuspiciousTlsTraffic,
}

#[Object]
impl SuspiciousTlsTraffic {
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

    async fn server_name(&self) -> &str {
        &self.inner.server_name
    }

    async fn alpn_protocol(&self) -> &str {
        &self.inner.alpn_protocol
    }

    async fn ja3(&self) -> &str {
        &self.inner.ja3
    }

    async fn version(&self) -> &str {
        &self.inner.version
    }

    async fn client_cipher_suites(&self) -> Vec<u16> {
        self.inner.client_cipher_suites.clone()
    }

    async fn client_extensions(&self) -> Vec<u16> {
        self.inner.client_extensions.clone()
    }

    async fn cipher(&self) -> u16 {
        self.inner.cipher
    }

    async fn extensions(&self) -> Vec<u16> {
        self.inner.extensions.clone()
    }

    async fn ja3s(&self) -> &str {
        &self.inner.ja3s
    }

    async fn serial(&self) -> &str {
        &self.inner.serial
    }

    async fn subject_country(&self) -> &str {
        &self.inner.subject_country
    }

    async fn subject_org_name(&self) -> &str {
        &self.inner.subject_org_name
    }

    async fn subject_common_name(&self) -> &str {
        &self.inner.subject_common_name
    }

    async fn validity_not_before(&self) -> i64 {
        self.inner.validity_not_before
    }

    async fn validity_not_after(&self) -> i64 {
        self.inner.validity_not_after
    }

    async fn subject_alt_name(&self) -> &str {
        &self.inner.subject_alt_name
    }

    async fn issuer_country(&self) -> &str {
        &self.inner.issuer_country
    }

    async fn issuer_org_name(&self) -> &str {
        &self.inner.issuer_org_name
    }

    async fn issuer_org_unit_name(&self) -> &str {
        &self.inner.issuer_org_unit_name
    }

    async fn issuer_common_name(&self) -> &str {
        &self.inner.issuer_common_name
    }

    async fn last_alert(&self) -> u8 {
        self.inner.last_alert
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

impl From<database::SuspiciousTlsTraffic> for SuspiciousTlsTraffic {
    fn from(inner: database::SuspiciousTlsTraffic) -> Self {
        Self { inner }
    }
}
