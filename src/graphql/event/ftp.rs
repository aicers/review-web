use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{country_code, find_ip_customer, find_ip_network, TriageScore};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

#[allow(clippy::module_name_repetitions)]
pub(super) struct FtpBruteForce {
    inner: database::FtpBruteForce,
}

#[Object]
impl FtpBruteForce {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
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

    async fn user_list(&self) -> Vec<String> {
        self.inner.user_list.clone()
    }

    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    async fn last_time(&self) -> DateTime<Utc> {
        self.inner.last_time
    }

    async fn is_internal(&self) -> bool {
        self.inner.is_internal
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

impl From<database::FtpBruteForce> for FtpBruteForce {
    fn from(inner: database::FtpBruteForce) -> Self {
        Self { inner }
    }
}

#[allow(clippy::module_name_repetitions)]
pub(super) struct FtpPlainText {
    inner: database::FtpPlainText,
}

#[Object]
impl FtpPlainText {
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

    async fn user(&self) -> &str {
        &self.inner.user
    }

    async fn password(&self) -> &str {
        &self.inner.password
    }

    async fn command(&self) -> &str {
        &self.inner.command
    }

    async fn reply_code(&self) -> &str {
        &self.inner.reply_code
    }

    async fn reply_msg(&self) -> &str {
        &self.inner.reply_msg
    }

    async fn data_passive(&self) -> bool {
        self.inner.data_passive
    }

    async fn data_orig_addr(&self) -> String {
        self.inner.data_orig_addr.to_string()
    }

    async fn data_resp_addr(&self) -> String {
        self.inner.data_resp_addr.to_string()
    }

    async fn data_resp_port(&self) -> u16 {
        self.inner.data_resp_port
    }

    async fn file(&self) -> &str {
        &self.inner.file
    }

    async fn file_size(&self) -> u64 {
        self.inner.file_size
    }

    async fn file_id(&self) -> &str {
        &self.inner.file_id
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

impl From<database::FtpPlainText> for FtpPlainText {
    fn from(inner: database::FtpPlainText) -> Self {
        Self { inner }
    }
}

#[allow(clippy::module_name_repetitions)]
pub(super) struct BlockListFtp {
    inner: database::BlockListFtp,
}

#[Object]
impl BlockListFtp {
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

    async fn user(&self) -> &str {
        &self.inner.user
    }

    async fn password(&self) -> &str {
        &self.inner.password
    }

    async fn command(&self) -> &str {
        &self.inner.command
    }

    async fn reply_code(&self) -> &str {
        &self.inner.reply_code
    }

    async fn reply_msg(&self) -> &str {
        &self.inner.reply_msg
    }

    async fn data_passive(&self) -> bool {
        self.inner.data_passive
    }

    async fn data_orig_addr(&self) -> String {
        self.inner.data_orig_addr.to_string()
    }

    async fn data_resp_addr(&self) -> String {
        self.inner.data_resp_addr.to_string()
    }

    async fn data_resp_port(&self) -> u16 {
        self.inner.data_resp_port
    }

    async fn file(&self) -> &str {
        &self.inner.file
    }

    async fn file_size(&self) -> u64 {
        self.inner.file_size
    }

    async fn file_id(&self) -> &str {
        &self.inner.file_id
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

impl From<database::BlockListFtp> for BlockListFtp {
    fn from(inner: database::BlockListFtp) -> Self {
        Self { inner }
    }
}
