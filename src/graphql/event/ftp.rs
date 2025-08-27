use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database::event as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

#[allow(clippy::module_name_repetitions)]
pub(super) struct FtpBruteForce {
    inner: database::FtpBruteForce,
}

#[Object]
impl FtpBruteForce {
    /// Start Time
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Source IP (Address)
    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// Source Country
    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    /// Source Customer
    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    /// Source Network
    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    /// Destination IP (Address)
    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// Destination Country
    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    /// Destination Customer
    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    /// Destination Network
    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    /// Destination Port (Number)
    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// User List
    async fn user_list(&self) -> &[String] {
        &self.inner.user_list
    }

    /// Detection Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Detection End Time
    async fn end_time(&self) -> DateTime<Utc> {
        self.inner.end_time
    }

    /// Is Internal
    async fn is_internal(&self) -> bool {
        self.inner.is_internal
    }

    /// Confidence
    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// MITRE Tactic
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// Triage Scores
    async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level
    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
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
    /// Start Time
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Source IP (Address)
    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// Source Country
    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    /// Source Customer
    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    /// Source Network
    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    /// Source Port (Number)
    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    /// Destination IP (Address)
    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// Destination Country
    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    /// Destination Customer
    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    /// Destination Network
    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    /// Destination Port (Number)
    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Username
    async fn user(&self) -> &str {
        &self.inner.user
    }

    /// Password
    async fn password(&self) -> &str {
        &self.inner.password
    }

    /// Command
    async fn command(&self) -> &str {
        &self.inner.command
    }

    /// Reply Code
    async fn reply_code(&self) -> &str {
        &self.inner.reply_code
    }

    /// Reply Message
    async fn reply_msg(&self) -> &str {
        &self.inner.reply_msg
    }

    /// Passive Mode Flag
    async fn data_passive(&self) -> bool {
        self.inner.data_passive
    }

    /// Data Channel Source IP (Address)
    async fn data_orig_addr(&self) -> String {
        self.inner.data_orig_addr.to_string()
    }

    /// Data Channel Destination IP (Address)
    async fn data_resp_addr(&self) -> String {
        self.inner.data_resp_addr.to_string()
    }

    /// Data Channel Destination Port (Number)
    async fn data_resp_port(&self) -> u16 {
        self.inner.data_resp_port
    }

    /// Filename
    async fn file(&self) -> &str {
        &self.inner.file
    }

    /// File Size
    async fn file_size(&self) -> StringNumber<u64> {
        StringNumber(self.inner.file_size)
    }

    /// File ID
    async fn file_id(&self) -> &str {
        &self.inner.file_id
    }

    /// Confidence
    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// MITRE Tactic
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// Triage Scores
    async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level
    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Low
    }
}

impl From<database::FtpPlainText> for FtpPlainText {
    fn from(inner: database::FtpPlainText) -> Self {
        Self { inner }
    }
}

#[allow(clippy::module_name_repetitions)]
pub(super) struct BlocklistFtp {
    inner: database::BlocklistFtp,
}

#[Object]
impl BlocklistFtp {
    /// Start Time
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Source IP (Address)
    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// Source Country
    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    /// Source Customer
    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    /// Source Network
    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    /// Source Port (Number)
    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    /// Destination IP (Address)
    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// Destination Country
    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    /// Destination Customer
    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    /// Destination Network
    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    /// Destination Port (Number)
    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// End Time
    async fn end_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.end_time)
    }

    /// Username
    async fn user(&self) -> &str {
        &self.inner.user
    }

    /// Password
    async fn password(&self) -> &str {
        &self.inner.password
    }

    /// Command
    async fn command(&self) -> &str {
        &self.inner.command
    }

    /// Reply Code
    async fn reply_code(&self) -> &str {
        &self.inner.reply_code
    }

    /// Reply Message
    async fn reply_msg(&self) -> &str {
        &self.inner.reply_msg
    }

    /// Passive Mode Flag
    async fn data_passive(&self) -> bool {
        self.inner.data_passive
    }

    /// Data Channel Source IP (Address)
    async fn data_orig_addr(&self) -> String {
        self.inner.data_orig_addr.to_string()
    }

    /// Data Channel Destination IP (Address)
    async fn data_resp_addr(&self) -> String {
        self.inner.data_resp_addr.to_string()
    }

    /// Data Channel Destination Port (Number)
    async fn data_resp_port(&self) -> u16 {
        self.inner.data_resp_port
    }

    /// Filename
    async fn file(&self) -> &str {
        &self.inner.file
    }

    /// File Size
    async fn file_size(&self) -> StringNumber<u64> {
        StringNumber(self.inner.file_size)
    }

    /// File ID
    async fn file_id(&self) -> &str {
        &self.inner.file_id
    }

    /// MITRE Tactic
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// Triage Scores
    async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level
    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl From<database::BlocklistFtp> for BlocklistFtp {
    fn from(inner: database::BlocklistFtp) -> Self {
        Self { inner }
    }
}
