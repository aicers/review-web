use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{
    customer::Customer, filter::LearningMethod, network::Network, triage::ThreatCategory,
};

#[allow(clippy::module_name_repetitions)]
pub(super) struct DnsCovertChannel {
    inner: database::DnsCovertChannel,
}

#[Object]
impl DnsCovertChannel {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    async fn session_end_time(&self) -> DateTime<Utc> {
        self.inner.session_end_time
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
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

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
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

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn query(&self) -> &str {
        &self.inner.query
    }

    async fn answer(&self) -> &[String] {
        &self.inner.answer
    }

    async fn trans_id(&self) -> u16 {
        self.inner.trans_id
    }

    async fn rtt(&self) -> StringNumber<i64> {
        StringNumber(self.inner.rtt)
    }

    async fn qclass(&self) -> u16 {
        self.inner.qclass
    }

    async fn qtype(&self) -> u16 {
        self.inner.qtype
    }

    async fn rcode(&self) -> u16 {
        self.inner.rcode
    }

    async fn aa_flag(&self) -> bool {
        self.inner.aa_flag
    }

    async fn tc_flag(&self) -> bool {
        self.inner.tc_flag
    }

    async fn rd_flag(&self) -> bool {
        self.inner.rd_flag
    }

    async fn ra_flag(&self) -> bool {
        self.inner.ra_flag
    }

    async fn ttl(&self) -> &[i32] {
        &self.inner.ttl
    }

    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }

    async fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }
}

impl From<database::DnsCovertChannel> for DnsCovertChannel {
    fn from(inner: database::DnsCovertChannel) -> Self {
        Self { inner }
    }
}

#[allow(clippy::module_name_repetitions)]
pub(super) struct LockyRansomware {
    inner: database::LockyRansomware,
}

#[Object]
impl LockyRansomware {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    async fn session_end_time(&self) -> DateTime<Utc> {
        self.inner.session_end_time
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
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

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
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

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn query(&self) -> &str {
        &self.inner.query
    }

    async fn answer(&self) -> &[String] {
        &self.inner.answer
    }

    async fn trans_id(&self) -> u16 {
        self.inner.trans_id
    }

    async fn rtt(&self) -> StringNumber<i64> {
        StringNumber(self.inner.rtt)
    }

    async fn qclass(&self) -> u16 {
        self.inner.qclass
    }

    async fn qtype(&self) -> u16 {
        self.inner.qtype
    }

    async fn rcode(&self) -> u16 {
        self.inner.rcode
    }

    async fn aa_flag(&self) -> bool {
        self.inner.aa_flag
    }

    async fn tc_flag(&self) -> bool {
        self.inner.tc_flag
    }

    async fn rd_flag(&self) -> bool {
        self.inner.rd_flag
    }

    async fn ra_flag(&self) -> bool {
        self.inner.ra_flag
    }

    async fn ttl(&self) -> &[i32] {
        &self.inner.ttl
    }

    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl From<database::LockyRansomware> for LockyRansomware {
    fn from(inner: database::LockyRansomware) -> Self {
        Self { inner }
    }
}

pub(super) struct CryptocurrencyMiningPool {
    inner: database::CryptocurrencyMiningPool,
}

#[Object]
impl CryptocurrencyMiningPool {
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

    async fn query(&self) -> &str {
        &self.inner.query
    }

    async fn answer(&self) -> &[String] {
        &self.inner.answer
    }

    async fn trans_id(&self) -> u16 {
        self.inner.trans_id
    }

    async fn rtt(&self) -> StringNumber<i64> {
        StringNumber(self.inner.rtt)
    }

    async fn qclass(&self) -> u16 {
        self.inner.qclass
    }

    async fn qtype(&self) -> u16 {
        self.inner.qtype
    }

    async fn rcode(&self) -> u16 {
        self.inner.rcode
    }

    async fn aa_flag(&self) -> bool {
        self.inner.aa_flag
    }

    async fn tc_flag(&self) -> bool {
        self.inner.tc_flag
    }

    async fn rd_flag(&self) -> bool {
        self.inner.rd_flag
    }

    async fn ra_flag(&self) -> bool {
        self.inner.ra_flag
    }

    async fn ttl(&self) -> &[i32] {
        &self.inner.ttl
    }

    async fn coins(&self) -> &[String] {
        &self.inner.coins
    }

    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl From<database::CryptocurrencyMiningPool> for CryptocurrencyMiningPool {
    fn from(inner: database::CryptocurrencyMiningPool) -> Self {
        Self { inner }
    }
}

pub(super) struct BlocklistDns {
    inner: database::BlocklistDns,
}

#[Object]
impl BlocklistDns {
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

    async fn end_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.end_time)
    }

    async fn query(&self) -> &str {
        &self.inner.query
    }

    async fn answer(&self) -> &[String] {
        &self.inner.answer
    }

    async fn trans_id(&self) -> u16 {
        self.inner.trans_id
    }

    async fn rtt(&self) -> StringNumber<i64> {
        StringNumber(self.inner.rtt)
    }

    async fn qclass(&self) -> u16 {
        self.inner.qclass
    }

    async fn qtype(&self) -> u16 {
        self.inner.qtype
    }

    async fn rcode(&self) -> u16 {
        self.inner.rcode
    }

    async fn aa_flag(&self) -> bool {
        self.inner.aa_flag
    }

    async fn tc_flag(&self) -> bool {
        self.inner.tc_flag
    }

    async fn rd_flag(&self) -> bool {
        self.inner.rd_flag
    }

    async fn ra_flag(&self) -> bool {
        self.inner.ra_flag
    }

    async fn ttl(&self) -> &[i32] {
        &self.inner.ttl
    }

    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl From<database::BlocklistDns> for BlocklistDns {
    fn from(inner: database::BlocklistDns) -> Self {
        Self { inner }
    }
}
