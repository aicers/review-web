use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database::event as database;

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
    /// Event Generation Time
    pub async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    pub async fn sensor(&self) -> &str {
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

    /// Destination Port (Number)
    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
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

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Duration
    ///
    /// It is measured in nanoseconds.
    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.inner.duration)
    }

    /// Packets Sent (by Source)
    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_pkts)
    }

    /// Packets Received (by Destination)
    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_pkts)
    }

    /// Layer 2 Bytes Sent (by Source)
    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_l2_bytes)
    }

    /// Layer 2 Bytes Received (by Destination)
    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_l2_bytes)
    }

    /// Query
    async fn query(&self) -> &str {
        &self.inner.query
    }

    /// Answer
    async fn answer(&self) -> &[String] {
        &self.inner.answer
    }

    /// Transaction ID
    async fn trans_id(&self) -> u16 {
        self.inner.trans_id
    }

    /// Round-Trip Time
    async fn rtt(&self) -> StringNumber<i64> {
        StringNumber(self.inner.rtt)
    }

    /// Query Class
    async fn qclass(&self) -> u16 {
        self.inner.qclass
    }

    /// Query Type
    async fn qtype(&self) -> u16 {
        self.inner.qtype
    }

    /// Response Code
    async fn rcode(&self) -> u16 {
        self.inner.rcode
    }

    /// Authoritative Answer Flag
    async fn aa_flag(&self) -> bool {
        self.inner.aa_flag
    }

    /// Truncated Flag
    async fn tc_flag(&self) -> bool {
        self.inner.tc_flag
    }

    /// Recursion Desired Flag
    async fn rd_flag(&self) -> bool {
        self.inner.rd_flag
    }

    /// Recursion Available Flag
    async fn ra_flag(&self) -> bool {
        self.inner.ra_flag
    }

    /// Time to Live
    async fn ttl(&self) -> &[i32] {
        &self.inner.ttl
    }

    /// Confidence
    pub async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// MITRE Tactic
    pub async fn category(&self) -> Option<ThreatCategory> {
        self.inner.category.map(Into::into)
    }

    /// Triage Scores
    pub async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level
    pub async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }

    /// Learning Method
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
    /// Event Generation Time
    pub async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    pub async fn sensor(&self) -> &str {
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

    /// Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Duration
    ///
    /// It is measured in nanoseconds.
    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.inner.duration)
    }

    /// Packets Sent (by Source)
    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_pkts)
    }

    /// Packets Received (by Destination)
    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_pkts)
    }

    /// Layer 2 Bytes Sent (by Source)
    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_l2_bytes)
    }

    /// Layer 2 Bytes Received (by Destination)
    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_l2_bytes)
    }

    /// Query
    async fn query(&self) -> &str {
        &self.inner.query
    }

    /// Answer
    async fn answer(&self) -> &[String] {
        &self.inner.answer
    }

    /// Transaction ID
    async fn trans_id(&self) -> u16 {
        self.inner.trans_id
    }

    /// Round-Trip Time
    async fn rtt(&self) -> StringNumber<i64> {
        StringNumber(self.inner.rtt)
    }

    /// Query Class
    async fn qclass(&self) -> u16 {
        self.inner.qclass
    }

    /// Query Type
    async fn qtype(&self) -> u16 {
        self.inner.qtype
    }

    /// Response Code
    async fn rcode(&self) -> u16 {
        self.inner.rcode
    }

    /// Authoritative Answer Flag
    async fn aa_flag(&self) -> bool {
        self.inner.aa_flag
    }

    /// Truncated Flag
    async fn tc_flag(&self) -> bool {
        self.inner.tc_flag
    }

    /// Recursion Desired Flag
    async fn rd_flag(&self) -> bool {
        self.inner.rd_flag
    }

    /// Recursion Available Flag
    async fn ra_flag(&self) -> bool {
        self.inner.ra_flag
    }

    /// Time to Live
    async fn ttl(&self) -> &[i32] {
        &self.inner.ttl
    }

    /// Confidence
    pub async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// MITRE Tactic
    pub async fn category(&self) -> Option<ThreatCategory> {
        self.inner.category.map(Into::into)
    }

    /// Triage Scores
    pub async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level
    pub async fn level(&self) -> ThreatLevel {
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
    /// Event Generation Time
    pub async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    pub async fn sensor(&self) -> &str {
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

    /// Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Duration
    ///
    /// It is measured in nanoseconds.
    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.inner.duration)
    }

    /// Packets Sent (by Source)
    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_pkts)
    }

    /// Packets Received (by Destination)
    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_pkts)
    }

    /// Layer 2 Bytes Sent (by Source)
    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_l2_bytes)
    }

    /// Layer 2 Bytes Received (by Destination)
    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_l2_bytes)
    }

    /// Query
    async fn query(&self) -> &str {
        &self.inner.query
    }

    /// Answer
    async fn answer(&self) -> &[String] {
        &self.inner.answer
    }

    /// Transaction ID
    async fn trans_id(&self) -> u16 {
        self.inner.trans_id
    }

    /// Round-Trip Time
    async fn rtt(&self) -> StringNumber<i64> {
        StringNumber(self.inner.rtt)
    }

    /// Query Class
    async fn qclass(&self) -> u16 {
        self.inner.qclass
    }

    /// Query Type
    async fn qtype(&self) -> u16 {
        self.inner.qtype
    }

    /// Response Code
    async fn rcode(&self) -> u16 {
        self.inner.rcode
    }

    /// Authoritative Answer Flag
    async fn aa_flag(&self) -> bool {
        self.inner.aa_flag
    }

    /// Truncated Flag
    async fn tc_flag(&self) -> bool {
        self.inner.tc_flag
    }

    /// Recursion Desired Flag
    async fn rd_flag(&self) -> bool {
        self.inner.rd_flag
    }

    /// Recursion Available Flag
    async fn ra_flag(&self) -> bool {
        self.inner.ra_flag
    }

    /// Time to Live
    async fn ttl(&self) -> &[i32] {
        &self.inner.ttl
    }

    /// Coin List
    async fn coins(&self) -> &[String] {
        &self.inner.coins
    }

    /// Confidence
    pub async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// MITRE Tactic
    pub async fn category(&self) -> Option<ThreatCategory> {
        self.inner.category.map(Into::into)
    }

    /// Triage Scores
    pub async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level
    pub async fn level(&self) -> ThreatLevel {
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
    /// Event Generation Time
    pub async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    pub async fn sensor(&self) -> &str {
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

    /// Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Duration
    ///
    /// It is measured in nanoseconds.
    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.inner.duration)
    }

    /// Packets Sent (by Source)
    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_pkts)
    }

    /// Packets Received (by Destination)
    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_pkts)
    }

    /// Layer 2 Bytes Sent (by Source)
    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_l2_bytes)
    }

    /// Layer 2 Bytes Received (by Destination)
    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_l2_bytes)
    }

    /// Query
    async fn query(&self) -> &str {
        &self.inner.query
    }

    /// Answer
    async fn answer(&self) -> &[String] {
        &self.inner.answer
    }

    /// Transaction ID
    async fn trans_id(&self) -> u16 {
        self.inner.trans_id
    }

    /// Round-Trip Time
    async fn rtt(&self) -> StringNumber<i64> {
        StringNumber(self.inner.rtt)
    }

    /// Query Class
    async fn qclass(&self) -> u16 {
        self.inner.qclass
    }

    /// Query Type
    async fn qtype(&self) -> u16 {
        self.inner.qtype
    }

    /// Response Code
    async fn rcode(&self) -> u16 {
        self.inner.rcode
    }

    /// Authoritative Answer Flag
    async fn aa_flag(&self) -> bool {
        self.inner.aa_flag
    }

    /// Truncated Flag
    async fn tc_flag(&self) -> bool {
        self.inner.tc_flag
    }

    /// Recursion Desired Flag
    async fn rd_flag(&self) -> bool {
        self.inner.rd_flag
    }

    /// Recursion Available Flag
    async fn ra_flag(&self) -> bool {
        self.inner.ra_flag
    }

    /// Time to Live
    async fn ttl(&self) -> &[i32] {
        &self.inner.ttl
    }

    /// MITRE Tactic
    pub async fn category(&self) -> Option<ThreatCategory> {
        self.inner.category.map(Into::into)
    }

    /// Confidence
    pub async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// Triage Scores
    pub async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level
    pub async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl From<database::BlocklistDns> for BlocklistDns {
    fn from(inner: database::BlocklistDns) -> Self {
        Self { inner }
    }
}
