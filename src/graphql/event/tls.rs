use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistTls {
    inner: database::BlocklistTls,
}

#[Object]
impl BlocklistTls {
    /// Timestamp
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
    /// TCP: 6, UDP: 17
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// End Time
    async fn end_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.end_time)
    }

    /// Server Name
    async fn server_name(&self) -> &str {
        &self.inner.server_name
    }

    /// ALPN Protocol
    async fn alpn_protocol(&self) -> &str {
        &self.inner.alpn_protocol
    }

    /// JA3 Fingerprint
    async fn ja3(&self) -> &str {
        &self.inner.ja3
    }

    /// TLS Version
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// Client Cipher Suites
    async fn client_cipher_suites(&self) -> &[u16] {
        &self.inner.client_cipher_suites
    }

    /// Client Extensions
    async fn client_extensions(&self) -> &[u16] {
        &self.inner.client_extensions
    }

    /// Cipher
    async fn cipher(&self) -> u16 {
        self.inner.cipher
    }

    /// Extensions
    async fn extensions(&self) -> &[u16] {
        &self.inner.extensions
    }

    /// JA3S Fingerprint
    async fn ja3s(&self) -> &str {
        &self.inner.ja3s
    }

    /// Certificate Serial
    async fn serial(&self) -> &str {
        &self.inner.serial
    }

    /// Subject Country
    async fn subject_country(&self) -> &str {
        &self.inner.subject_country
    }

    /// Subject Organization Name
    async fn subject_org_name(&self) -> &str {
        &self.inner.subject_org_name
    }

    /// Subject Common Name
    async fn subject_common_name(&self) -> &str {
        &self.inner.subject_common_name
    }

    /// Validity Not Before
    async fn validity_not_before(&self) -> StringNumber<i64> {
        StringNumber(self.inner.validity_not_before)
    }

    /// Validity Not After
    async fn validity_not_after(&self) -> StringNumber<i64> {
        StringNumber(self.inner.validity_not_after)
    }

    /// Subject Alternative Name
    async fn subject_alt_name(&self) -> &str {
        &self.inner.subject_alt_name
    }

    /// Issuer Country
    async fn issuer_country(&self) -> &str {
        &self.inner.issuer_country
    }

    /// Issuer Organization Name
    async fn issuer_org_name(&self) -> &str {
        &self.inner.issuer_org_name
    }

    /// Issuer Organization Unit Name
    async fn issuer_org_unit_name(&self) -> &str {
        &self.inner.issuer_org_unit_name
    }

    /// Issuer Common Name
    async fn issuer_common_name(&self) -> &str {
        &self.inner.issuer_common_name
    }

    /// Last Alert
    async fn last_alert(&self) -> u8 {
        self.inner.last_alert
    }

    /// MITRE Tactic
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// Confidence
    async fn confidence(&self) -> f32 {
        self.inner.confidence
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

impl From<database::BlocklistTls> for BlocklistTls {
    fn from(inner: database::BlocklistTls) -> Self {
        Self { inner }
    }
}

pub(super) struct SuspiciousTlsTraffic {
    inner: database::SuspiciousTlsTraffic,
}

#[Object]
impl SuspiciousTlsTraffic {
    /// Timestamp
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
    /// TCP: 6, UDP: 17
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// End Time
    async fn end_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.end_time)
    }

    /// Server Name
    async fn server_name(&self) -> &str {
        &self.inner.server_name
    }

    /// ALPN Protocol
    async fn alpn_protocol(&self) -> &str {
        &self.inner.alpn_protocol
    }

    /// JA3 Fingerprint
    async fn ja3(&self) -> &str {
        &self.inner.ja3
    }

    /// TLS Version
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// Client Cipher Suites
    async fn client_cipher_suites(&self) -> &[u16] {
        &self.inner.client_cipher_suites
    }

    /// Client Extensions
    async fn client_extensions(&self) -> &[u16] {
        &self.inner.client_extensions
    }

    /// Cipher
    async fn cipher(&self) -> u16 {
        self.inner.cipher
    }

    /// Extensions
    async fn extensions(&self) -> &[u16] {
        &self.inner.extensions
    }

    /// JA3S Fingerprint
    async fn ja3s(&self) -> &str {
        &self.inner.ja3s
    }

    /// Certificate Serial
    async fn serial(&self) -> &str {
        &self.inner.serial
    }

    /// Subject Country
    async fn subject_country(&self) -> &str {
        &self.inner.subject_country
    }

    /// Subject Organization Name
    async fn subject_org_name(&self) -> &str {
        &self.inner.subject_org_name
    }

    /// Subject Common Name
    async fn subject_common_name(&self) -> &str {
        &self.inner.subject_common_name
    }

    /// Validity Not Before
    async fn validity_not_before(&self) -> StringNumber<i64> {
        StringNumber(self.inner.validity_not_before)
    }

    /// Validity Not After
    async fn validity_not_after(&self) -> StringNumber<i64> {
        StringNumber(self.inner.validity_not_after)
    }

    /// Subject Alternative Name
    async fn subject_alt_name(&self) -> &str {
        &self.inner.subject_alt_name
    }

    /// Issuer Country
    async fn issuer_country(&self) -> &str {
        &self.inner.issuer_country
    }

    /// Issuer Organization Name
    async fn issuer_org_name(&self) -> &str {
        &self.inner.issuer_org_name
    }

    /// Issuer Organization Unit Name
    async fn issuer_org_unit_name(&self) -> &str {
        &self.inner.issuer_org_unit_name
    }

    /// Issuer Common Name
    async fn issuer_common_name(&self) -> &str {
        &self.inner.issuer_common_name
    }

    /// Last Alert
    async fn last_alert(&self) -> u8 {
        self.inner.last_alert
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

impl From<database::SuspiciousTlsTraffic> for SuspiciousTlsTraffic {
    fn from(inner: database::SuspiciousTlsTraffic) -> Self {
        Self { inner }
    }
}
