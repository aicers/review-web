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
    /// Timestamp (타임스탬프)
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor (센서)
    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Source IP Address (출발지 IP 주소)
    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// Source Country (출발지 국가) - The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    /// Source Customer (출발지 고객)
    /// Source Customer (출발지 고객)
    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    /// Source Network (출발지 네트워크)
    /// Source Network (출발지 네트워크)
    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    /// Source Port Number (출발지 포트 번호)
    /// Source Port Number (출발지 포트 번호)
    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    /// Destination IP Address (목적지 IP 주소)
    /// Destination IP Address (목적지 IP 주소)
    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// Destination Country (목적지 국가) - The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    /// Destination Customer (목적지 고객)
    /// Destination Customer (목적지 고객)
    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    /// Destination Network (목적지 네트워크)
    /// Destination Network (목적지 네트워크)
    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    /// Destination Port Number (목적지 포트 번호)
    /// Destination Port Number (목적지 포트 번호)
    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    /// Protocol Number (프로토콜 번호) - TCP: 6, UDP: 17
    /// Protocol Number (프로토콜 번호) - TCP: 6, UDP: 17
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// End Time (종료 시간)
    /// End Time (종료 시간)
    async fn end_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.end_time)
    }

    /// Server Name (서버명)
    /// Server Name (서버명)
    async fn server_name(&self) -> &str {
        &self.inner.server_name
    }

    /// ALPN Protocol (ALPN 프로토콜)
    /// ALPN Protocol (ALPN 프로토콜)
    async fn alpn_protocol(&self) -> &str {
        &self.inner.alpn_protocol
    }

    /// JA3 Fingerprint (JA3 핑거프린트)
    /// JA3 Fingerprint (JA3 핑거프린트)
    async fn ja3(&self) -> &str {
        &self.inner.ja3
    }

    /// TLS Version (TLS 버전)
    /// TLS Version (TLS 버전)
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// Client Cipher Suites (클라이언트 암호 시트 목록)
    /// Client Cipher Suites (클라이언트 암호 시트 목록)
    async fn client_cipher_suites(&self) -> &[u16] {
        &self.inner.client_cipher_suites
    }

    /// Client Extensions (클라이언트 확장 목록)
    /// Client Extensions (클라이언트 확장 목록)
    async fn client_extensions(&self) -> &[u16] {
        &self.inner.client_extensions
    }

    /// Cipher (암호 시트)
    /// Cipher (암호 시트)
    async fn cipher(&self) -> u16 {
        self.inner.cipher
    }

    /// Extensions (확장 목록)
    /// Extensions (확장 목록)
    async fn extensions(&self) -> &[u16] {
        &self.inner.extensions
    }

    /// JA3S Fingerprint (JA3S 핑거프린트)
    /// JA3S Fingerprint (JA3S 핑거프린트)
    async fn ja3s(&self) -> &str {
        &self.inner.ja3s
    }

    /// Certificate Serial (인증서 시리얼)
    /// Certificate Serial (인증서 시리얼)
    async fn serial(&self) -> &str {
        &self.inner.serial
    }

    /// Subject Country (인증서 주체 국가)
    /// Subject Country (인증서 주체 국가)
    async fn subject_country(&self) -> &str {
        &self.inner.subject_country
    }

    /// Subject Organization Name (인증서 주체 조직명)
    /// Subject Organization Name (인증서 주체 조직명)
    async fn subject_org_name(&self) -> &str {
        &self.inner.subject_org_name
    }

    /// Subject Common Name (인증서 주체 공통명)
    /// Subject Common Name (인증서 주체 공통명)
    async fn subject_common_name(&self) -> &str {
        &self.inner.subject_common_name
    }

    /// Validity Not Before (유효성 시작 시간)
    /// Validity Not Before (유효성 시작 시간)
    async fn validity_not_before(&self) -> StringNumber<i64> {
        StringNumber(self.inner.validity_not_before)
    }

    /// Validity Not After (유효성 종료 시간)
    /// Validity Not After (유효성 종료 시간)
    async fn validity_not_after(&self) -> StringNumber<i64> {
        StringNumber(self.inner.validity_not_after)
    }

    /// Subject Alternative Name (인증서 주체 대체명)
    /// Subject Alternative Name (인증서 주체 대체명)
    async fn subject_alt_name(&self) -> &str {
        &self.inner.subject_alt_name
    }

    /// Issuer Country (인증서 발급자 국가)
    /// Issuer Country (인증서 발급자 국가)
    async fn issuer_country(&self) -> &str {
        &self.inner.issuer_country
    }

    /// Issuer Organization Name (인증서 발급자 조직명)
    /// Issuer Organization Name (인증서 발급자 조직명)
    async fn issuer_org_name(&self) -> &str {
        &self.inner.issuer_org_name
    }

    /// Issuer Organization Unit Name (인증서 발급자 조직 단위명)
    /// Issuer Organization Unit Name (인증서 발급자 조직 단위명)
    async fn issuer_org_unit_name(&self) -> &str {
        &self.inner.issuer_org_unit_name
    }

    /// Issuer Common Name (인증서 발급자 공통명)
    /// Issuer Common Name (인증서 발급자 공통명)
    async fn issuer_common_name(&self) -> &str {
        &self.inner.issuer_common_name
    }

    /// Last Alert (최종 알랈)
    /// Last Alert (최종 알랈)
    async fn last_alert(&self) -> u8 {
        self.inner.last_alert
    }

    /// MITRE Tactic (MITRE 전술)
    /// MITRE Tactic (MITRE 전술)
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// Confidence (신뢰도)
    /// Confidence (신뢰도)
    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// Triage Scores (선별 점수 목록)
    /// Triage Scores (선별 점수 목록)
    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level (위협등급)
    /// Threat Level (위협등급)
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
    /// Timestamp (타임스탬프)
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor (센서)
    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Source IP Address (출발지 IP 주소)
    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// Source Country (출발지 국가) - The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    /// Source Customer (출발지 고객)
    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    /// Source Network (출발지 네트워크)
    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    /// Source Port Number (출발지 포트 번호)
    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    /// Destination IP Address (목적지 IP 주소)
    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// Destination Country (목적지 국가) - The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    /// Destination Customer (목적지 고객)
    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    /// Destination Network (목적지 네트워크)
    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    /// Destination Port Number (목적지 포트 번호)
    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    /// Protocol Number (프로토콜 번호) - TCP: 6, UDP: 17
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// End Time (종료 시간)
    async fn end_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.end_time)
    }

    /// Server Name (서버명)
    async fn server_name(&self) -> &str {
        &self.inner.server_name
    }

    /// ALPN Protocol (ALPN 프로토콜)
    async fn alpn_protocol(&self) -> &str {
        &self.inner.alpn_protocol
    }

    /// JA3 Fingerprint (JA3 핑거프린트)
    async fn ja3(&self) -> &str {
        &self.inner.ja3
    }

    /// TLS Version (TLS 버전)
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// Client Cipher Suites (클라이언트 암호 시트 목록)
    async fn client_cipher_suites(&self) -> &[u16] {
        &self.inner.client_cipher_suites
    }

    /// Client Extensions (클라이언트 확장 목록)
    async fn client_extensions(&self) -> &[u16] {
        &self.inner.client_extensions
    }

    /// Cipher (암호 시트)
    async fn cipher(&self) -> u16 {
        self.inner.cipher
    }

    /// Extensions (확장 목록)
    async fn extensions(&self) -> &[u16] {
        &self.inner.extensions
    }

    /// JA3S Fingerprint (JA3S 핑거프린트)
    async fn ja3s(&self) -> &str {
        &self.inner.ja3s
    }

    /// Certificate Serial (인증서 시리얼)
    async fn serial(&self) -> &str {
        &self.inner.serial
    }

    /// Subject Country (인증서 주체 국가)
    async fn subject_country(&self) -> &str {
        &self.inner.subject_country
    }

    /// Subject Organization Name (인증서 주체 조직명)
    async fn subject_org_name(&self) -> &str {
        &self.inner.subject_org_name
    }

    /// Subject Common Name (인증서 주체 공통명)
    async fn subject_common_name(&self) -> &str {
        &self.inner.subject_common_name
    }

    /// Validity Not Before (유효성 시작 시간)
    async fn validity_not_before(&self) -> StringNumber<i64> {
        StringNumber(self.inner.validity_not_before)
    }

    /// Validity Not After (유효성 종료 시간)
    async fn validity_not_after(&self) -> StringNumber<i64> {
        StringNumber(self.inner.validity_not_after)
    }

    /// Subject Alternative Name (인증서 주체 대체명)
    async fn subject_alt_name(&self) -> &str {
        &self.inner.subject_alt_name
    }

    /// Issuer Country (인증서 발급자 국가)
    async fn issuer_country(&self) -> &str {
        &self.inner.issuer_country
    }

    /// Issuer Organization Name (인증서 발급자 조직명)
    async fn issuer_org_name(&self) -> &str {
        &self.inner.issuer_org_name
    }

    /// Issuer Organization Unit Name (인증서 발급자 조직 단위명)
    async fn issuer_org_unit_name(&self) -> &str {
        &self.inner.issuer_org_unit_name
    }

    /// Issuer Common Name (인증서 발급자 공통명)
    async fn issuer_common_name(&self) -> &str {
        &self.inner.issuer_common_name
    }

    /// Last Alert (최종 알랈)
    async fn last_alert(&self) -> u8 {
        self.inner.last_alert
    }

    /// Confidence (신뢰도)
    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// MITRE Tactic (MITRE 전술)
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// Triage Scores (선별 점수 목록)
    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level (위협등급)
    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl From<database::SuspiciousTlsTraffic> for SuspiciousTlsTraffic {
    fn from(inner: database::SuspiciousTlsTraffic) -> Self {
        Self { inner }
    }
}
