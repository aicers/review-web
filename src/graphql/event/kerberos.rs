use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistKerberos {
    inner: database::BlocklistKerberos,
}

#[Object]
impl BlocklistKerberos {
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

    /// End Time (종료 시간) - The last time the event was seen in string wthin the range
    /// representable by a `i64`.
    async fn end_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.end_time)
    }

    /// Client Time (클라이언트 시간) - The client time in string wthin the range representable
    /// by a `i64`.
    async fn client_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.client_time)
    }

    /// Server Time (서버 시간) - The server time in string wthin the range representable
    /// by a `i64`.
    async fn server_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.server_time)
    }

    /// Error Code (오류 코드) - The error code in string wthin the range representable
    /// by a `u32`.
    async fn error_code(&self) -> StringNumber<u32> {
        StringNumber(self.inner.error_code)
    }

    /// Client Realm (클라이언트 렄역)
    async fn client_realm(&self) -> &str {
        &self.inner.client_realm
    }

    /// CName Type (클라이언트명 타입)
    async fn cname_type(&self) -> u8 {
        self.inner.cname_type
    }

    /// Client Name (클라이언트명 목록)
    async fn client_name(&self) -> &[String] {
        &self.inner.client_name
    }

    /// Realm (레름)
    async fn realm(&self) -> &str {
        &self.inner.realm
    }

    /// SName Type (서비스명 타입)
    async fn sname_type(&self) -> u8 {
        self.inner.sname_type
    }

    /// Service Name (서비스명 목록)
    async fn service_name(&self) -> &[String] {
        &self.inner.service_name
    }

    /// MITRE Tactic (MITRE 전술)
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// Confidence (신뢰도)
    async fn confidence(&self) -> f32 {
        self.inner.confidence
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

impl From<database::BlocklistKerberos> for BlocklistKerberos {
    fn from(inner: database::BlocklistKerberos) -> Self {
        Self { inner }
    }
}
