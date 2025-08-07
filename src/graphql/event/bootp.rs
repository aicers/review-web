use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistBootp {
    inner: database::BlocklistBootp,
}

#[Object]
impl BlocklistBootp {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor (센서)
    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Source IP (Address) (출발지 IP (주소))
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

    /// Source Port (Number) (출발지 포트 (번호))
    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    /// Destination IP (Adress) (목적지 IP (주소))
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

    /// Destination Port (Number) (목적지 포트 (번호))
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

    /// Operation Code (작업 코드) - 1: BOOTREQUEST, 2 = BOOTREPLY
    async fn op(&self) -> u8 {
        self.inner.op
    }

    /// Hardware Type (하드웨어 유형) - 하단 참조
    async fn htype(&self) -> u8 {
        self.inner.htype
    }

    /// Hop Count (Hop 개수)
    async fn hops(&self) -> u8 {
        self.inner.hops
    }

    /// Transaction ID (트랜잭션 ID)
    async fn xid(&self) -> StringNumber<u32> {
        StringNumber(self.inner.xid)
    }

    /// Client IP (Address) (클라이언트 IP (주소))
    async fn ciaddr(&self) -> String {
        self.inner.ciaddr.to_string()
    }

    /// Your IP (Address) (할당 IP (주소))
    async fn yiaddr(&self) -> String {
        self.inner.yiaddr.to_string()
    }

    /// Server IP (Address) (서버 IP (주소))
    async fn siaddr(&self) -> String {
        self.inner.siaddr.to_string()
    }

    /// Gateway IP (Address) (게이트웨이 IP (주소))
    async fn giaddr(&self) -> String {
        self.inner.giaddr.to_string()
    }

    /// Client Hardware IP (Address) (클라이언트 하드웨어 IP (주소))
    async fn chaddr(&self) -> String {
        self.inner
            .chaddr
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<String>>()
            .join(":")
    }

    /// Server Hostname (서버 호스트명)
    async fn sname(&self) -> &str {
        &self.inner.sname
    }

    /// Boot Filename (부트 파일 이름)
    async fn file(&self) -> &str {
        &self.inner.file
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

impl From<database::BlocklistBootp> for BlocklistBootp {
    fn from(inner: database::BlocklistBootp) -> Self {
        Self { inner }
    }
}
