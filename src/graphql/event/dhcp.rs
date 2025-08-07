use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistDhcp {
    inner: database::BlocklistDhcp,
}

#[Object]
impl BlocklistDhcp {
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

    /// Destination IP (Address) (목적지 IP (주소))
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

    /// Message Type (메시지 유형) - DHCP message type
    async fn msg_type(&self) -> u8 {
        self.inner.msg_type
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

    /// Subnet Mask (서브넷 마스크)
    async fn subnet_mask(&self) -> String {
        self.inner.subnet_mask.to_string()
    }

    /// Router (라우터)
    async fn router(&self) -> String {
        self.inner
            .router
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(", ")
    }

    /// Domain Name Server (도메인 이름 서버)
    async fn domain_name_server(&self) -> String {
        self.inner
            .domain_name_server
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(", ")
    }

    /// Requested IP (Address) (요청 IP (주소))
    async fn req_ip_addr(&self) -> String {
        self.inner.req_ip_addr.to_string()
    }

    /// Lease Time (리스 시간)
    async fn lease_time(&self) -> StringNumber<u32> {
        StringNumber(self.inner.lease_time)
    }

    /// Server ID (서버 ID)
    async fn server_id(&self) -> String {
        self.inner.server_id.to_string()
    }

    /// Parameter Request List (매개변수 요청 목록)
    async fn param_req_list(&self) -> String {
        self.inner
            .param_req_list
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join(", ")
    }

    /// Message (메시지)
    async fn message(&self) -> &str {
        &self.inner.message
    }

    /// Renewal Time (갱신 시간)
    async fn renewal_time(&self) -> StringNumber<u32> {
        StringNumber(self.inner.renewal_time)
    }

    /// Rebinding Time (재바인딩 시간)
    async fn rebinding_time(&self) -> StringNumber<u32> {
        StringNumber(self.inner.rebinding_time)
    }

    /// Class ID (클래스 ID)
    async fn class_id(&self) -> String {
        self.inner
            .class_id
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<String>>()
            .join(":")
    }

    /// Client ID Type (클라이언트 ID 유형)
    async fn client_id_type(&self) -> u8 {
        self.inner.client_id_type
    }

    /// Client ID (클라이언트 ID)
    async fn client_id(&self) -> String {
        self.inner
            .client_id
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<String>>()
            .join(":")
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

impl From<database::BlocklistDhcp> for BlocklistDhcp {
    fn from(inner: database::BlocklistDhcp) -> Self {
        Self { inner }
    }
}
