use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistSmtp {
    inner: database::BlocklistSmtp,
}

#[Object]
impl BlocklistSmtp {
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

    /// Protocol Number (프로토콜 번호)
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// End Time (종료 시간)
    async fn end_time(&self) -> i64 {
        self.inner.end_time
    }

    /// Mail From (발신 메일)
    async fn mailfrom(&self) -> &str {
        &self.inner.mailfrom
    }

    /// Date (날짜)
    async fn date(&self) -> &str {
        &self.inner.date
    }

    /// From (발신자)
    async fn from(&self) -> &str {
        &self.inner.from
    }

    /// To (수신자)
    async fn to(&self) -> &str {
        &self.inner.to
    }

    /// Subject (제목)
    async fn subject(&self) -> &str {
        &self.inner.subject
    }

    /// Agent (에이전트)
    async fn agent(&self) -> &str {
        &self.inner.agent
    }

    /// State (상태)
    async fn state(&self) -> &str {
        &self.inner.state
    }

    /// Threat Category (위협 범주)
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// Confidence Score (신뢰도)
    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// Triage Scores (분류 점수)
    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level (위협 수준)
    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl From<database::BlocklistSmtp> for BlocklistSmtp {
    fn from(inner: database::BlocklistSmtp) -> Self {
        Self { inner }
    }
}
