use async_graphql::{Context, ID, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{
    customer::Customer, filter::LearningMethod, network::Network, triage::ThreatCategory,
};

#[allow(clippy::module_name_repetitions)]
pub(super) struct NetworkThreat {
    inner: database::NetworkThreat,
}

#[Object]
impl NetworkThreat {
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
        self.inner.orig_addr.to_string()
    }

    /// Source Port Number (출발지 포트 번호)
    async fn src_port(&self) -> u16 {
        self.inner.orig_port
    }

    /// Source Country (출발지 국가) - The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.orig_addr)
    }

    /// Source Customer (출발지 고객)
    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.orig_addr)
    }

    /// Source Network (출발지 네트워크)
    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.orig_addr)
    }

    /// Destination IP Address (목적지 IP 주소)
    async fn dst_addr(&self) -> String {
        self.inner.resp_addr.to_string()
    }

    /// Destination Port Number (목적지 포트 번호)
    async fn dst_port(&self) -> u16 {
        self.inner.resp_port
    }

    /// Destination Country (목적지 국가) - The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.resp_addr)
    }

    /// Destination Customer (목적지 고객)
    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.resp_addr)
    }

    /// Destination Network (목적지 네트워크)
    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.resp_addr)
    }

    /// Protocol Number (프로토콜 번호)
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Service Name (서비스 이름)
    async fn service(&self) -> &str {
        &self.inner.service
    }

    /// End Time (종료 시간) - The timestamp that marks the end of the event, representing the last time it was seen,
    /// in string within the representable range of `i64`.
    async fn end_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.end_time)
    }

    /// Event Content (이벤트 내용)
    async fn content(&self) -> &str {
        &self.inner.content
    }

    /// Database Name (데이터베이스 이름)
    async fn db_name(&self) -> &str {
        &self.inner.db_name
    }

    /// Rule ID (규칙 ID) - The rule ID of the event in string within the representable
    /// range of `u32`.
    async fn rule_id(&self) -> ID {
        ID(self.inner.rule_id.to_string())
    }

    /// Referenced Label (참조 레이블)
    async fn matched_to(&self) -> &str {
        &self.inner.matched_to
    }

    /// Cluster ID (클러스터 ID) - The cluster ID of the event in string within the representable
    /// range of `usize`.
    async fn cluster_id(&self) -> ID {
        ID(self
            .inner
            .cluster_id
            .map_or(String::new(), |id| id.to_string()))
    }

    /// Attack Kind (공격 유형)
    async fn attack_kind(&self) -> &str {
        &self.inner.attack_kind
    }

    /// Confidence Score (신뢰도)
    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// Threat Category (위협 범주)
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
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

    /// Learning Method (학습 방법)
    async fn learning_method(&self) -> LearningMethod {
        LearningMethod::Unsupervised
    }
}

impl From<database::NetworkThreat> for NetworkThreat {
    fn from(inner: database::NetworkThreat) -> Self {
        Self { inner }
    }
}
