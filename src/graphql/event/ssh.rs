use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistSsh {
    inner: database::BlocklistSsh,
}

#[Object]
impl BlocklistSsh {
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
    async fn end_time(&self) -> i64 {
        self.inner.end_time
    }

    /// Client (클라이언트)
    async fn client(&self) -> &str {
        &self.inner.client
    }

    /// Server (서버)
    async fn server(&self) -> &str {
        &self.inner.server
    }

    /// Cipher Algorithm (암호화 알고리즘)
    async fn cipher_alg(&self) -> &str {
        &self.inner.cipher_alg
    }

    /// MAC Algorithm (MAC 알고리즘)
    async fn mac_alg(&self) -> &str {
        &self.inner.mac_alg
    }

    /// Compression Algorithm (압축 알고리즘)
    async fn compression_alg(&self) -> &str {
        &self.inner.compression_alg
    }

    /// Key Exchange Algorithm (키 교환 알고리즘)
    async fn kex_alg(&self) -> &str {
        &self.inner.kex_alg
    }

    /// Host Key Algorithm (호스트 키 알고리즘)
    async fn host_key_alg(&self) -> &str {
        &self.inner.host_key_alg
    }

    /// HASSH Algorithms (HASSH 알고리즘)
    async fn hassh_algorithms(&self) -> &str {
        &self.inner.hassh_algorithms
    }

    /// HASSH (HASSH)
    async fn hassh(&self) -> &str {
        &self.inner.hassh
    }

    /// HASSH Server Algorithms (HASSH 서버 알고리즘)
    async fn hassh_server_algorithms(&self) -> &str {
        &self.inner.hassh_server_algorithms
    }

    /// HASSH Server (HASSH 서버)
    async fn hassh_server(&self) -> &str {
        &self.inner.hassh_server
    }

    /// Client Server Host Key Algorithms (클라이언트 서버 호스트 키 알고리즘)
    async fn client_shka(&self) -> &str {
        &self.inner.client_shka
    }

    /// Server Server Host Key Algorithms (서버 서버 호스트 키 알고리즘)
    async fn server_shka(&self) -> &str {
        &self.inner.server_shka
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

impl From<database::BlocklistSsh> for BlocklistSsh {
    fn from(inner: database::BlocklistSsh) -> Self {
        Self { inner }
    }
}
