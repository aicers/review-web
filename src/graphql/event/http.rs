use async_graphql::{Context, ID, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{
    customer::Customer, filter::LearningMethod, network::Network, triage::ThreatCategory,
};

#[allow(clippy::module_name_repetitions)]
pub(super) struct HttpThreat {
    inner: database::HttpThreat,
}

#[Object]
impl HttpThreat {
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

    /// HTTP Method (HTTP 메소드)
    async fn method(&self) -> &str {
        &self.inner.method
    }

    /// Host Name (호스트명)
    async fn host(&self) -> &str {
        &self.inner.host
    }

    /// Content (콘텐츠)
    async fn content(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.inner.method,
            self.inner.host,
            self.inner.uri,
            self.inner.referer,
            self.inner.status_code,
            self.inner.user_agent
        )
    }

    /// URI (URI)
    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    /// Referer (참조자)
    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    /// HTTP Version (HTTP 버전)
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// User Agent (사용자 에이전트)
    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    /// Request Length (요청 길이) - The length of the request in string within the range representable
    /// by a `usize`.
    async fn request_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.request_len)
    }

    /// Response Length (응답 길이) - The length of the response in string within the range representable
    /// by a `usize`.
    async fn response_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.response_len)
    }

    /// Status Code (상태 코드)
    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    /// Status Message (상태 메시지)
    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    /// Username (사용자명)
    async fn username(&self) -> &str {
        &self.inner.username
    }

    /// Password (비밀번호)
    async fn password(&self) -> &str {
        &self.inner.password
    }

    /// Cookie (쿠키)
    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    /// Content Encoding (콘텐츠 인코딩)
    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    /// Content Type (콘텐츠 타입)
    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    /// Cache Control (캐시 제어)
    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    /// Original Filenames (원본 파일명 목록)
    async fn orig_filenames(&self) -> &[String] {
        &self.inner.orig_filenames
    }

    /// Original MIME Types (원본 MIME 타입 목록)
    async fn orig_mime_types(&self) -> &[String] {
        &self.inner.orig_mime_types
    }

    /// Response Filenames (응답 파일명 목록)
    async fn resp_filenames(&self) -> &[String] {
        &self.inner.resp_filenames
    }

    /// Response MIME Types (응답 MIME 타입 목록)
    async fn resp_mime_types(&self) -> &[String] {
        &self.inner.resp_mime_types
    }

    /// POST Body (POST 본문)
    async fn post_body(&self) -> &[u8] {
        &self.inner.post_body
    }

    /// State (상태)
    async fn state(&self) -> &str {
        &self.inner.state
    }

    /// Database Name (데이터베이스명)
    async fn db_name(&self) -> &str {
        &self.inner.db_name
    }

    /// Rule ID (규칙 ID) - The rule id of the event in string wthin the range representable
    /// by a `u32`.
    async fn rule_id(&self) -> ID {
        ID(self.inner.rule_id.to_string())
    }

    /// Matched To (매칭 대상)
    async fn matched_to(&self) -> &str {
        &self.inner.matched_to
    }

    /// Cluster ID (클러스터 ID) - The cluster id of the event in string wthin the range representable
    /// by a `usize`.
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
        ThreatLevel::Low
    }

    /// Learning Method (탐지 방식)
    async fn learning_method(&self) -> LearningMethod {
        LearningMethod::Unsupervised
    }
}

impl From<database::HttpThreat> for HttpThreat {
    fn from(inner: database::HttpThreat) -> Self {
        Self { inner }
    }
}

pub(super) struct RepeatedHttpSessions {
    inner: database::RepeatedHttpSessions,
}

#[Object]
impl RepeatedHttpSessions {
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

    /// Source Port Number (출발지 포트 번호)
    async fn src_port(&self) -> u16 {
        self.inner.src_port
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

    /// Destination IP Address (목적지 IP 주소)
    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// Destination Port Number (목적지 포트 번호)
    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    /// Protocol Number (프로토콜 번호) - TCP: 6, UDP: 17
    async fn proto(&self) -> u8 {
        self.inner.proto
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

    /// Learning Method (탐지 방식)
    async fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }
}

impl From<database::RepeatedHttpSessions> for RepeatedHttpSessions {
    fn from(inner: database::RepeatedHttpSessions) -> Self {
        Self { inner }
    }
}

pub(super) struct TorConnection {
    inner: database::TorConnection,
}

#[Object]
impl TorConnection {
    /// Timestamp (타임스탬프)
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor (센서)
    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Session End Time (세션 종료 시간)
    async fn session_end_time(&self) -> DateTime<Utc> {
        self.inner.session_end_time
    }

    /// Source IP Address (출발지 IP 주소)
    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// Source Port Number (출발지 포트 번호)
    async fn src_port(&self) -> u16 {
        self.inner.src_port
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

    /// Destination IP Address (목적지 IP 주소)
    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// Destination Port Number (목적지 포트 번호)
    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    /// Protocol Number (프로토콜 번호) - TCP: 6, UDP: 17
    async fn proto(&self) -> u8 {
        self.inner.proto
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

    async fn host(&self) -> &str {
        &self.inner.host
    }

    async fn method(&self) -> &str {
        &self.inner.method
    }

    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    async fn version(&self) -> &str {
        &self.inner.version
    }

    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    /// The length of the request in string within the range representable
    /// by a `usize`.
    async fn request_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.request_len)
    }

    /// The length of the response in string within the range representable
    /// by a `usize`.
    async fn response_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.response_len)
    }

    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    async fn username(&self) -> &str {
        &self.inner.username
    }

    async fn password(&self) -> &str {
        &self.inner.password
    }

    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    async fn orig_filenames(&self) -> &[String] {
        &self.inner.orig_filenames
    }

    async fn orig_mime_types(&self) -> &[String] {
        &self.inner.orig_mime_types
    }

    async fn resp_filenames(&self) -> &[String] {
        &self.inner.resp_filenames
    }

    async fn resp_mime_types(&self) -> &[String] {
        &self.inner.resp_mime_types
    }

    async fn post_body(&self) -> &[u8] {
        &self.inner.post_body
    }

    /// State (상태)
    async fn state(&self) -> &str {
        &self.inner.state
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

    /// Learning Method (탐지 방식)
    async fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }
}

impl From<database::TorConnection> for TorConnection {
    fn from(inner: database::TorConnection) -> Self {
        Self { inner }
    }
}

pub(super) struct DomainGenerationAlgorithm {
    inner: database::DomainGenerationAlgorithm,
}

#[Object]
impl DomainGenerationAlgorithm {
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

    async fn host(&self) -> &str {
        &self.inner.host
    }

    async fn method(&self) -> &str {
        &self.inner.method
    }

    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    async fn version(&self) -> &str {
        &self.inner.version
    }

    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    /// The length of the request in string within the range representable
    /// by a `usize`.
    async fn request_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.request_len)
    }

    /// The length of the response in string within the range representable
    /// by a `usize`.
    async fn response_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.response_len)
    }

    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    async fn username(&self) -> &str {
        &self.inner.username
    }

    async fn password(&self) -> &str {
        &self.inner.password
    }

    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    async fn orig_filenames(&self) -> &[String] {
        &self.inner.orig_filenames
    }

    async fn orig_mime_types(&self) -> &[String] {
        &self.inner.orig_mime_types
    }

    async fn resp_filenames(&self) -> &[String] {
        &self.inner.resp_filenames
    }

    async fn resp_mime_types(&self) -> &[String] {
        &self.inner.resp_mime_types
    }

    async fn post_body(&self) -> &[u8] {
        &self.inner.post_body
    }

    async fn state(&self) -> &str {
        &self.inner.state
    }

    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
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

impl From<database::DomainGenerationAlgorithm> for DomainGenerationAlgorithm {
    fn from(inner: database::DomainGenerationAlgorithm) -> Self {
        Self { inner }
    }
}

pub(super) struct NonBrowser {
    inner: database::NonBrowser,
}

#[Object]
impl NonBrowser {
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

    async fn host(&self) -> &str {
        &self.inner.host
    }

    async fn method(&self) -> &str {
        &self.inner.method
    }

    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    async fn version(&self) -> &str {
        &self.inner.version
    }

    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    /// The length of the request in string within the range representable
    /// by a `usize`.
    async fn request_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.request_len)
    }

    /// The length of the response in string within the range representable
    /// by a `usize`.
    async fn response_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.response_len)
    }

    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    async fn username(&self) -> &str {
        &self.inner.username
    }

    async fn password(&self) -> &str {
        &self.inner.password
    }

    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    async fn orig_filenames(&self) -> &[String] {
        &self.inner.orig_filenames
    }

    async fn orig_mime_types(&self) -> &[String] {
        &self.inner.orig_mime_types
    }

    async fn resp_filenames(&self) -> &[String] {
        &self.inner.resp_filenames
    }

    async fn resp_mime_types(&self) -> &[String] {
        &self.inner.resp_mime_types
    }

    async fn post_body(&self) -> &[u8] {
        &self.inner.post_body
    }

    async fn state(&self) -> &str {
        &self.inner.state
    }

    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
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

impl From<database::NonBrowser> for NonBrowser {
    fn from(inner: database::NonBrowser) -> Self {
        Self { inner }
    }
}

pub(super) struct BlocklistHttp {
    inner: database::BlocklistHttp,
}

#[Object]
impl BlocklistHttp {
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

    /// The last time of the event in string within the range representable
    /// by a `i64`.
    async fn end_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.end_time)
    }

    async fn method(&self) -> &str {
        &self.inner.method
    }

    async fn host(&self) -> &str {
        &self.inner.host
    }

    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    async fn version(&self) -> &str {
        &self.inner.version
    }

    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    /// The range of the request in string within the range representable
    ///  by a `usize`.
    async fn request_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.request_len)
    }

    /// The range of the response in string within the range representable
    /// by a `usize`.
    async fn response_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.response_len)
    }

    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    async fn username(&self) -> &str {
        &self.inner.username
    }

    async fn password(&self) -> &str {
        &self.inner.password
    }

    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    async fn orig_filenames(&self) -> &[String] {
        &self.inner.orig_filenames
    }

    async fn orig_mime_types(&self) -> &[String] {
        &self.inner.orig_mime_types
    }

    async fn resp_filenames(&self) -> &[String] {
        &self.inner.resp_filenames
    }

    async fn resp_mime_types(&self) -> &[String] {
        &self.inner.resp_mime_types
    }

    async fn post_body(&self) -> &[u8] {
        &self.inner.post_body
    }

    async fn state(&self) -> &str {
        &self.inner.state
    }

    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
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

impl From<database::BlocklistHttp> for BlocklistHttp {
    fn from(inner: database::BlocklistHttp) -> Self {
        Self { inner }
    }
}
