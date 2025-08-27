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
    /// Start Time
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
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// HTTP Method
    async fn method(&self) -> &str {
        &self.inner.method
    }

    /// Host
    async fn host(&self) -> &str {
        &self.inner.host
    }

    /// Event Content
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

    /// URI
    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    /// Referer
    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    /// HTTP Version
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// User Agent
    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    /// Request Length
    async fn request_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.request_len)
    }

    /// Response Length
    async fn response_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.response_len)
    }

    /// Status Code
    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    /// Status Message
    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    /// Username
    async fn username(&self) -> &str {
        &self.inner.username
    }

    /// Password
    async fn password(&self) -> &str {
        &self.inner.password
    }

    /// Cookie
    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    /// Content Encoding
    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    /// Content Type
    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    /// Cache Control
    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    /// Request Filenames
    async fn orig_filenames(&self) -> &[String] {
        &self.inner.orig_filenames
    }

    /// Request MIME Types
    async fn orig_mime_types(&self) -> &[String] {
        &self.inner.orig_mime_types
    }

    /// Response Filenames
    async fn resp_filenames(&self) -> &[String] {
        &self.inner.resp_filenames
    }

    /// Response MIME Types
    async fn resp_mime_types(&self) -> &[String] {
        &self.inner.resp_mime_types
    }

    /// POST Body
    async fn post_body(&self) -> &[u8] {
        &self.inner.post_body
    }

    /// Last State
    async fn state(&self) -> &str {
        &self.inner.state
    }

    /// Database Name
    async fn db_name(&self) -> &str {
        &self.inner.db_name
    }

    /// Pattern ID
    async fn rule_id(&self) -> ID {
        ID(self.inner.rule_id.to_string())
    }

    /// Referenced Label
    async fn matched_to(&self) -> &str {
        &self.inner.matched_to
    }

    /// Cluster ID
    async fn cluster_id(&self) -> ID {
        ID(self
            .inner
            .cluster_id
            .map_or(String::new(), |id| id.to_string()))
    }

    /// Attack Kind
    async fn attack_kind(&self) -> &str {
        &self.inner.attack_kind
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
        ThreatLevel::Low
    }

    /// Learning Method
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
    /// Start Time
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

    /// Source Port (Number)
    async fn src_port(&self) -> u16 {
        self.inner.src_port
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

    /// Destination IP (Address)
    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// Destination Port (Number)
    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
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

    /// Learning Method
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
    /// Start Time
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// End Time
    async fn session_end_time(&self) -> DateTime<Utc> {
        self.inner.session_end_time
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

    /// Host
    async fn host(&self) -> &str {
        &self.inner.host
    }

    /// HTTP Method
    async fn method(&self) -> &str {
        &self.inner.method
    }

    /// URI
    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    /// Referer
    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    /// HTTP Version
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// User Agent
    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    /// Request Length
    async fn request_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.request_len)
    }

    /// Response Length
    async fn response_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.response_len)
    }

    /// Status Code
    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    /// Status Message
    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    /// Username
    async fn username(&self) -> &str {
        &self.inner.username
    }

    /// Password
    async fn password(&self) -> &str {
        &self.inner.password
    }

    /// Cookie
    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    /// Content Encoding
    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    /// Content Type
    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    /// Cache Control
    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    /// Request Filenames
    async fn orig_filenames(&self) -> &[String] {
        &self.inner.orig_filenames
    }

    /// Request MIME Types
    async fn orig_mime_types(&self) -> &[String] {
        &self.inner.orig_mime_types
    }

    /// Response Filenames
    async fn resp_filenames(&self) -> &[String] {
        &self.inner.resp_filenames
    }

    /// Response MIME Types
    async fn resp_mime_types(&self) -> &[String] {
        &self.inner.resp_mime_types
    }

    /// POST Body
    async fn post_body(&self) -> &[u8] {
        &self.inner.post_body
    }

    /// Last State
    async fn state(&self) -> &str {
        &self.inner.state
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

    /// Learning Method
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
    /// Start Time
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
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Host
    async fn host(&self) -> &str {
        &self.inner.host
    }

    /// HTTP Method
    async fn method(&self) -> &str {
        &self.inner.method
    }

    /// URI
    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    /// Referer
    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    /// HTTP Version
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// User Agent
    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    /// Request Length
    async fn request_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.request_len)
    }

    /// Response Length
    async fn response_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.response_len)
    }

    /// Status Code
    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    /// Status Message
    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    /// Username
    async fn username(&self) -> &str {
        &self.inner.username
    }

    /// Password
    async fn password(&self) -> &str {
        &self.inner.password
    }

    /// Cookie
    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    /// Content Encoding
    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    /// Content Type
    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    /// Cache Control
    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    /// Request Filenames
    async fn orig_filenames(&self) -> &[String] {
        &self.inner.orig_filenames
    }

    /// Request MIME Types
    async fn orig_mime_types(&self) -> &[String] {
        &self.inner.orig_mime_types
    }

    /// Response Filenames
    async fn resp_filenames(&self) -> &[String] {
        &self.inner.resp_filenames
    }

    /// Response MIME Types
    async fn resp_mime_types(&self) -> &[String] {
        &self.inner.resp_mime_types
    }

    /// POST Body
    async fn post_body(&self) -> &[u8] {
        &self.inner.post_body
    }

    /// Last State
    async fn state(&self) -> &str {
        &self.inner.state
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

    /// Learning Method
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
    /// Start Time
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
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Host
    async fn host(&self) -> &str {
        &self.inner.host
    }

    /// HTTP Method
    async fn method(&self) -> &str {
        &self.inner.method
    }

    /// URI
    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    /// Referer
    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    /// HTTP Version
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// User Agent
    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    /// Request Length
    async fn request_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.request_len)
    }

    /// Response Length
    async fn response_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.response_len)
    }

    /// Status Code
    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    /// Status Message
    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    /// Username
    async fn username(&self) -> &str {
        &self.inner.username
    }

    /// Password
    async fn password(&self) -> &str {
        &self.inner.password
    }

    /// Cookie
    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    /// Content Encoding
    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    /// Content Type
    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    /// Cache Control
    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    /// Request Filenames
    async fn orig_filenames(&self) -> &[String] {
        &self.inner.orig_filenames
    }

    /// Request MIME Types
    async fn orig_mime_types(&self) -> &[String] {
        &self.inner.orig_mime_types
    }

    /// Response Filenames
    async fn resp_filenames(&self) -> &[String] {
        &self.inner.resp_filenames
    }

    /// Response MIME Types
    async fn resp_mime_types(&self) -> &[String] {
        &self.inner.resp_mime_types
    }

    /// POST Body
    async fn post_body(&self) -> &[u8] {
        &self.inner.post_body
    }

    /// Last State
    async fn state(&self) -> &str {
        &self.inner.state
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

    /// Learning Method
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
    /// Start Time
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
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// End Time
    async fn end_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.end_time)
    }

    /// HTTP Method
    async fn method(&self) -> &str {
        &self.inner.method
    }

    /// Host
    async fn host(&self) -> &str {
        &self.inner.host
    }

    /// URI
    async fn uri(&self) -> &str {
        &self.inner.uri
    }

    /// Referer
    async fn referer(&self) -> &str {
        &self.inner.referer
    }

    /// HTTP Version
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// User Agent
    async fn user_agent(&self) -> &str {
        &self.inner.user_agent
    }

    /// Request Length
    async fn request_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.request_len)
    }

    /// Response Length
    async fn response_len(&self) -> StringNumber<usize> {
        StringNumber(self.inner.response_len)
    }

    /// Status Code
    async fn status_code(&self) -> u16 {
        self.inner.status_code
    }

    /// Status Message
    async fn status_msg(&self) -> &str {
        &self.inner.status_msg
    }

    /// Username
    async fn username(&self) -> &str {
        &self.inner.username
    }

    /// Password
    async fn password(&self) -> &str {
        &self.inner.password
    }

    /// Cookie
    async fn cookie(&self) -> &str {
        &self.inner.cookie
    }

    /// Content Encoding
    async fn content_encoding(&self) -> &str {
        &self.inner.content_encoding
    }

    /// Content Type
    async fn content_type(&self) -> &str {
        &self.inner.content_type
    }

    /// Cache Control
    async fn cache_control(&self) -> &str {
        &self.inner.cache_control
    }

    /// Request Filenames
    async fn orig_filenames(&self) -> &[String] {
        &self.inner.orig_filenames
    }

    /// Request MIME Types
    async fn orig_mime_types(&self) -> &[String] {
        &self.inner.orig_mime_types
    }

    /// Response Filenames
    async fn resp_filenames(&self) -> &[String] {
        &self.inner.resp_filenames
    }

    /// Response MIME Types
    async fn resp_mime_types(&self) -> &[String] {
        &self.inner.resp_mime_types
    }

    /// POST Body
    async fn post_body(&self) -> &[u8] {
        &self.inner.post_body
    }

    /// Last State
    async fn state(&self) -> &str {
        &self.inner.state
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

    /// Learning Method
    async fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }
}

impl From<database::BlocklistHttp> for BlocklistHttp {
    fn from(inner: database::BlocklistHttp) -> Self {
        Self { inner }
    }
}
