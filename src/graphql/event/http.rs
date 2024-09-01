use async_graphql::{Context, Object, Result, StringNumber, ID};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{country_code, find_ip_customer, find_ip_network, TriageScore};
use crate::graphql::{customer::Customer, network::Network};

#[allow(clippy::module_name_repetitions)]
pub(super) struct HttpThreat {
    inner: database::HttpThreat,
}

#[Object]
impl HttpThreat {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    async fn method(&self) -> &str {
        &self.inner.method
    }

    async fn host(&self) -> &str {
        &self.inner.host
    }

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

    async fn orig_filenames(&self) -> Vec<String> {
        self.inner.orig_filenames.clone()
    }

    async fn orig_mime_types(&self) -> Vec<String> {
        self.inner.orig_mime_types.clone()
    }

    async fn resp_filenames(&self) -> Vec<String> {
        self.inner.resp_filenames.clone()
    }

    async fn resp_mime_types(&self) -> Vec<String> {
        self.inner.resp_mime_types.clone()
    }

    async fn post_body(&self) -> Vec<u8> {
        self.inner.post_body.clone()
    }

    async fn state(&self) -> &str {
        &self.inner.state
    }

    async fn db_name(&self) -> &str {
        &self.inner.db_name
    }

    /// The rule id of the event in string wthin the range representable
    /// by a `u32`.
    async fn rule_id(&self) -> ID {
        ID(self.inner.rule_id.to_string())
    }

    async fn matched_to(&self) -> &str {
        &self.inner.matched_to
    }

    /// The cluster id of the event in string wthin the range representable
    /// by a `usize`.
    async fn cluster_id(&self) -> ID {
        ID(self.inner.cluster_id.to_string())
    }

    async fn attack_kind(&self) -> &str {
        &self.inner.attack_kind
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
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
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
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn session_end_time(&self) -> DateTime<Utc> {
        self.inner.session_end_time
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

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
        &self.inner.referrer
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

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
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

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

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

    async fn orig_filenames(&self) -> Vec<String> {
        self.inner.orig_filenames.clone()
    }

    async fn orig_mime_types(&self) -> Vec<String> {
        self.inner.orig_mime_types.clone()
    }

    async fn resp_filenames(&self) -> Vec<String> {
        self.inner.resp_filenames.clone()
    }

    async fn resp_mime_types(&self) -> Vec<String> {
        self.inner.resp_mime_types.clone()
    }

    async fn post_body(&self) -> Vec<u8> {
        self.inner.post_body.clone()
    }

    async fn state(&self) -> &str {
        &self.inner.state
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

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

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
        &self.inner.referrer
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

    async fn orig_filenames(&self) -> Vec<String> {
        self.inner.orig_filenames.clone()
    }

    async fn orig_mime_types(&self) -> Vec<String> {
        self.inner.orig_mime_types.clone()
    }

    async fn resp_filenames(&self) -> Vec<String> {
        self.inner.resp_filenames.clone()
    }

    async fn resp_mime_types(&self) -> Vec<String> {
        self.inner.resp_mime_types.clone()
    }

    async fn post_body(&self) -> Vec<u8> {
        self.inner.post_body.clone()
    }

    async fn state(&self) -> &str {
        &self.inner.state
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::NonBrowser> for NonBrowser {
    fn from(inner: database::NonBrowser) -> Self {
        Self { inner }
    }
}

pub(super) struct BlockListHttp {
    inner: database::BlockListHttp,
}

#[Object]
impl BlockListHttp {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn src_addr(&self) -> String {
        self.inner.src_addr.to_string()
    }

    /// The two-letter country code of the source IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn src_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.src_addr)
    }

    async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.src_addr)
    }

    async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.src_addr)
    }

    async fn src_port(&self) -> u16 {
        self.inner.src_port
    }

    async fn dst_addr(&self) -> String {
        self.inner.dst_addr.to_string()
    }

    /// The two-letter country code of the destination IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn dst_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.dst_addr)
    }

    async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.dst_addr)
    }

    async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.dst_addr)
    }

    async fn dst_port(&self) -> u16 {
        self.inner.dst_port
    }

    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// The last time of the event in string within the range representable
    /// by a `i64`.
    async fn last_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.last_time)
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
        &self.inner.referrer
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

    async fn orig_filenames(&self) -> Vec<String> {
        self.inner.orig_filenames.clone()
    }

    async fn orig_mime_types(&self) -> Vec<String> {
        self.inner.orig_mime_types.clone()
    }

    async fn resp_filenames(&self) -> Vec<String> {
        self.inner.resp_filenames.clone()
    }

    async fn resp_mime_types(&self) -> Vec<String> {
        self.inner.resp_mime_types.clone()
    }

    async fn post_body(&self) -> Vec<u8> {
        self.inner.post_body.clone()
    }

    async fn state(&self) -> &str {
        &self.inner.state
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::BlockListHttp> for BlockListHttp {
    fn from(inner: database::BlockListHttp) -> Self {
        Self { inner }
    }
}
