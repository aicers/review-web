use async_graphql::{Context, ID, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database::event as database;

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
    /// Event Generation Time
    pub async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    pub async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Originator IP (Address)
    async fn orig_addr(&self) -> String {
        self.inner.orig_addr.to_string()
    }

    /// Originator Port (Number)
    async fn orig_port(&self) -> u16 {
        self.inner.orig_port
    }

    /// Originator Country
    /// The two-letter country code of the originator IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn orig_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.orig_addr)
    }

    /// Originator Customer
    async fn orig_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.orig_addr)
    }

    /// Originator Network
    async fn orig_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.orig_addr)
    }

    /// Responder IP (Address)
    async fn resp_addr(&self) -> String {
        self.inner.resp_addr.to_string()
    }

    /// Responder Port (Number)
    async fn resp_port(&self) -> u16 {
        self.inner.resp_port
    }

    /// Responder Country
    /// The two-letter country code of the responder IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn resp_country(&self, ctx: &Context<'_>) -> String {
        country_code(ctx, self.inner.resp_addr)
    }

    /// Responder Customer
    async fn resp_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.customer_map();
        find_ip_customer(&map, self.inner.resp_addr)
    }

    /// Responder Network
    async fn resp_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        find_ip_network(&map, self.inner.resp_addr)
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Service Name
    async fn service(&self) -> &str {
        &self.inner.service
    }

    /// Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Duration
    ///
    /// It is measured in nanoseconds.
    async fn duration(&self) -> StringNumber<i64> {
        StringNumber(self.inner.duration)
    }

    /// Packets Sent (by Source)
    async fn orig_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_pkts)
    }

    /// Packets Received (by Destination)
    async fn resp_pkts(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_pkts)
    }

    /// Layer 2 Bytes Sent (by Source)
    async fn orig_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_l2_bytes)
    }

    /// Layer 2 Bytes Received (by Destination)
    async fn resp_l2_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_l2_bytes)
    }

    /// Event Content
    async fn content(&self) -> &str {
        &self.inner.content
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
    pub async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// MITRE Tactic
    pub async fn category(&self) -> Option<ThreatCategory> {
        self.inner.category.map(Into::into)
    }

    /// Triage Scores
    pub async fn triage_scores(&self) -> Option<Vec<TriageScore<'_>>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level
    pub async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }

    /// Learning Method
    async fn learning_method(&self) -> LearningMethod {
        LearningMethod::Unsupervised
    }
}

impl From<database::NetworkThreat> for NetworkThreat {
    fn from(inner: database::NetworkThreat) -> Self {
        Self { inner }
    }
}
