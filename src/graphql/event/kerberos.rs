use async_graphql::{Context, ID, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database::event as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{customer::Customer, network::Network, triage::ThreatCategory};

pub(super) struct BlocklistKerberos {
    id: i128,
    inner: database::BlocklistKerberos,
}

#[Object]
impl BlocklistKerberos {
    /// Opaque event identifier.
    pub async fn id(&self) -> ID {
        super::opaque_event_id(self.id)
    }

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

    /// Originator Country
    /// The two-letter country code of the originator IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn orig_country(&self, _ctx: &Context<'_>) -> String {
        country_code(&self.inner.orig_country_code)
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

    /// Originator Port (Number)
    async fn orig_port(&self) -> u16 {
        self.inner.orig_port
    }

    /// Responder IP (Address)
    async fn resp_addr(&self) -> String {
        self.inner.resp_addr.to_string()
    }

    /// Responder Country
    /// The two-letter country code of the responder IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn resp_country(&self, _ctx: &Context<'_>) -> String {
        country_code(&self.inner.resp_country_code)
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

    /// Responder Port (Number)
    async fn resp_port(&self) -> u16 {
        self.inner.resp_port
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
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

    /// Client Time
    async fn client_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.client_time)
    }

    /// Server Time
    async fn server_time(&self) -> StringNumber<i64> {
        StringNumber(self.inner.server_time)
    }

    /// Error Code
    async fn error_code(&self) -> StringNumber<u32> {
        StringNumber(self.inner.error_code)
    }

    /// Client Realm
    async fn client_realm(&self) -> &str {
        &self.inner.client_realm
    }

    /// Client Name Type
    async fn cname_type(&self) -> u8 {
        self.inner.cname_type
    }

    /// Client Name
    async fn cname(&self) -> &[String] {
        &self.inner.cname
    }

    /// Realm
    async fn realm(&self) -> &str {
        &self.inner.realm
    }

    /// Service Name Type
    async fn sname_type(&self) -> u8 {
        self.inner.sname_type
    }

    /// Service Name
    async fn sname(&self) -> &[String] {
        &self.inner.sname
    }

    /// MITRE Tactic
    pub async fn category(&self) -> Option<ThreatCategory> {
        self.inner.category.map(Into::into)
    }

    /// Confidence
    pub async fn confidence(&self) -> f32 {
        self.inner.confidence
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
        database::BlocklistKerberos::threat_level().into()
    }
}

impl From<(i128, database::BlocklistKerberos)> for BlocklistKerberos {
    fn from((id, inner): (i128, database::BlocklistKerberos)) -> Self {
        Self { id, inner }
    }
}
