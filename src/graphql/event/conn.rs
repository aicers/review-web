use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database::event as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{
    customer::Customer, filter::LearningMethod, network::Network, triage::ThreatCategory,
};

#[allow(clippy::module_name_repetitions)]
pub(super) struct PortScan {
    inner: database::PortScan,
}

#[Object]
impl PortScan {
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

    /// Responder Port (Number) List
    async fn resp_ports(&self) -> &[u16] {
        &self.inner.resp_ports
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Detection Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Detection End Time
    async fn end_time(&self) -> DateTime<Utc> {
        self.inner.end_time
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
}

impl From<database::PortScan> for PortScan {
    fn from(inner: database::PortScan) -> Self {
        Self { inner }
    }
}

pub(super) struct MultiHostPortScan {
    inner: database::MultiHostPortScan,
}

#[Object]
impl MultiHostPortScan {
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

    /// Responder IP (Address) List
    async fn resp_addrs(&self) -> Vec<String> {
        self.inner
            .resp_addrs
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Responder Country List
    /// The two-letter country code of the responder IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn resp_countries(&self, ctx: &Context<'_>) -> Vec<String> {
        self.inner
            .resp_addrs
            .iter()
            .map(|resp_addr| country_code(ctx, *resp_addr))
            .collect()
    }

    /// Responder Customer List
    async fn resp_customers(&self, ctx: &Context<'_>) -> Result<Vec<Option<Customer>>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.customer_map();
        let mut customers = vec![];
        for resp_addr in &self.inner.resp_addrs {
            customers.push(find_ip_customer(&map, *resp_addr)?);
        }
        Ok(customers)
    }

    /// Responder Network
    async fn resp_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        find_ip_network(
            &map,
            *self
                .inner
                .resp_addrs
                .first()
                .expect("has value with internal network"),
        )
    }

    /// Responder Port (Number)
    async fn resp_port(&self) -> u16 {
        self.inner.resp_port
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Detection Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Detection End Time
    async fn end_time(&self) -> DateTime<Utc> {
        self.inner.end_time
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
}

impl From<database::MultiHostPortScan> for MultiHostPortScan {
    fn from(inner: database::MultiHostPortScan) -> Self {
        Self { inner }
    }
}

pub(super) struct ExternalDdos {
    inner: database::ExternalDdos,
}

#[Object]
impl ExternalDdos {
    /// Event Generation Time
    pub async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    pub async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Originator IP (Address) List
    async fn orig_addrs(&self) -> Vec<String> {
        self.inner
            .orig_addrs
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Originator Country List
    /// The two-letter country code of the originator IP address. `"XX"` if the
    /// location of the address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn orig_countries(&self, ctx: &Context<'_>) -> Vec<String> {
        self.inner
            .orig_addrs
            .iter()
            .map(|orig_addr| country_code(ctx, *orig_addr))
            .collect()
    }

    /// Originator Customer List
    async fn orig_customers(&self, ctx: &Context<'_>) -> Result<Vec<Option<Customer>>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.customer_map();
        let mut customers = vec![];
        for orig_addr in &self.inner.orig_addrs {
            customers.push(find_ip_customer(&map, *orig_addr)?);
        }
        Ok(customers)
    }

    /// Originator Network
    async fn orig_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        find_ip_network(
            &map,
            *self
                .inner
                .orig_addrs
                .first()
                .expect("has value with internal network"),
        )
    }

    /// Responder IP (Address)
    async fn resp_addr(&self) -> String {
        self.inner.resp_addr.to_string()
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

    /// Detection Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Detection End Time
    async fn end_time(&self) -> DateTime<Utc> {
        self.inner.end_time
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

    pub async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }
}

impl From<database::ExternalDdos> for ExternalDdos {
    fn from(inner: database::ExternalDdos) -> Self {
        Self { inner }
    }
}

pub(super) struct BlocklistConn {
    inner: database::BlocklistConn,
}

#[Object]
impl BlocklistConn {
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

    /// Responder Port (Number)
    async fn resp_port(&self) -> u16 {
        self.inner.resp_port
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Connection State
    async fn conn_state(&self) -> String {
        self.inner.conn_state.clone()
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

    /// Service Name
    async fn service(&self) -> String {
        self.inner.service.clone()
    }

    /// Bytes Sent (by Source)
    async fn orig_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_bytes)
    }

    /// Bytes Received (by Destination)
    async fn resp_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_bytes)
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
        ThreatLevel::Medium
    }
}

impl From<database::BlocklistConn> for BlocklistConn {
    fn from(inner: database::BlocklistConn) -> Self {
        Self { inner }
    }
}

pub(super) struct TorConnectionConn {
    inner: database::TorConnectionConn,
}

#[Object]
impl TorConnectionConn {
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

    /// Responder Port (Number)
    async fn resp_port(&self) -> u16 {
        self.inner.resp_port
    }

    /// Protocol Number
    async fn proto(&self) -> u8 {
        self.inner.proto
    }

    /// Connection State
    async fn conn_state(&self) -> String {
        self.inner.conn_state.clone()
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

    /// Service Name
    async fn service(&self) -> String {
        self.inner.service.clone()
    }

    /// Bytes Sent (by Source)
    async fn orig_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.orig_bytes)
    }

    /// Bytes Received (by Destination)
    async fn resp_bytes(&self) -> StringNumber<u64> {
        StringNumber(self.inner.resp_bytes)
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
        ThreatLevel::Medium
    }

    /// Learning Method
    async fn learning_method(&self) -> LearningMethod {
        LearningMethod::SemiSupervised
    }
}

impl From<database::TorConnectionConn> for TorConnectionConn {
    fn from(inner: database::TorConnectionConn) -> Self {
        Self { inner }
    }
}
