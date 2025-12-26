use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use review_database::event as database;

use super::{ThreatLevel, TriageScore, country_code, find_ip_customer, find_ip_network};
use crate::graphql::{
    customer::Customer, filter::LearningMethod, network::Network, triage::ThreatCategory,
};

/// An event indicating an unusual pattern of connections to multiple
/// responder IP addresses.
pub(super) struct UnusualDestinationPattern {
    inner: database::UnusualDestinationPattern,
}

#[Object]
impl UnusualDestinationPattern {
    /// Event Generation Time
    pub async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    pub async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Detection Start Time
    async fn start_time(&self) -> DateTime<Utc> {
        self.inner.start_time
    }

    /// Detection End Time
    async fn end_time(&self) -> DateTime<Utc> {
        self.inner.end_time
    }

    /// Responder IP (Address) List
    async fn resp_addrs(&self) -> Vec<String> {
        self.inner
            .destination_ips
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Responder Country List
    /// The two-letter country codes of the responder IP addresses. `"XX"` if
    /// the location of an address is not known, and `"ZZ"` if the location
    /// database is unavailable.
    async fn resp_countries(&self, ctx: &Context<'_>) -> Vec<String> {
        self.inner
            .destination_ips
            .iter()
            .map(|resp_addr| country_code(ctx, *resp_addr))
            .collect()
    }

    /// Responder Customer List
    async fn resp_customers(&self, ctx: &Context<'_>) -> Result<Vec<Option<Customer>>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.customer_map();
        let mut customers = vec![];
        for resp_addr in &self.inner.destination_ips {
            customers.push(find_ip_customer(&map, *resp_addr)?);
        }
        Ok(customers)
    }

    /// Responder Network
    async fn resp_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.network_map();
        if let Some(first_ip) = self.inner.destination_ips.first() {
            find_ip_network(&map, *first_ip)
        } else {
            Ok(None)
        }
    }

    /// Count of connections
    #[allow(clippy::cast_possible_wrap)]
    async fn count(&self) -> i64 {
        self.inner.count as i64
    }

    /// Expected mean of connections
    async fn expected_mean(&self) -> f64 {
        self.inner.expected_mean
    }

    /// Standard deviation of connections
    async fn std_deviation(&self) -> f64 {
        self.inner.std_deviation
    }

    /// Z-score indicating how many standard deviations the count is from the
    /// mean
    async fn z_score(&self) -> f64 {
        self.inner.z_score
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
        LearningMethod::SemiSupervised
    }
}

impl From<database::UnusualDestinationPattern> for UnusualDestinationPattern {
    fn from(inner: database::UnusualDestinationPattern) -> Self {
        Self { inner }
    }
}
