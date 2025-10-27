use async_graphql::{ID, Object};
use chrono::{DateTime, Utc};
use review_database::event as database;

use super::{ThreatLevel, TriageScore};
use crate::graphql::{filter::LearningMethod, triage::ThreatCategory};

#[allow(clippy::module_name_repetitions)]
pub(super) struct WindowsThreat {
    inner: database::WindowsThreat,
}

#[Object]
impl WindowsThreat {
    /// Event Generation Time
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor
    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Service Name
    async fn service(&self) -> &str {
        &self.inner.service
    }

    /// Agent Name
    async fn agent_name(&self) -> &str {
        &self.inner.agent_name
    }

    /// Agent ID
    async fn agent_id(&self) -> &str {
        &self.inner.agent_id
    }

    /// Process GUID
    async fn process_guid(&self) -> &str {
        &self.inner.process_guid
    }

    /// Process ID
    async fn process_id(&self) -> u32 {
        self.inner.process_id
    }

    /// Executable Path
    async fn image(&self) -> &str {
        &self.inner.image
    }

    /// User
    async fn user(&self) -> &str {
        &self.inner.user
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
    async fn rule_id(&self) -> u32 {
        self.inner.rule_id
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
    async fn category(&self) -> Option<ThreatCategory> {
        self.inner.category.map(Into::into)
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
        LearningMethod::Unsupervised
    }
}

impl From<database::WindowsThreat> for WindowsThreat {
    fn from(inner: database::WindowsThreat) -> Self {
        Self { inner }
    }
}
