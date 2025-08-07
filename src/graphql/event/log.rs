use async_graphql::{ID, Object};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore};
use crate::graphql::{filter::LearningMethod, triage::ThreatCategory};

#[allow(clippy::module_name_repetitions)]
pub(super) struct ExtraThreat {
    inner: database::ExtraThreat,
}

#[Object]
impl ExtraThreat {
    /// Timestamp
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

    /// Event Content
    async fn content(&self) -> &str {
        &self.inner.content
    }

    /// Database Name
    async fn db_name(&self) -> &str {
        &self.inner.db_name
    }

    /// Rule ID
    /// The rule id of the event in string wthin the range representable
    /// by a `u32`.
    async fn rule_id(&self) -> ID {
        ID(self.inner.rule_id.to_string())
    }

    /// Referenced Label
    async fn matched_to(&self) -> &str {
        &self.inner.matched_to
    }

    /// Cluster ID
    /// The cluster id of the event in string wthin the range representable
    /// by a `usize`.
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

    /// Confidence Score
    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// Threat Category
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
        LearningMethod::Unsupervised
    }
}

impl From<database::ExtraThreat> for ExtraThreat {
    fn from(inner: database::ExtraThreat) -> Self {
        Self { inner }
    }
}
