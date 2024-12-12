use async_graphql::Object;
use chrono::{DateTime, Utc};
use review_database as database;

use super::TriageScore;
use crate::graphql::triage::ThreatCategory;

#[allow(clippy::module_name_repetitions)]
pub(super) struct WindowsThreat {
    inner: database::WindowsThreat,
}

#[Object]
impl WindowsThreat {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    async fn service(&self) -> &str {
        &self.inner.service
    }

    async fn agent_name(&self) -> &str {
        &self.inner.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.inner.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.inner.process_guid
    }

    async fn process_id(&self) -> u32 {
        self.inner.process_id
    }

    async fn image(&self) -> &str {
        &self.inner.image
    }

    async fn user(&self) -> &str {
        &self.inner.user
    }

    async fn content(&self) -> &str {
        &self.inner.content
    }

    async fn db_name(&self) -> &str {
        &self.inner.db_name
    }

    async fn rule_id(&self) -> u32 {
        self.inner.rule_id
    }

    async fn matched_to(&self) -> &str {
        &self.inner.matched_to
    }

    async fn cluster_id(&self) -> usize {
        self.inner.cluster_id
    }

    async fn attack_kind(&self) -> &str {
        &self.inner.attack_kind
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
}

impl From<database::WindowsThreat> for WindowsThreat {
    fn from(inner: database::WindowsThreat) -> Self {
        Self { inner }
    }
}
