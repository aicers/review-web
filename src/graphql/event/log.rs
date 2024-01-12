use super::TriageScore;
use async_graphql::Object;
use chrono::{DateTime, Utc};
use review_database as database;

#[allow(clippy::module_name_repetitions)]
pub(super) struct ExtraThreat {
    inner: database::ExtraThreat,
}

#[Object]
impl ExtraThreat {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn service(&self) -> &str {
        &self.inner.service
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

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::ExtraThreat> for ExtraThreat {
    fn from(inner: database::ExtraThreat) -> Self {
        Self { inner }
    }
}
