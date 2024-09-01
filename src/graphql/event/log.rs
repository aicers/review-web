use async_graphql::{Object, ID};
use chrono::{DateTime, Utc};
use review_database as database;

use super::TriageScore;

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

impl From<database::ExtraThreat> for ExtraThreat {
    fn from(inner: database::ExtraThreat) -> Self {
        Self { inner }
    }
}
