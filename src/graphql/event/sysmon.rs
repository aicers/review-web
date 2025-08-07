use async_graphql::{ID, Object};
use chrono::{DateTime, Utc};
use review_database as database;

use super::{ThreatLevel, TriageScore};
use crate::graphql::{filter::LearningMethod, triage::ThreatCategory};

#[allow(clippy::module_name_repetitions)]
pub(super) struct WindowsThreat {
    inner: database::WindowsThreat,
}

#[Object]
impl WindowsThreat {
    /// Timestamp (타임스탬프)
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    /// Sensor (센서)
    async fn sensor(&self) -> &str {
        &self.inner.sensor
    }

    /// Service Name (서비스 이름)
    async fn service(&self) -> &str {
        &self.inner.service
    }

    /// Agent Name (에이전트 이름)
    async fn agent_name(&self) -> &str {
        &self.inner.agent_name
    }

    /// Agent ID (에이전트 ID)
    async fn agent_id(&self) -> &str {
        &self.inner.agent_id
    }

    /// Process GUID (프로세스 GUID)
    async fn process_guid(&self) -> &str {
        &self.inner.process_guid
    }

    /// Process ID (프로세스 ID)
    async fn process_id(&self) -> u32 {
        self.inner.process_id
    }

    /// Executable Path (실행 파일 경로)
    async fn image(&self) -> &str {
        &self.inner.image
    }

    /// User (사용자)
    async fn user(&self) -> &str {
        &self.inner.user
    }

    /// Event Content (이벤트 내용)
    async fn content(&self) -> &str {
        &self.inner.content
    }

    /// Database Name (데이터베이스 이름)
    async fn db_name(&self) -> &str {
        &self.inner.db_name
    }

    /// Rule ID (규칙 ID)
    async fn rule_id(&self) -> u32 {
        self.inner.rule_id
    }

    /// Referenced Label (참조 레이블)
    async fn matched_to(&self) -> &str {
        &self.inner.matched_to
    }

    /// Cluster ID (클러스터 ID)
    async fn cluster_id(&self) -> ID {
        ID(self
            .inner
            .cluster_id
            .map_or(String::new(), |id| id.to_string()))
    }

    /// Attack Kind (공격 유형)
    async fn attack_kind(&self) -> &str {
        &self.inner.attack_kind
    }

    /// Confidence Score (신뢰도)
    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    /// Threat Category (위협 범주)
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// Triage Scores (분류 점수)
    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }

    /// Threat Level (위협 수준)
    async fn level(&self) -> ThreatLevel {
        ThreatLevel::Medium
    }

    /// Learning Method (학습 방법)
    async fn learning_method(&self) -> LearningMethod {
        LearningMethod::Unsupervised
    }
}

impl From<database::WindowsThreat> for WindowsThreat {
    fn from(inner: database::WindowsThreat) -> Self {
        Self { inner }
    }
}
