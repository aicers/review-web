use anyhow::Context as AnyhowContext;
use async_graphql::{types::ID, InputObject, Result};

use super::{AgentKind, AgentStatus};

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
pub struct NodeProfileInput {
    pub customer_id: ID,
    pub description: String,
    pub hostname: String,
}

impl TryFrom<NodeProfileInput> for review_database::NodeProfile {
    type Error = anyhow::Error;

    fn try_from(input: NodeProfileInput) -> Result<Self, Self::Error> {
        Ok(Self {
            customer_id: input.customer_id.parse().context("invalid customer ID")?,
            description: input.description.clone(),
            hostname: input.hostname.clone(),
        })
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
pub struct AgentInput {
    key: String,
    kind: AgentKind,
    status: AgentStatus,
    config: Option<String>,
    draft: Option<String>,
}

impl From<AgentInput> for review_database::Agent {
    fn from(input: AgentInput) -> Self {
        Self {
            node: u32::MAX,
            key: input.key,
            kind: input.kind.into(),
            status: input.status.into(),
            config: input.config.and_then(|config| config.try_into().ok()),
            draft: input.draft.and_then(|draft| draft.try_into().ok()),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
pub struct GigantoInput {
    status: AgentStatus,
    draft: Option<String>,
}

impl From<GigantoInput> for review_database::Giganto {
    fn from(input: GigantoInput) -> Self {
        Self {
            status: input.status.into(),
            draft: input.draft.and_then(|draft| draft.try_into().ok()),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
pub(super) struct NodeInput {
    pub name: String,
    pub name_draft: Option<String>,
    pub profile: Option<NodeProfileInput>,
    pub profile_draft: Option<NodeProfileInput>,
    pub agents: Vec<AgentInput>,
    pub giganto: Option<GigantoInput>,
}

impl TryFrom<NodeInput> for review_database::NodeUpdate {
    type Error = anyhow::Error;

    fn try_from(input: NodeInput) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Some(input.name),
            name_draft: input.name_draft,
            profile: input.profile.map(TryInto::try_into).transpose()?,
            profile_draft: input.profile_draft.map(TryInto::try_into).transpose()?,
            agents: input.agents.into_iter().map(Into::into).collect(),
            giganto: input.giganto.map(Into::into),
        })
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
pub(super) struct NodeDraftInput {
    pub name_draft: String,
    pub profile_draft: Option<NodeProfileInput>,
    pub agents: Option<Vec<AgentInput>>,
    pub giganto: Option<GigantoInput>,
}

pub(super) fn create_draft_update(
    old: &NodeInput,
    new: NodeDraftInput,
) -> Result<review_database::NodeUpdate> {
    let (name_draft, profile_draft) = if let Some(draft) = new.profile_draft {
        if new.name_draft.is_empty() {
            return Err("missing name draft".into());
        }
        (Some(new.name_draft), Some(draft.try_into()?))
    } else {
        (None, None)
    };

    let agents: Vec<review_database::Agent> = if let Some(agents) = new.agents {
        agents.into_iter().map(Into::into).collect()
    } else {
        Vec::new()
    };

    let giganto: Option<review_database::Giganto> = new.giganto.map(Into::into);

    Ok(review_database::NodeUpdate {
        name: Some(old.name.clone()),
        name_draft,
        profile: old.profile.clone().map(TryInto::try_into).transpose()?,
        profile_draft,
        agents,
        giganto,
    })
}
