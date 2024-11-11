use std::{collections::HashMap, fmt};

use anyhow::Context as AnyhowContext;
use async_graphql::{types::ID, InputObject, Result};

use super::{AgentKind, AgentStatus};

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject, PartialEq)]
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

impl fmt::Display for NodeProfileInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ customer_id: {}, description: {}, hostname: {} }}",
            *self.customer_id, self.description, self.hostname
        )
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
pub struct AgentInput {
    kind: AgentKind,
    pub(super) key: String,
    status: AgentStatus,
    pub(super) config: Option<String>,
    pub(super) draft: Option<String>,
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
pub struct AgentDraftInput {
    kind: AgentKind,
    pub(super) key: String,
    status: AgentStatus,
    pub(super) draft: Option<String>,
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
    pub agents: Option<Vec<AgentDraftInput>>,
    pub giganto: Option<GigantoInput>,
}

pub(super) fn create_draft_update(
    old: &NodeInput,
    new: NodeDraftInput,
) -> Result<review_database::NodeUpdate> {
    if new.name_draft.is_empty() {
        return Err("missing name draft".into());
    }

    let profile_draft = if let Some(draft) = new.profile_draft {
        Some(draft.try_into()?)
    } else {
        None
    };

    let old_config_map: HashMap<String, Option<String>> = old
        .agents
        .iter()
        .map(|agent| (agent.key.clone(), agent.config.clone()))
        .collect();

    let agents: Vec<review_database::Agent> = if let Some(new_agents) = new.agents {
        new_agents
            .into_iter()
            .map(|agent_draft| {
                let config = old_config_map
                    .get(&agent_draft.key)
                    .and_then(|config| config.as_ref().and_then(|c| c.clone().try_into().ok()));

                review_database::Agent {
                    node: u32::MAX,
                    key: agent_draft.key,
                    kind: agent_draft.kind.into(),
                    status: agent_draft.status.into(),
                    config,
                    draft: agent_draft.draft.and_then(|draft| draft.try_into().ok()),
                }
            })
            .collect()
    } else {
        Vec::new()
    };

    let giganto: Option<review_database::Giganto> = new.giganto.map(Into::into);

    Ok(review_database::NodeUpdate {
        name: Some(old.name.clone()),
        name_draft: Some(new.name_draft),
        profile: old.profile.clone().map(TryInto::try_into).transpose()?,
        profile_draft,
        agents,
        giganto,
    })
}
