use std::{collections::HashMap, fmt};

use anyhow::Context as AnyhowContext;
use async_graphql::{types::ID, Error, InputObject, Result};

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
    pub(super) kind: AgentKind,
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
    pub(super) kind: AgentKind,
    pub(super) key: String,
    pub(super) status: AgentStatus,
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

    let agents: Vec<review_database::Agent> = new
        .agents
        .map(|new_agents| {
            new_agents
                .into_iter()
                .map(|new_agent| {
                    let config = match old_config_map.get(&new_agent.key) {
                        Some(config) => match config.as_ref() {
                            Some(c) => Some(c.clone().try_into().map_err(|_| {
                                Error::new(format!(
                                    "Failed to convert the config to TOML for the agent: {}",
                                    new_agent.key
                                ))
                            })?),
                            None => None,
                        },
                        None => {
                            return Err(Error::new(format!(
                                "Missing configuration for the agent: {}",
                                new_agent.key
                            )))
                        }
                    };

                    let draft = match new_agent.draft {
                        Some(draft) => Some(draft.try_into().map_err(|_| {
                            Error::new(format!(
                                "Failed to convert the draft to TOML for the agent: {}",
                                new_agent.key
                            ))
                        })?),
                        None => None,
                    };

                    Ok(review_database::Agent {
                        node: u32::MAX,
                        key: new_agent.key,
                        kind: new_agent.kind.into(),
                        status: new_agent.status.into(),
                        config,
                        draft,
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();

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
