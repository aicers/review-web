use std::net::IpAddr;

use anyhow::Context as AnyhowContext;
use async_graphql::{types::ID, InputObject, Result};

use super::PortNumber;

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
#[allow(clippy::struct_excessive_bools)]
pub struct NodeSettingsInput {
    pub customer_id: ID,
    pub description: String,
    pub hostname: String,
}

impl TryFrom<NodeSettingsInput> for review_database::NodeProfile {
    type Error = anyhow::Error;

    fn try_from(input: NodeSettingsInput) -> Result<Self, Self::Error> {
        Ok(Self {
            customer_id: input.customer_id.parse().context("invalid customer ID")?,
            description: input.description.clone(),
            hostname: input.hostname.clone(),
        })
    }
}

fn parse_str_to_ip(ip_str: Option<&str>) -> Option<IpAddr> {
    ip_str.and_then(|ip_str| ip_str.parse::<IpAddr>().ok())
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
pub(super) struct NodeInput {
    pub name: String,
    pub name_draft: Option<String>,
    pub settings: Option<NodeSettingsInput>,
    pub settings_draft: Option<NodeSettingsInput>,
}

impl TryFrom<NodeInput> for review_database::NodeUpdate {
    type Error = anyhow::Error;

    fn try_from(input: NodeInput) -> Result<Self, Self::Error> {
        Ok(Self {
            name: Some(input.name),
            name_draft: input.name_draft,
            profile: input.settings.clone().map(TryInto::try_into).transpose()?,
            profile_draft: input
                .settings_draft
                .clone()
                .map(TryInto::try_into)
                .transpose()?,
            agents: vec![], // TODO before PR - temp value
            giganto: None,  // TODO before PR - temp value
        })
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
pub(super) struct NodeDraftInput {
    pub name_draft: Option<String>,
    pub settings_draft: Option<NodeSettingsInput>,
}

pub(super) fn create_draft_update(
    old: &NodeInput,
    new: NodeDraftInput,
) -> Result<review_database::NodeUpdate> {
    let (name_draft, profile_draft) = if let Some(draft) = new.settings_draft {
        (new.name_draft, Some(draft.try_into()?))
    } else {
        (None, None)
    };

    Ok(review_database::NodeUpdate {
        name: Some(old.name.clone()),
        name_draft,
        profile: old.settings.clone().map(TryInto::try_into).transpose()?,
        profile_draft,
        agents: vec![], // TODO before PR - temp value
        giganto: None,  // TODO before PR - temp value
    })
}
