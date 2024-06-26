use std::{collections::HashMap, net::IpAddr};

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

    pub review: bool,
    pub review_port: Option<PortNumber>,
    pub review_web_port: Option<PortNumber>,

    pub piglet: bool,
    pub piglet_giganto_ip: Option<String>,
    pub piglet_giganto_port: Option<PortNumber>,
    pub piglet_review_ip: Option<String>,
    pub piglet_review_port: Option<PortNumber>,
    pub save_packets: bool,
    pub http: bool,
    pub office: bool,
    pub exe: bool,
    pub pdf: bool,
    pub html: bool,
    pub txt: bool,
    pub smtp_eml: bool,
    pub ftp: bool,

    pub giganto: bool,
    pub giganto_ingestion_ip: Option<String>,
    pub giganto_ingestion_port: Option<PortNumber>,
    pub giganto_publish_ip: Option<String>,
    pub giganto_publish_port: Option<PortNumber>,
    pub giganto_graphql_ip: Option<String>,
    pub giganto_graphql_port: Option<PortNumber>,
    pub retention_period: Option<u16>,

    pub reconverge: bool,
    pub reconverge_review_ip: Option<String>,
    pub reconverge_review_port: Option<PortNumber>,
    pub reconverge_giganto_ip: Option<String>,
    pub reconverge_giganto_port: Option<PortNumber>,

    pub hog: bool,
    pub hog_review_ip: Option<String>,
    pub hog_review_port: Option<PortNumber>,
    pub hog_giganto_ip: Option<String>,
    pub hog_giganto_port: Option<PortNumber>,
    pub protocols: bool,
    pub protocol_list: HashMap<String, bool>,
    pub sensors: bool,
    pub sensor_list: HashMap<String, bool>,
}

impl TryFrom<NodeSettingsInput> for review_database::NodeSettings {
    type Error = anyhow::Error;

    fn try_from(input: NodeSettingsInput) -> Result<Self, Self::Error> {
        Ok(Self {
            customer_id: input.customer_id.parse().context("invalid customer ID")?,
            description: input.description.clone(),
            hostname: input.hostname.clone(),
            review: input.review,
            review_port: input.review_port,
            review_web_port: input.review_web_port,
            piglet: input.piglet,
            piglet_giganto_ip: parse_str_to_ip(input.piglet_giganto_ip.as_deref()),
            piglet_giganto_port: input.piglet_giganto_port,
            piglet_review_ip: parse_str_to_ip(input.piglet_review_ip.as_deref()),
            piglet_review_port: input.piglet_review_port,
            save_packets: input.save_packets,
            http: input.http,
            office: input.office,
            exe: input.exe,
            pdf: input.pdf,
            html: input.html,
            txt: input.txt,
            smtp_eml: input.smtp_eml,
            ftp: input.ftp,
            giganto: input.giganto,
            giganto_ingestion_ip: parse_str_to_ip(input.giganto_ingestion_ip.as_deref()),
            giganto_ingestion_port: input.giganto_ingestion_port,
            giganto_publish_ip: parse_str_to_ip(input.giganto_publish_ip.as_deref()),
            giganto_publish_port: input.giganto_publish_port,
            giganto_graphql_ip: parse_str_to_ip(input.giganto_graphql_ip.as_deref()),
            giganto_graphql_port: input.giganto_graphql_port,
            retention_period: input.retention_period,
            reconverge: input.reconverge,
            reconverge_review_ip: parse_str_to_ip(input.reconverge_review_ip.as_deref()),
            reconverge_review_port: input.reconverge_review_port,
            reconverge_giganto_ip: parse_str_to_ip(input.reconverge_giganto_ip.as_deref()),
            reconverge_giganto_port: input.reconverge_giganto_port,
            hog: input.hog,
            hog_review_ip: parse_str_to_ip(input.hog_review_ip.as_deref()),
            hog_review_port: input.hog_review_port,
            hog_giganto_ip: parse_str_to_ip(input.hog_giganto_ip.as_deref()),
            hog_giganto_port: input.hog_giganto_port,
            protocols: input.protocols,
            protocol_list: input.protocol_list.clone(),
            sensors: input.sensors,
            sensor_list: input.sensor_list.clone(),
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
            settings: input.settings.map(TryInto::try_into).transpose()?,
            settings_draft: input.settings_draft.map(TryInto::try_into).transpose()?,
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
    let (name_draft, settings_draft) = if let Some(draft) = new.settings_draft {
        (new.name_draft, Some(draft.try_into()?))
    } else {
        (None, None)
    };
    Ok(review_database::NodeUpdate {
        name: Some(old.name.clone()),
        name_draft,
        settings: old.settings.clone().map(TryInto::try_into).transpose()?,
        settings_draft,
    })
}
