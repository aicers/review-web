use super::{Node, NodeSetting, PortNumber};
use anyhow::Context as AnyhowContext;
use async_graphql::{types::ID, InputObject, Result};
use review_database::IndexedMapUpdate;
use std::{borrow::Cow, collections::HashMap, net::IpAddr};

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
#[allow(clippy::struct_excessive_bools)]
pub struct NodeSettingInput {
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

impl PartialEq<NodeSetting> for NodeSettingInput {
    fn eq(&self, other: &NodeSetting) -> bool {
        self.customer_id.as_str().parse::<u32>() == Ok(other.customer_id)
            && self.description == other.description
            && self.hostname == other.hostname
            && self.review == other.review
            && self.review_port == other.review_port
            && self.review_web_port == other.review_web_port
            && self.piglet == other.piglet
            && parse_str_to_ip(self.piglet_giganto_ip.as_deref()) == other.piglet_giganto_ip
            && self.piglet_giganto_port == other.piglet_giganto_port
            && parse_str_to_ip(self.piglet_review_ip.as_deref()) == other.piglet_review_ip
            && self.piglet_review_port == other.piglet_review_port
            && self.save_packets == other.save_packets
            && self.http == other.http
            && self.office == other.office
            && self.exe == other.exe
            && self.pdf == other.pdf
            && self.html == other.html
            && self.txt == other.txt
            && self.smtp_eml == other.smtp_eml
            && self.ftp == other.ftp
            && self.giganto == other.giganto
            && parse_str_to_ip(self.giganto_ingestion_ip.as_deref()) == other.giganto_ingestion_ip
            && self.giganto_ingestion_port == other.giganto_ingestion_port
            && parse_str_to_ip(self.giganto_publish_ip.as_deref()) == other.giganto_publish_ip
            && self.giganto_publish_port == other.giganto_publish_port
            && parse_str_to_ip(self.giganto_graphql_ip.as_deref()) == other.giganto_graphql_ip
            && self.giganto_graphql_port == other.giganto_graphql_port
            && self.retention_period == other.retention_period
            && self.reconverge == other.reconverge
            && parse_str_to_ip(self.reconverge_review_ip.as_deref()) == other.reconverge_review_ip
            && self.reconverge_review_port == other.reconverge_review_port
            && parse_str_to_ip(self.reconverge_giganto_ip.as_deref()) == other.reconverge_giganto_ip
            && self.reconverge_giganto_port == other.reconverge_giganto_port
            && self.hog == other.hog
            && parse_str_to_ip(self.hog_review_ip.as_deref()) == other.hog_review_ip
            && self.hog_review_port == other.hog_review_port
            && parse_str_to_ip(self.hog_giganto_ip.as_deref()) == other.hog_giganto_ip
            && self.hog_giganto_port == other.hog_giganto_port
            && self.protocols == other.protocols
            && self.protocol_list == other.protocol_list
            && self.sensors == other.sensors
            && self.sensor_list == other.sensor_list
    }
}

impl PartialEq<NodeSettingInput> for NodeSetting {
    fn eq(&self, other: &NodeSettingInput) -> bool {
        other.eq(self)
    }
}

impl TryFrom<&NodeSettingInput> for NodeSetting {
    type Error = anyhow::Error;

    fn try_from(input: &NodeSettingInput) -> Result<Self, Self::Error> {
        Ok(NodeSetting {
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
    pub setting: Option<NodeSettingInput>,
    pub setting_draft: Option<NodeSettingInput>,
}

impl IndexedMapUpdate for NodeInput {
    type Entry = Node;

    fn key(&self) -> Option<Cow<[u8]>> {
        Some(Cow::Borrowed(self.name.as_bytes()))
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(setting_draft) = self.setting_draft.as_ref() {
            value.name_draft = self.name_draft.clone();
            value.setting_draft = Some(NodeSetting::try_from(setting_draft)?);
        } else {
            value.name_draft = None;
            value.setting_draft = None;
        }
        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        let name_matches = self.name == value.name;

        let name_draft_matches = match (&self.name_draft, &value.name_draft) {
            (Some(input_value), Some(db_value)) => input_value == db_value,
            (Some(_), None) | (None, Some(_)) => false,
            (None, None) => true,
        };

        let setting_matches = match (&self.setting, &value.setting) {
            (Some(input_value), Some(db_value)) => input_value == db_value,
            (Some(_), None) | (None, Some(_)) => false,
            (None, None) => true,
        };

        let setting_draft_matches = match (&self.setting_draft, &value.setting_draft) {
            (Some(input_value), Some(db_value)) => input_value == db_value,
            (Some(_), None) | (None, Some(_)) => false,
            (None, None) => true,
        };

        name_matches && name_draft_matches && setting_matches && setting_draft_matches
    }
}
