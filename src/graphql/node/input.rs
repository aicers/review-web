use super::{Node, PortNumber}; //NicInput
use anyhow::Context as AnyhowContext; //bail
use async_graphql::{types::ID, InputObject, Result};
use review_database::IndexedMapUpdate;
use std::{collections::HashMap, net::IpAddr};

#[allow(clippy::module_name_repetitions)]
#[derive(Clone, InputObject)]
#[allow(clippy::struct_excessive_bools)]
pub(super) struct NodeInput {
    pub name: String,
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

impl IndexedMapUpdate for NodeInput {
    type Entry = Node;

    fn key(&self) -> Option<&[u8]> {
        Some(self.name.as_bytes())
    }

    #[allow(clippy::too_many_lines)]
    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.name.clear();
        value.name.push_str(&self.name);
        value.customer_id = self
            .customer_id
            .as_str()
            .parse::<u32>()
            .context("invalid customer ID")?;
        value.description.clear();
        value.description.push_str(&self.description);
        value.hostname.clear();
        value.hostname.push_str(&self.hostname);

        // review
        value.review = self.review;
        value.review_port = self.review_port;
        value.review_web_port = self.review_web_port;

        // piglet
        value.piglet = self.piglet;
        value.piglet_giganto_ip = if let Some(ip) = self.piglet_giganto_ip.as_deref() {
            Some(ip.parse::<IpAddr>().context("invalid IP address")?)
        } else {
            None
        };
        value.piglet_giganto_port = self.piglet_giganto_port;
        value.piglet_review_ip = if let Some(ip) = self.piglet_review_ip.as_deref() {
            Some(ip.parse::<IpAddr>().context("invalid IP address")?)
        } else {
            None
        };
        value.piglet_review_port = self.piglet_review_port;
        value.save_packets = self.save_packets;
        value.http = self.http;
        value.office = self.office;
        value.exe = self.exe;
        value.pdf = self.pdf;
        value.html = self.html;
        value.txt = self.txt;
        value.smtp_eml = self.smtp_eml;
        value.ftp = self.ftp;

        // giganto
        value.giganto = self.giganto;
        value.giganto_ingestion_ip = if let Some(ip) = self.giganto_ingestion_ip.as_deref() {
            Some(ip.parse::<IpAddr>().context("invalid IP address")?)
        } else {
            None
        };
        value.giganto_ingestion_port = self.giganto_ingestion_port;
        value.giganto_publish_ip = if let Some(ip) = self.giganto_publish_ip.as_deref() {
            Some(ip.parse::<IpAddr>().context("invalid IP address")?)
        } else {
            None
        };
        value.giganto_publish_port = self.giganto_publish_port;
        value.giganto_graphql_ip = if let Some(ip) = self.giganto_graphql_ip.as_deref() {
            Some(ip.parse::<IpAddr>().context("invalid IP address")?)
        } else {
            None
        };
        value.giganto_graphql_port = self.giganto_graphql_port;
        value.retention_period = self.retention_period;

        // reconverge
        value.reconverge = self.reconverge;
        value.reconverge_review_ip = if let Some(ip) = self.reconverge_review_ip.as_deref() {
            Some(ip.parse::<IpAddr>().context("invalid IP address")?)
        } else {
            None
        };
        value.reconverge_review_port = self.reconverge_review_port;
        value.reconverge_giganto_ip = if let Some(ip) = self.reconverge_giganto_ip.as_deref() {
            Some(ip.parse::<IpAddr>().context("invalid IP address")?)
        } else {
            None
        };
        value.reconverge_giganto_port = self.reconverge_giganto_port;

        // hog
        value.hog = self.hog;
        value.hog_review_ip = if let Some(ip) = self.hog_review_ip.as_deref() {
            Some(ip.parse::<IpAddr>().context("invalid IP address")?)
        } else {
            None
        };
        value.hog_review_port = self.hog_review_port;
        value.hog_giganto_ip = if let Some(ip) = self.hog_giganto_ip.as_deref() {
            Some(ip.parse::<IpAddr>().context("invalid IP address")?)
        } else {
            None
        };
        value.hog_giganto_port = self.hog_giganto_port;
        value.protocols = self.protocols;
        value.protocol_list = self.protocol_list.clone();
        value.sensors = self.sensors;
        value.sensor_list = self.sensor_list.clone();

        Ok(value)
    }

    #[allow(clippy::too_many_lines)]
    fn verify(&self, value: &Self::Entry) -> bool {
        if self.name != value.name {
            return false;
        }
        if self
            .customer_id
            .as_str()
            .parse::<u32>()
            .map_or(true, |id| id != value.customer_id)
        {
            return false;
        }
        if self.description != value.description {
            return false;
        }
        if self.hostname != value.hostname {
            return false;
        }

        // review
        if self.review != value.review {
            return false;
        }
        if self.review_port != value.review_port {
            return false;
        }
        if self.review_web_port != value.review_web_port {
            return false;
        }

        // piglet
        if self.piglet != value.piglet {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) =
            (self.piglet_giganto_ip.as_deref(), value.piglet_giganto_ip)
        {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.piglet_giganto_ip.is_some() || value.piglet_giganto_ip.is_some() {
            return false;
        }
        if self.piglet_giganto_port != value.piglet_giganto_port {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) =
            (self.piglet_review_ip.as_deref(), value.piglet_review_ip)
        {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.piglet_review_ip.is_some() || value.piglet_review_ip.is_some() {
            return false;
        }
        if self.piglet_review_port != value.piglet_review_port {
            return false;
        }
        if self.save_packets != value.save_packets {
            return false;
        }
        if self.http != value.http {
            return false;
        }
        if self.office != value.office {
            return false;
        }
        if self.exe != value.exe {
            return false;
        }
        if self.pdf != value.pdf {
            return false;
        }
        if self.html != value.html {
            return false;
        }
        if self.txt != value.txt {
            return false;
        }
        if self.smtp_eml != value.smtp_eml {
            return false;
        }
        if self.ftp != value.ftp {
            return false;
        }

        // giganto
        if self.giganto != value.giganto {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) = (
            self.giganto_ingestion_ip.as_deref(),
            value.giganto_ingestion_ip,
        ) {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.giganto_ingestion_ip.is_some() || value.giganto_ingestion_ip.is_some() {
            return false;
        }
        if self.giganto_ingestion_port != value.giganto_ingestion_port {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) =
            (self.giganto_publish_ip.as_deref(), value.giganto_publish_ip)
        {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.giganto_publish_ip.is_some() || value.giganto_publish_ip.is_some() {
            return false;
        }
        if self.giganto_publish_port != value.giganto_publish_port {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) =
            (self.giganto_graphql_ip.as_deref(), value.giganto_graphql_ip)
        {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.giganto_graphql_ip.is_some() || value.giganto_graphql_ip.is_some() {
            return false;
        }
        if self.giganto_graphql_port != value.giganto_graphql_port {
            return false;
        }
        if self.retention_period != value.retention_period {
            return false;
        }

        // reconverge
        if self.reconverge != value.reconverge {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) = (
            self.reconverge_review_ip.as_deref(),
            value.reconverge_review_ip,
        ) {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.reconverge_review_ip.is_some() || value.reconverge_review_ip.is_some() {
            return false;
        }
        if self.reconverge_review_port != value.reconverge_review_port {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) = (
            self.reconverge_giganto_ip.as_deref(),
            value.reconverge_giganto_ip,
        ) {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.reconverge_giganto_ip.is_some() || value.reconverge_giganto_ip.is_some() {
            return false;
        }
        if self.reconverge_giganto_port != value.reconverge_giganto_port {
            return false;
        }

        // hog
        if self.hog != value.hog {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) =
            (self.hog_review_ip.as_deref(), value.hog_review_ip)
        {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.hog_review_ip.is_some() || value.hog_review_ip.is_some() {
            return false;
        }
        if self.hog_review_port != value.hog_review_port {
            return false;
        }
        if let (Some(ip_self), Some(ip_value)) =
            (self.hog_giganto_ip.as_deref(), value.hog_giganto_ip)
        {
            if ip_self
                .parse::<IpAddr>()
                .map_or(true, |ip_self| ip_self != ip_value)
            {
                return false;
            }
        } else if self.hog_giganto_ip.is_some() || value.hog_giganto_ip.is_some() {
            return false;
        }
        if self.hog_giganto_port != value.hog_giganto_port {
            return false;
        }
        if self.protocols != value.protocols {
            return false;
        }
        if self.protocol_list != value.protocol_list {
            return false;
        }
        if self.sensors != value.sensors {
            return false;
        }
        if self.sensor_list != value.sensor_list {
            return false;
        }

        true
    }
}
