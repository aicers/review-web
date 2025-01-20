use std::{collections::HashMap, path::PathBuf, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use ipnet::IpNet;
use review_database::HostNetworkGroup;
pub use roxy::{Process, ResourceUsage};

pub use crate::graphql::{ParsedCertificate, SamplingPolicy};

#[async_trait]
pub trait AgentManager: Send + Sync {
    async fn broadcast_trusted_domains(&self) -> Result<(), anyhow::Error> {
        Err(anyhow!("Not supported"))
    }

    async fn broadcast_internal_networks(
        &self,
        networks: &HostNetworkGroup,
    ) -> Result<Vec<String>, anyhow::Error>;

    async fn broadcast_allow_networks(
        &self,
        networks: &HostNetworkGroup,
    ) -> Result<Vec<String>, anyhow::Error>;

    async fn broadcast_block_networks(
        &self,
        networks: &HostNetworkGroup,
    ) -> Result<Vec<String>, anyhow::Error>;

    async fn broadcast_trusted_user_agent_list(
        &self,
        _list: &[String],
    ) -> Result<(), anyhow::Error> {
        Err(anyhow!("Not supported"))
    }

    /// Returns a list of online applications grouped by host ID.
    ///
    /// The result is a `HashMap` where the key is the hostname and the value is a list of tuples.
    /// Each tuple contains the key of the agent and the name of the application.
    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error>; // (hostname, (agent_key, app_name))

    async fn broadcast_crusher_sampling_policy(
        &self,
        _sampling_policies: &[SamplingPolicy],
    ) -> Result<(), anyhow::Error>;

    /// Returns the list of processes running on the given host.
    async fn get_process_list(&self, _hostname: &str) -> Result<Vec<Process>, anyhow::Error>;

    /// Returns the resource usage of the given host.
    async fn get_resource_usage(&self, _hostname: &str) -> Result<ResourceUsage, anyhow::Error>;

    /// Halts the node with the given hostname.
    async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error>;

    /// Sends a ping message to the given host and waits for a response. Returns
    /// the round-trip time.
    async fn ping(&self, _hostname: &str) -> Result<Duration, anyhow::Error>;

    /// Reboots the node with the given hostname.
    async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error>;

    /// Notifies agents to update their configuration.
    async fn update_config(&self, _agent_key: &str) -> Result<(), anyhow::Error>;

    /// Updates the traffic filter rules for the given host.
    async fn update_traffic_filter_rules(
        &self,
        _host: &str,
        _rules: &[(IpNet, Option<Vec<u16>>, Option<Vec<u16>>)],
    ) -> Result<(), anyhow::Error> {
        Err(anyhow!("Not supported"))
    }
}

pub trait CertManager: Send + Sync {
    /// Returns the certificate path.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate path cannot be determined.
    fn cert_path(&self) -> Result<PathBuf, anyhow::Error>;

    /// Returns the key path.
    ///
    /// # Errors
    ///
    /// Returns an error if the key path cannot be determined.
    fn key_path(&self) -> Result<PathBuf, anyhow::Error>;

    /// Updates the certificate and key.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate and key cannot be updated.
    fn update_certificate(
        &self,
        cert: String,
        key: String,
    ) -> Result<Vec<ParsedCertificate>, anyhow::Error>;
}
