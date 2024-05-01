pub use crate::graphql::{ParsedCertificate, SamplingPolicy};
use anyhow::anyhow;
use async_trait::async_trait;
use ipnet::IpNet;
pub use review_protocol::types::Config;
pub use roxy::{Process, ResourceUsage};
use std::{collections::HashMap, path::PathBuf};

#[async_trait]
pub trait AgentManager: Send + Sync {
    async fn broadcast_trusted_domains(&self) -> Result<(), anyhow::Error> {
        Err(anyhow!("Not supported"))
    }

    async fn broadcast_internal_networks(
        &self,
        _networks: &[u8],
    ) -> Result<Vec<String>, anyhow::Error>;

    async fn broadcast_allow_networks(
        &self,
        _networks: &[u8],
    ) -> Result<Vec<String>, anyhow::Error>;

    async fn broadcast_block_networks(
        &self,
        _networks: &[u8],
    ) -> Result<Vec<String>, anyhow::Error>;

    async fn broadcast_trusted_user_agent_list(&self, _list: &[u8]) -> Result<(), anyhow::Error> {
        Err(anyhow!("Not supported"))
    }

    async fn online_apps_by_host_id(
        &self,
    ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error>; // (hostname, (agent_key, app_name))

    async fn broadcast_crusher_sampling_policy(
        &self,
        _sampling_policies: &[SamplingPolicy],
    ) -> Result<(), anyhow::Error>;

    /// Returns the configuration of the given agent.
    async fn get_config(&self, _hostname: &str, _agent_id: &str) -> Result<Config, anyhow::Error>;

    /// Returns the list of processes running on the given host.
    async fn get_process_list(&self, _hostname: &str) -> Result<Vec<Process>, anyhow::Error>;

    /// Returns the resource usage of the given host.
    async fn get_resource_usage(&self, _hostname: &str) -> Result<ResourceUsage, anyhow::Error>;

    /// Halts the node with the given hostname.
    async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error>;

    /// Sends a ping message to the given host and waits for a response. Returns
    /// the round-trip time in microseconds.
    async fn ping(&self, _hostname: &str) -> Result<i64, anyhow::Error>;

    /// Reboots the node with the given hostname.
    async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error>;

    /// Sets the configuration of the given agent.
    async fn set_config(
        &self,
        _hostname: &str,
        _agent_id: &str,
        _config: &Config,
    ) -> Result<(), anyhow::Error>;

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
