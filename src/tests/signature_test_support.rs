//! Shared required-method stubs for the signature surface tests.
macro_rules! impl_signature_test_manager {
    ($name:ty { $($methods:tt)* }) => {
        #[async_trait::async_trait]
        impl crate::backend::AgentManager for $name {
            $($methods)*
            async fn request_customer_data_deletion(&self, _targets: &[crate::customer_data_deletion::CustomerDataDeletionTarget]) -> Result<(), anyhow::Error> { anyhow::bail!("unexpected call") }
            async fn send_agent_specific_internal_networks(&self, _networks: &[crate::graphql::NetworksTargetAgentLookupKeysPair]) -> Result<Vec<String>, anyhow::Error> { anyhow::bail!("unexpected call") }
            async fn send_agent_specific_exclusion_list(&self, _networks: &[crate::graphql::NetworkListItemsTargetAgentLookupKeysPair]) -> Result<Vec<String>, anyhow::Error> { anyhow::bail!("unexpected call") }
            async fn send_agent_specific_watchlist(&self, _networks: &[crate::graphql::NetworkListItemsTargetAgentLookupKeysPair]) -> Result<Vec<String>, anyhow::Error> { anyhow::bail!("unexpected call") }
            async fn online_apps_by_host_id(&self) -> Result<std::collections::HashMap<String, Vec<(String, String)>>, anyhow::Error> { anyhow::bail!("unexpected call") }
            async fn time_series_generation_policies_changed(&self, _generators: &[review_database::ModelInstance]) {}
            async fn capabilities(&self, _hostname: &str) -> Result<std::collections::BTreeSet<String>, anyhow::Error> { anyhow::bail!("unexpected call") }
            async fn get_resource_usage(&self, _hostname: &str) -> Result<review_protocol::types::ResourceUsage, anyhow::Error> { anyhow::bail!("unexpected call") }
            async fn halt(&self, _hostname: &str) -> Result<(), anyhow::Error> { anyhow::bail!("unexpected call") }
            async fn ping(&self, _hostname: &str) -> Result<std::time::Duration, anyhow::Error> { anyhow::bail!("unexpected call") }
            async fn reboot(&self, _hostname: &str) -> Result<(), anyhow::Error> { anyhow::bail!("unexpected call") }
            async fn update_config(&self, _agent_lookup_key: &str) -> Result<(), anyhow::Error> { anyhow::bail!("unexpected call") }
        }
    };
}
pub(crate) use impl_signature_test_manager;
