use std::convert::{TryFrom, TryInto};

use anyhow::Context as AnyhowContext;
use async_graphql::{Context, InputObject, Object, Result, SimpleObject};
use review_database::{self as database, Store};
use serde::{Deserialize, Serialize};

use super::BoxedAgentManager;
use super::node::agent_lookup_key_service_token;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetworksTargetAgentLookupKeysPair {
    networks: database::HostNetworkGroup,
    target_agent_lookup_keys: Vec<String>,
}

impl NetworksTargetAgentLookupKeysPair {
    #[must_use]
    pub fn new(
        networks: database::HostNetworkGroup,
        agent_lookup_keys: Vec<String>,
        target_agent: &str,
    ) -> Self {
        Self {
            networks,
            target_agent_lookup_keys: agent_lookup_keys
                .into_iter()
                .filter(|agent_lookup_key| {
                    agent_lookup_key_service_token(agent_lookup_key) == Some(target_agent)
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn target_agent_lookup_keys(&self) -> &[String] {
        &self.target_agent_lookup_keys
    }

    #[must_use]
    pub fn networks(&self) -> &database::HostNetworkGroup {
        &self.networks
    }
}

#[derive(Clone, InputObject)]
pub struct HostNetworkGroupInput {
    pub hosts: Vec<String>,
    pub networks: Vec<String>,
    pub ranges: Vec<IpRangeInput>,
}

impl PartialEq<database::HostNetworkGroup> for HostNetworkGroupInput {
    fn eq(&self, rhs: &database::HostNetworkGroup) -> bool {
        if self.hosts.len() != rhs.hosts().len()
            || self.networks.len() != rhs.networks().len()
            || self.ranges.len() != rhs.ip_ranges().len()
        {
            return false;
        }

        for h in &self.hosts {
            let Ok(addr) = h.parse() else {
                return false;
            };
            if !rhs.contains_host(addr) {
                return false;
            }
        }
        for n in &self.networks {
            let Ok(net) = n.parse() else {
                return false;
            };
            if !rhs.contains_network(&net) {
                return false;
            }
        }
        for r in &self.ranges {
            let Ok(start) = r.start.parse() else {
                return false;
            };
            let Ok(end) = r.end.parse() else {
                return false;
            };
            if !rhs.contains_ip_range(&(start..=end)) {
                return false;
            }
        }
        true
    }
}

impl TryFrom<HostNetworkGroupInput> for database::HostNetworkGroup {
    type Error = anyhow::Error;

    fn try_from(input: HostNetworkGroupInput) -> Result<Self, Self::Error> {
        (&input).try_into()
    }
}

impl TryFrom<&HostNetworkGroupInput> for database::HostNetworkGroup {
    type Error = anyhow::Error;

    fn try_from(input: &HostNetworkGroupInput) -> Result<Self, Self::Error> {
        let mut hosts = Vec::with_capacity(input.hosts.len());
        for h in &input.hosts {
            hosts.push(h.parse().context("invalid host address")?);
        }

        let mut networks = Vec::with_capacity(input.networks.len());
        for n in &input.networks {
            networks.push(n.parse().context("invalid network address")?);
        }

        let mut ip_ranges = Vec::with_capacity(input.ranges.len());
        for r in &input.ranges {
            let start = r.start.parse().context("invalid start address")?;
            let end = r.end.parse().context("invalid end address")?;
            ip_ranges.push(start..=end);
        }

        Ok(Self::new(hosts, networks, ip_ranges))
    }
}

#[derive(Clone, InputObject)]
pub struct IpRangeInput {
    pub start: String,
    pub end: String,
}

pub(super) struct HostNetworkGroup<'a> {
    inner: &'a database::HostNetworkGroup,
}

#[Object]
impl HostNetworkGroup<'_> {
    #[graphql(name = "hosts")]
    async fn hosts_as_strings(&self) -> Vec<String> {
        self.inner.hosts().iter().map(ToString::to_string).collect()
    }

    #[graphql(name = "networks")]
    async fn networks_as_strings(&self) -> Vec<String> {
        self.inner
            .networks()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    async fn ranges(&self) -> Vec<IpRange> {
        self.inner
            .ip_ranges()
            .iter()
            .map(|r| IpRange {
                start: r.start().to_string(),
                end: r.end().to_string(),
            })
            .collect()
    }
}

impl<'a> From<&'a database::HostNetworkGroup> for HostNetworkGroup<'a> {
    fn from(inner: &'a database::HostNetworkGroup) -> Self {
        Self { inner }
    }
}

#[derive(SimpleObject)]
struct IpRange {
    start: String,
    end: String,
}

/// Returns the networks the customer owns, merged into one group whatever
/// their type, as stored in the customer networks table.
///
/// A customer with no stored row owns no networks, and gets an empty group.
///
/// # Errors
///
/// Returns an error if the stored row could not be read or decoded.
pub fn get_customer_networks(db: &Store, customer_id: u32) -> Result<database::HostNetworkGroup> {
    Ok(db
        .customer_networks_map()
        .get(customer_id)?
        .map(|set| set.merged_group())
        .unwrap_or_default())
}

/// Returns a list of agents that received the internal networks.
///
/// # Errors
///
/// Returns an error if the broadcast fail.
pub async fn send_agent_specific_customer_networks(
    ctx: &Context<'_>,
    networks: &[NetworksTargetAgentLookupKeysPair],
) -> Result<Vec<String>> {
    let agent_manager = ctx.data::<BoxedAgentManager>()?;
    agent_manager
        .send_agent_specific_internal_networks(networks)
        .await
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use review_database as database;

    use super::NetworksTargetAgentLookupKeysPair;

    #[test]
    fn network_target_agent_lookup_keys_pair_filters_mtls_service_tokens() {
        let networks = database::HostNetworkGroup::new(vec![], vec![], vec![]);
        let agent_lookup_keys = vec![
            "001.hog.node-01.customer.internal".to_string(),
            "002.hog.node-01.customer.internal".to_string(),
            "001.reconverge.node-01.customer.internal".to_string(),
        ];
        let pair = NetworksTargetAgentLookupKeysPair::new(
            networks.clone(),
            agent_lookup_keys.clone(),
            "hog",
        );
        assert_eq!(pair.target_agent_lookup_keys(), &agent_lookup_keys[..2]);

        let pair = NetworksTargetAgentLookupKeysPair::new(networks, agent_lookup_keys, "piglet");
        assert_eq!(pair.target_agent_lookup_keys().len(), 0);
    }
}
