use super::{BoxedAgentManager, Role, RoleGuard};
use async_graphql::{Context, Object, Result};
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use review_database::{self as database, Store};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

#[derive(Default)]
pub(super) struct TrafficFilterQuery;

#[Object]
impl TrafficFilterQuery {
    /// traffic filtering rules of agents.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn traffic_filter_list(
        &self,
        ctx: &Context<'_>,
        agents: Option<Vec<String>>,
    ) -> Result<Option<Vec<TrafficFilter>>> {
        let store = ctx.data::<Arc<Store>>()?;
        let res = database::TrafficFilter::get_list(store, &agents)?;
        Ok(res.map(|r| r.into_iter().map(Into::into).collect()))
    }
}

#[derive(Default)]
pub(super) struct TrafficFilterMutation;

#[Object]
impl TrafficFilterMutation {
    /// inserts traffic filtering rules
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn insert_traffic_filter_rules(
        &self,
        ctx: &Context<'_>,
        agent: String,
        network: String,
        tcp_ports: Option<Vec<u16>>,
        udp_ports: Option<Vec<u16>>,
        description: Option<String>,
    ) -> Result<usize> {
        let network = parse_network(&network)?;
        let store = ctx.data::<Arc<Store>>()?;
        database::TrafficFilter::insert(store, &agent, network, tcp_ports, udp_ports, description)
            .map_err(Into::into)
    }

    /// updates traffic filtering rules
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn update_traffic_filter_rules(
        &self,
        ctx: &Context<'_>,
        agent: String,
        network: String,
        tcp_ports: Option<Vec<u16>>,
        udp_ports: Option<Vec<u16>>,
        description: Option<String>,
    ) -> Result<usize> {
        let network = parse_network(&network)?;
        let store = ctx.data::<Arc<Store>>()?;
        database::TrafficFilter::update(store, &agent, network, tcp_ports, udp_ports, description)
            .map_err(Into::into)
    }

    /// clears traffic filtering rules
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn clear_traffic_filter_rules(&self, ctx: &Context<'_>, agent: String) -> Result<usize> {
        let store = ctx.data::<Arc<Store>>()?;
        database::TrafficFilter::clear(store, &agent).map_err(Into::into)
    }

    /// removes traffic filtering rules from the agent
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn remove_traffic_filter_rules(
        &self,
        ctx: &Context<'_>,
        agent: String,
        networks: Vec<String>,
    ) -> Result<usize> {
        let mut new_rules: Vec<IpNet> = Vec::new();
        for network in networks {
            new_rules.push(parse_network(&network)?);
        }
        let store = ctx.data::<Arc<Store>>()?;
        database::TrafficFilter::remove(store, &agent, &new_rules).map_err(Into::into)
    }

    /// applies traffic filtering rules to the agents if it is connected
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn apply_traffic_filter_rules(
        &self,
        ctx: &Context<'_>,
        agents: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = ctx.data::<Arc<Store>>()?;
        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        let mut res = Vec::new();
        for agent in &agents {
            if let Some(tf) = database::TrafficFilter::get(store, agent)? {
                if let Err(e) = agent_manager
                    .update_traffic_filter_rules(agent, &tf.rules())
                    .await
                {
                    res.push(format!("{agent}: update request failed. {e:?}"));
                } else {
                    database::TrafficFilter::update_time(store, agent)?;
                    res.push(format!("{agent}: {} rules are updated.", tf.len()));
                }
            }
        }
        Ok(res)
    }
}

fn parse_network(network: &str) -> Result<IpNet> {
    if network.to_lowercase() == "any" {
        IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).map_err(Into::into)
    } else {
        network.parse::<IpNet>().map_err(Into::into)
    }
}

struct TrafficFilter {
    inner: database::TrafficFilter,
}

#[Object]
impl TrafficFilter {
    /// Agent name
    async fn agent(&self) -> &str {
        &self.inner.agent
    }

    /// The traffic filter rules.
    async fn rules(&self) -> Vec<String> {
        #[allow(clippy::type_complexity)] // allowable and even clearer for this case
        let mut rules: Vec<(IpNet, Option<Vec<u16>>, Option<Vec<u16>>)> = self.inner.rules();
        rules.sort_by(|a, b| a.0.cmp(&b.0));
        rules
            .into_iter()
            .map(|(net, tcp_ports, udp_ports)| {
                let tcp_ports = tcp_ports.map_or("-".to_string(), |ports| {
                    ports
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                });
                let udp_ports = udp_ports.map_or("-".to_string(), |ports| {
                    ports
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                });
                format!("{net}\t{tcp_ports}\t{udp_ports}")
            })
            .collect()
    }

    /// The last modification time.
    async fn last_modification_time(&self) -> DateTime<Utc> {
        self.inner.last_modification_time
    }

    /// The latest time when rules are applied to the agent successfully.
    async fn update_time(&self) -> Option<DateTime<Utc>> {
        self.inner.update_time
    }

    /// The last modification time.
    async fn description(&self) -> Option<&str> {
        self.inner.description.as_deref()
    }
}

impl From<database::TrafficFilter> for TrafficFilter {
    fn from(inner: database::TrafficFilter) -> Self {
        Self { inner }
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn insert_update_list() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute(
                r#"mutation {
                    insertTrafficFilterRules(
                        agent: "c2@moon"
                        network: "172.30.1.0/24"
                        tcpPorts: [80, 8080]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTrafficFilterRules: 1}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertTrafficFilterRules(
                        agent: "c2@moon"
                        network: "192.168.0.0/16"
                        tcpPorts: [80, 8000, 8080]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTrafficFilterRules: 2}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertTrafficFilterRules(
                        agent: "c1@sun"
                        network: "0.0.0.0/0"
                        udpPorts: [53]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTrafficFilterRules: 1}"#);

        let res = schema
            .execute(
                r#"mutation {
                    updateTrafficFilterRules(
                        agent: "c1@sun"
                        network: "0.0.0.0/0"
                        udpPorts: [37, 53]
                        description: "drop NTP, DNS UDP ports"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateTrafficFilterRules: 1}"#);

        let res = schema
            .execute(
                r#"query {
                    trafficFilterList(agents: null) {
                        agent
                        rules
                    }
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{trafficFilterList: [{agent: "c1@sun",rules: ["0.0.0.0/0\t-\t37,53"]},{agent: "c2@moon",rules: ["172.30.1.0/24\t80,8080\t-","192.168.0.0/16\t80,8000,8080\t-"]}]}"#
        );
    }

    #[tokio::test]
    async fn remove_and_clear() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute(
                r#"mutation {
                    insertTrafficFilterRules(
                        agent: "c2@moon"
                        network: "172.30.1.0/24"
                        tcpPorts: [80, 8080]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTrafficFilterRules: 1}"#);

        let res: async_graphql::Response = schema
            .execute(
                r#"mutation {
                    insertTrafficFilterRules(
                        agent: "c2@moon"
                        network: "0.0.0.0/0"
                        udpPorts: [37, 53]
                        description: "drop NTP, DNS UDP ports"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTrafficFilterRules: 2}"#);

        let res: async_graphql::Response = schema
            .execute(
                r#"mutation {
                    removeTrafficFilterRules(
                        agent: "c2@moon"
                        networks: ["0.0.0.0/0"]
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeTrafficFilterRules: 1}"#);

        let res: async_graphql::Response = schema
            .execute(
                r#"mutation {
                    clearTrafficFilterRules(
                        agent: "c2@moon"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{clearTrafficFilterRules: 0}"#);
    }
}
