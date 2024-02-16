use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    NodeControlMutation,
};
use async_graphql::{Context, Object, Result};
use bincode::Options;
use oinq::RequestCode;

#[Object]
impl NodeControlMutation {
    /// Reboots the node with the given hostname as an argument.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node_reboot(&self, ctx: &Context<'_>, hostname: String) -> Result<String> {
        let agents = ctx.data::<BoxedAgentManager>()?;
        let review_hostname = roxy::hostname();
        if !review_hostname.is_empty() && review_hostname == hostname {
            Err("cannot reboot. review reboot is not allowed".into())
        } else {
            // TODO: Refactor this code to use `AgentManager::reboot` after
            // `review` implements it. See #144.
            let apps = agents.online_apps_by_host_id().await?;
            let Some(apps) = apps.get(&hostname) else {
                return Err("unable to gather info of online agents".into());
            };
            let Some((key, _)) = apps.first() else {
                return Err("unable to access first of online agents".into());
            };

            let code: u32 = RequestCode::Reboot.into();
            let msg = bincode::serialize(&code)?;
            let response = agents.send_and_recv(key, &msg).await?;
            let Ok(response) =
                bincode::DefaultOptions::new().deserialize::<Result<(), &str>>(&response)
            else {
                // Since the node turns off, deserialization fails.
                return Ok(hostname);
            };
            response.map_or_else(
                |e| Err(format!("unable to reboot the system: {e}").into()),
                |()| Ok(hostname),
            )
        }
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
    .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn node_shutdown(&self, ctx: &Context<'_>, hostname: String) -> Result<String> {
        let agents = ctx.data::<BoxedAgentManager>()?;
        let review_hostname = roxy::hostname();

        if !review_hostname.is_empty() && review_hostname == hostname {
            Err("cannot shutdown. review shutdown is not allowed".into())
        } else {
            let apps = agents.online_apps_by_host_id().await?;
            let Some(apps) = apps.get(&hostname) else {
                return Err("unable to gather info of online agents".into());
            };
            let Some((key, _)) = apps.first() else {
                return Err("unable to access first of online agents".into());
            };

            let code: u32 = RequestCode::Shutdown.into();
            let msg = bincode::serialize(&code)?;
            let response = agents.send_and_recv(key, &msg).await?;
            let Ok(response) =
                bincode::DefaultOptions::new().deserialize::<Result<(), &str>>(&response)
            else {
                return Ok(hostname);
            };
            response.map_or_else(
                |e| Err(format!("unable to shutdown the system: {e}").into()),
                |()| Ok(hostname),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::{AgentManager, BoxedAgentManager, TestSchema};
    use std::collections::HashMap;
    use tokio::sync::mpsc::{self, Sender};

    struct MockAgentManager {
        pub online_apps_by_host_id: HashMap<String, Vec<(String, String)>>,
        pub send_result_checker: Sender<String>,
    }

    impl MockAgentManager {
        pub async fn insert_result(&self, result_key: &str) {
            self.send_result_checker
                .send(result_key.to_string())
                .await
                .expect("send result failed");
        }
    }

    #[async_trait::async_trait]
    impl AgentManager for MockAgentManager {
        async fn broadcast_internal_networks(
            &self,
            _networks: &[u8],
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(vec!["hog@hostA".to_string()])
        }

        async fn broadcast_allow_networks(
            &self,
            _networks: &[u8],
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(vec![])
        }

        async fn broadcast_block_networks(
            &self,
            _networks: &[u8],
        ) -> Result<Vec<String>, anyhow::Error> {
            Ok(vec![])
        }

        async fn online_apps_by_host_id(
            &self,
        ) -> Result<HashMap<String, Vec<(String, String)>>, anyhow::Error> {
            Ok(self.online_apps_by_host_id.clone())
        }

        async fn send_and_recv(&self, key: &str, _msg: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
            self.insert_result(key).await;
            Ok(vec![])
        }
    }

    fn insert_apps(host: &str, apps: &[&str], map: &mut HashMap<String, Vec<(String, String)>>) {
        let entries = apps
            .iter()
            .map(|&app| (format!("{}@{}", app, host), app.to_string()))
            .collect();
        map.insert(host.to_string(), entries);
    }

    #[tokio::test]
    async fn test_node_shutdown() {
        let mut online_apps_by_host_id = HashMap::new();
        insert_apps("localhost", &["hog"], &mut online_apps_by_host_id);

        let (send_result_checker, _recv_result_checker) = mpsc::channel(10);

        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {
            online_apps_by_host_id,
            send_result_checker,
        });

        let schema = TestSchema::new_with(agent_manager).await;

        // node_shutdown
        let res = schema
            .execute(
                r#"mutation {
                nodeShutdown(hostname:"localhost")
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{nodeShutdown: "localhost"}"#);
    }
}
