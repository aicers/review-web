use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    Process, ProcessListQuery,
};
use async_graphql::{Context, Object, Result};
use bincode::Options;
use oinq::RequestCode;
use roxy::Process as RoxyProcess;

#[Object]
impl ProcessListQuery {
    /// A list of process of the node.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn process_list(&self, ctx: &Context<'_>, hostname: String) -> Result<Vec<Process>> {
        let agents = ctx.data::<BoxedAgentManager>()?;
        let review_hostname = roxy::hostname();

        let process_list: Vec<Process>;

        if !review_hostname.is_empty() && review_hostname == hostname {
            process_list = roxy::process_list()
                .await
                .into_iter()
                .map(Process::from)
                .collect();
        } else {
            let apps = agents.online_apps_by_host_id().await?;
            let Some(apps) = apps.get(&hostname) else {
                return Err("unable to gather info of online agents".into());
            };
            let priority_app = apps
                .iter()
                .find(|(x, _)| x == &format!("hog@{hostname}"))
                .or_else(|| {
                    apps.iter()
                        .find(|(x, _)| x == &format!("piglet@{hostname}"))
                })
                .or_else(|| {
                    apps.iter()
                        .find(|(x, _)| x == &format!("crusher@{hostname}"))
                });

            let Some((key, _)) = priority_app else {
                return Err("unable to get process list".into());
            };

            let process_list_code: u32 = RequestCode::ProcessList.into();
            let process_list_msg = bincode::serialize(&process_list_code)?;

            let response = agents.send_and_recv(key, &process_list_msg).await?;
            if let Ok(Ok(list)) = bincode::DefaultOptions::new()
                .deserialize::<Result<Vec<RoxyProcess>, &str>>(&response)
            {
                process_list = list.into_iter().map(Process::from).collect();
            } else {
                // Since the node turns off, deserialization fails.
                return Err("unable to deserialize process list".into());
            };
        }

        Ok(process_list)
    }
}
