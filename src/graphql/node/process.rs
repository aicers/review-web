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
            // TODO: Refactor this code to use `AgentManager::process_list`
            // after the `AgentManager` trait is implemented. See #144.
            let apps = agents.online_apps_by_host_id().await?;
            let Some(apps) = apps.get(&hostname) else {
                return Err("unable to gather info of online agents".into());
            };

            // The priority of applications (`Hog`, followed by `Crusher` and
            // then `Piglet`) is determined based on their roles and
            // capabilities in the system.
            //
            // 1. `Hog` has the highest priority because it can act as a dummy
            //    agent to monitor servers where our software isn't installed.
            //    This is essential for comprehensive system monitoring.
            // 2. `Crusher` and `Piglet` are preferred for process list
            //    collection because they maintain a continuous connection to
            //    REview.
            // 3. `REconverge` is not suited for process list collection due to
            //    its intermittent connection.
            // 4. The order of Hog, Crusher, and Piglet also considers the load
            //    each program can handle.
            let priority_app = apps
                .iter()
                .find(|(_, app_name)| app_name == "hog")
                .or_else(|| apps.iter().find(|(_, app_name)| app_name == "piglet"))
                .or_else(|| apps.iter().find(|(_, app_name)| app_name == "crusher"));

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
