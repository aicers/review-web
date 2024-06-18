use async_graphql::{Context, Object, Result};

use super::{
    super::{BoxedAgentManager, Role, RoleGuard},
    Process, ProcessListQuery,
};

#[Object]
impl ProcessListQuery {
    /// A list of process of the node.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn process_list(&self, ctx: &Context<'_>, hostname: String) -> Result<Vec<Process>> {
        let agents = ctx.data::<BoxedAgentManager>()?;
        let review_hostname = roxy::hostname();

        let processes = if !review_hostname.is_empty() && review_hostname == hostname {
            roxy::process_list().await
        } else {
            agents.get_process_list(&hostname).await?
        };
        Ok(processes.into_iter().map(Process::from).collect())
    }
}
