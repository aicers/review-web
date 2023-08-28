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
            roxy::reboot().map_or_else(|e| Err(e.to_string().into()), |_| Ok(hostname))
        } else {
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
                |_| Ok(hostname),
            )
        }
    }
}
