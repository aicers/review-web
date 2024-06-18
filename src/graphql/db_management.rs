use std::sync::Arc;

use async_graphql::{Context, Object, Result};
use review_database::{backup, Store};
use tokio::sync::RwLock;

use super::{Role, RoleGuard};

#[derive(Default)]
pub(super) struct DbManagementMutation;

#[Object]
impl DbManagementMutation {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn backup(&self, ctx: &Context<'_>, num_of_backups_to_keep: u32) -> Result<bool> {
        let store = ctx.data::<Arc<RwLock<Store>>>()?;
        Ok(backup::create(store, false, num_of_backups_to_keep)
            .await
            .is_ok())
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn restore_from_latest_backup(&self, ctx: &Context<'_>) -> Result<bool> {
        let store = ctx.data::<Arc<RwLock<Store>>>()?;
        backup::restore(store, None).await?;
        Ok(true)
    }
}
