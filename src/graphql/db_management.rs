use std::sync::Arc;

use async_graphql::{Context, Object, Result};
use review_database::{Store, backup};
use tokio::sync::RwLock;
use tracing::info;

use super::{Role, RoleGuard};
use crate::info_with_username;

#[derive(Default)]
pub(super) struct DbManagementMutation;

#[Object]
impl DbManagementMutation {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn backup(&self, ctx: &Context<'_>, num_of_backups_to_keep: u32) -> Result<bool> {
        let store = ctx.data::<Arc<RwLock<Store>>>()?;
        info_with_username!(ctx, "Database backup is being executed");
        Ok(backup::create(store, false, num_of_backups_to_keep)
            .await
            .is_ok())
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn restore_from_latest_backup(&self, ctx: &Context<'_>) -> Result<bool> {
        let store = ctx.data::<Arc<RwLock<Store>>>()?;
        info_with_username!(ctx, "Database is being restored from the latest backup");
        backup::restore(store, None).await?;
        Ok(true)
    }
}
