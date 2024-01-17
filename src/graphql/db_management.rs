use super::{always_true, earliest_key, latest_key, Role, RoleGuard, DEFAULT_CONNECTION_SIZE};
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    Context, Object, Result, SimpleObject,
};
use chrono::{DateTime, Utc};
use data_encoding::BASE64;
use review_database::{
    backup::{self, BackupConfig},
    Store,
};
use std::{
    cmp::{self, Ordering},
    sync::Arc,
};
use tokio::sync::RwLock;

#[derive(Clone, SimpleObject)]
pub struct BackupInfo {
    pub file_name: String,
    pub file_size: u64,
    pub creation_time: DateTime<Utc>,
}

impl From<review_database::backup::ArchiveBackupInfo> for BackupInfo {
    fn from(backup: review_database::backup::ArchiveBackupInfo) -> Self {
        Self {
            file_name: backup.file_name,
            file_size: backup.file_size,
            creation_time: backup.creation_time,
        }
    }
}

#[derive(Default)]
pub(super) struct DbManagementQuery;

#[derive(Default)]
pub(super) struct DbManagementMutation;

#[Object]
impl DbManagementQuery {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
    .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn list_archive_backups(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, BackupInfo, BackupTotalCount, EmptyFields>> {
        let backup_cfg = ctx.data::<Arc<RwLock<BackupConfig>>>()?;
        let mut backup_list: Vec<BackupInfo> = backup::list_archived_files(backup_cfg)
            .await?
            .into_iter()
            .map(std::convert::Into::into)
            .collect();
        backup_list.sort_unstable_by(|a, b| a.file_name.cmp(&b.file_name));

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                backup_load(backup_list, after, before, first, last, BackupTotalCount)
            },
        )
        .await
    }
}

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

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
    .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn backup_to_archive_file(&self, ctx: &Context<'_>) -> Result<String> {
        let store = ctx.data::<Arc<RwLock<Store>>>()?;
        let backup_cfg = ctx.data::<Arc<RwLock<BackupConfig>>>()?;
        Ok(backup::create_archive_backup(store, backup_cfg).await?)
    }
}

struct BackupTotalCount;

#[Object]
impl BackupTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let backup_cfg = ctx.data::<Arc<RwLock<BackupConfig>>>()?;
        Ok(backup::count(backup_cfg).await)
    }
}

fn backup_load(
    backup_list: Vec<BackupInfo>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
    total_count: BackupTotalCount,
) -> Result<Connection<String, BackupInfo, BackupTotalCount, EmptyFields>> {
    let (nodes, has_previous, has_next) =
        load_nodes_with_filter(backup_list, after, before, first, last)?;
    let mut connection = Connection::with_additional_fields(has_previous, has_next, total_count);
    connection
        .edges
        .extend(nodes.into_iter().map(|(k, ev)| Edge::new(k, ev)));
    Ok(connection)
}

#[allow(clippy::type_complexity)] // since this is called within `backup_load` only
fn load_nodes_with_filter(
    mut backup_list: Vec<BackupInfo>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<(Vec<(String, BackupInfo)>, bool, bool)> {
    if let Some(last) = last {
        backup_list.reverse();
        let iter = if let Some(before) = before {
            let end = latest_key(&before)?;
            backup_list
                .into_iter()
                .filter(|x| x.file_name.as_bytes().cmp(&end) == Ordering::Less)
                .collect::<Vec<BackupInfo>>()
        } else {
            backup_list
        };

        let (nodes, has_more) = if let Some(after) = after {
            let to = earliest_key(&after)?;
            iter_to_nodes_with_filter(iter, &to, cmp::Ordering::is_ge, last)
        } else {
            iter_to_nodes_with_filter(iter, &[], always_true, last)
        };
        Ok((nodes, has_more, false))
    } else {
        let first = first.unwrap_or(DEFAULT_CONNECTION_SIZE);
        let iter = if let Some(after) = after {
            let start = earliest_key(&after)?;
            backup_list
                .into_iter()
                .filter(|x| x.file_name.as_bytes().cmp(&start) == Ordering::Greater)
                .collect::<Vec<BackupInfo>>()
        } else {
            backup_list
        };

        let (nodes, has_more) = if let Some(before) = before {
            let to = latest_key(&before)?;
            iter_to_nodes_with_filter(iter, &to, cmp::Ordering::is_le, first)
        } else {
            iter_to_nodes_with_filter(iter, &[], always_true, first)
        };
        Ok((nodes, false, has_more))
    }
}

fn iter_to_nodes_with_filter(
    iter: Vec<BackupInfo>,
    to: &[u8],
    cond: fn(cmp::Ordering) -> bool,
    len: usize,
) -> (Vec<(String, BackupInfo)>, bool) {
    let mut nodes = Vec::new();
    let mut exceeded = false;
    for backup_info in iter {
        if !(cond)(backup_info.file_name.as_bytes().cmp(to)) {
            break;
        }

        let cursor = BASE64.encode(backup_info.file_name.as_bytes());
        let node = backup_info;

        nodes.push((cursor, node));
        exceeded = nodes.len() > len;
        if exceeded {
            break;
        }
    }
    if exceeded {
        nodes.pop();
    }
    (nodes, exceeded)
}
