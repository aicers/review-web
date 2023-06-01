use super::{always_true, Role, RoleGuard, DEFAULT_CONNECTION_SIZE};
use anyhow::Context as ct;
use async_graphql::{
    connection::{query, Connection, Edge, EmptyFields},
    Context, InputObject, Object, Result, SimpleObject,
};
use chrono::{DateTime, NaiveTime, Utc};
use data_encoding::BASE64;
use review_database::{backup, backup::BackupConfig, Store};
use std::{
    cmp,
    fs::{read_to_string, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Arc,
    thread,
    time::Duration,
};
use tokio::sync::{mpsc::Sender, RwLock};
use toml_edit::{value, Document};

#[derive(SimpleObject, Debug)]
struct BackupSetting {
    backup_time: String,
    backup_duration: u16,
    num_of_backups_to_keep: u32,
}

#[derive(InputObject)]
struct UserSetting {
    backup_time: Option<String>,
    backup_duration: Option<u16>,
    num_of_backups_to_keep: Option<u32>,
}

#[derive(Clone, SimpleObject)]
pub struct BackupInfo {
    pub id: u32,
    pub timestamp: DateTime<Utc>,
    pub size: u64,
}

impl From<review_database::backup::BackupInfo> for BackupInfo {
    fn from(backup: review_database::backup::BackupInfo) -> Self {
        Self {
            id: backup.id,
            timestamp: backup.timestamp,
            size: backup.size,
        }
    }
}

#[derive(Default)]
pub(super) struct DbManagementQuery;

#[derive(Default)]
pub(super) struct DbManagementMutation;

#[Object]
impl DbManagementMutation {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn backup(&self, ctx: &Context<'_>) -> Result<bool> {
        let store = ctx.data::<Arc<Store>>()?;
        let backup_cfg = ctx.data::<Arc<RwLock<BackupConfig>>>()?;
        Ok(backup::create(store, &backup_cfg.read().await.clone()).is_ok())
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn restore_from_backup(&self, ctx: &Context<'_>, id: u32) -> Result<bool> {
        let store: Arc<Store> = ctx.data::<Arc<Store>>()?.clone();
        let backup_cfg = ctx
            .data::<Arc<RwLock<BackupConfig>>>()?
            .read()
            .await
            .clone();
        thread::spawn(move || backup::restore(&store, &backup_cfg, id));
        Ok(true)
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
    .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn set_backup_config(&self, ctx: &Context<'_>, config: UserSetting) -> Result<bool> {
        let cfg_path = ctx.data::<PathBuf>()?;
        let toml = read_to_string(cfg_path).context("toml not found")?;
        let mut doc = toml.parse::<Document>()?;

        if config.backup_time.is_some() || config.backup_duration.is_some() {
            let mut time = doc
                .get("backup_time")
                .context("\"backup_time\" not found")?
                .as_str()
                .context("Failed to parse as String")?
                .to_string();
            let mut duration: u16 = doc
                .get("backup_duration")
                .context("\"backup_duration\" not found")?
                .as_integer()
                .context("Failed to parse as integer")?
                .try_into()?;
            if let Some(backup_time) = config.backup_time {
                doc["backup_time"] = value(backup_time.clone());
                time = backup_time;
            }
            if let Some(backup_duration) = config.backup_duration {
                doc["backup_duration"] = value(i64::from(backup_duration));
                duration = backup_duration;
            }

            let schedule_sender = ctx.data::<Sender<(Duration, Duration)>>()?;
            let backup_schedule = {
                let time = NaiveTime::parse_from_str(&time, "%H:%M:%S")?;
                let duration = Duration::from_secs(u64::from(duration) * 24 * 60 * 60);
                let init = backup_schedule_init(time, duration)?;
                (init, duration)
            };
            schedule_sender.send(backup_schedule).await?;
        }

        if let Some(num_of_backups_to_keep) = config.num_of_backups_to_keep {
            doc["num_of_backups_to_keep"] = value(i64::from(num_of_backups_to_keep));
            let store: Arc<Store> = ctx.data::<Arc<Store>>()?.clone();
            let mut backup_cfg = ctx.data::<Arc<RwLock<BackupConfig>>>()?.write().await;
            backup_cfg.num_of_backups = num_of_backups_to_keep;
            let backup_cfg = backup_cfg.clone();
            thread::spawn(move || backup::purge_old_backups(&store, &backup_cfg));
        }

        let output = doc.to_string();
        let mut toml_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(cfg_path)?;
        writeln!(toml_file, "{output}")?;
        Ok(true)
    }
}

#[Object]
impl DbManagementQuery {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn backup_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, BackupInfo, BackupTotalCount, EmptyFields>> {
        let store = ctx.data::<Arc<Store>>()?;
        let backup_cfg = ctx.data::<Arc<RwLock<BackupConfig>>>()?;
        let backup_list: Vec<BackupInfo> =
            backup::list(store, &backup_cfg.read().await.backup_path)?
                .into_iter()
                .map(std::convert::Into::into)
                .collect();
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

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
    .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn backup_config(&self, ctx: &Context<'_>) -> Result<BackupSetting> {
        let cfg_path = ctx.data::<PathBuf>()?;
        let toml = read_to_string(cfg_path).context("toml not found")?;
        let doc = toml.parse::<Document>()?;

        let backup_time = doc
            .get("backup_time")
            .context("\"backup_time\" not found")?
            .as_str()
            .context("Failed to parse as String")?
            .to_string();
        let backup_duration: u16 = doc
            .get("backup_duration")
            .context("\"backup_duration\" not found")?
            .as_integer()
            .context("Failed to parse as integer")?
            .try_into()?;
        let num_of_backups_to_keep: u32 = doc
            .get("num_of_backups_to_keep")
            .context("\"num_of_backups_to_keep\" not found")?
            .as_integer()
            .context("Failed to parse as integer")?
            .try_into()?;
        Ok(BackupSetting {
            backup_time,
            backup_duration,
            num_of_backups_to_keep,
        })
    }
}

struct BackupTotalCount;

#[Object]
impl BackupTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = ctx.data::<Arc<Store>>()?;
        Ok(backup::count(store)?)
    }
}

fn backup_schedule_init(time: NaiveTime, duration: Duration) -> Result<Duration> {
    let now = Utc::now();
    let schedule = now.date_naive().and_time(time) - now.date_naive().and_time(now.time());

    if schedule.num_seconds() > 0 {
        Ok(schedule.to_std()?)
    } else {
        Ok((schedule + chrono::Duration::from_std(duration)?).to_std()?)
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
            let end = backup_key(&before)?;
            backup_list
                .into_iter()
                .filter(|x| x.id < end)
                .collect::<Vec<BackupInfo>>()
        } else {
            backup_list
        };

        let (nodes, has_more) = if let Some(after) = after {
            let to = backup_key(&after)?;
            iter_to_nodes_with_filter(iter, to, cmp::Ordering::is_ge, last)
        } else {
            iter_to_nodes_with_filter(iter, u32::MIN, always_true, last)
        };
        Ok((nodes, has_more, false))
    } else {
        let first = first.unwrap_or(DEFAULT_CONNECTION_SIZE);
        let iter = if let Some(after) = after {
            let start = backup_key(&after)?;
            backup_list
                .into_iter()
                .filter(|x| x.id > start)
                .collect::<Vec<BackupInfo>>()
        } else {
            backup_list
        };

        let (nodes, has_more) = if let Some(before) = before {
            let to = backup_key(&before)?;
            iter_to_nodes_with_filter(iter, to, cmp::Ordering::is_le, first)
        } else {
            iter_to_nodes_with_filter(iter, u32::MAX, always_true, first)
        };
        Ok((nodes, false, has_more))
    }
}

fn iter_to_nodes_with_filter(
    iter: Vec<BackupInfo>,
    to: u32,
    cond: fn(cmp::Ordering) -> bool,
    len: usize,
) -> (Vec<(String, BackupInfo)>, bool) {
    let mut nodes = Vec::new();
    let mut exceeded = false;
    for backup_info in iter {
        if !(cond)(backup_info.id.cmp(&to)) {
            break;
        }

        let cursor = BASE64.encode(&backup_info.id.to_le_bytes());
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

fn backup_key(cursor: &str) -> Result<u32> {
    let decord_cursor = BASE64
        .decode(cursor.as_bytes())
        .map_err(|_| "invalid cursor `after`")?;
    let decord_cursor: [u8; 4] = decord_cursor.as_slice().try_into()?;
    let key = u32::from_le_bytes(decord_cursor);
    Ok(key)
}
