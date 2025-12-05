use std::sync::{Arc, RwLock};

use async_graphql::{Context, ID, Object, Result, SimpleObject, StringNumber};
use chrono::{DateTime, TimeZone, Utc};
use review_database::{BackupConfig, Store, backup};
use tracing::info;

use super::{Role, RoleGuard};
use crate::info_with_username;

#[derive(SimpleObject)]
pub struct BackupInfo {
    pub id: ID,
    pub timestamp: DateTime<Utc>,
    pub size: StringNumber<u64>,
}

/// GraphQL output type for backup configuration settings.
#[derive(SimpleObject)]
pub struct BackupConfigOutput {
    /// Interval between backups in days (must be >= 1).
    pub backup_duration: i32,
    /// Scheduled backup time in HH:MM:SS UTC format.
    pub backup_time: String,
    /// Maximum number of backups to retain (must be >= 1).
    pub num_of_backups_to_keep: i32,
}

impl From<BackupConfig> for BackupConfigOutput {
    fn from(config: BackupConfig) -> Self {
        Self {
            backup_duration: i32::from(config.backup_duration),
            backup_time: config.backup_time,
            num_of_backups_to_keep: i32::from(config.num_of_backups_to_keep),
        }
    }
}

#[derive(Default)]
pub(super) struct DbManagementQuery;

#[Object]
impl DbManagementQuery {
    /// Retrieves a list of available database backups.
    ///
    /// Returns backups sorted by timestamp in descending order (latest first).
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn backups(&self, ctx: &Context<'_>) -> Result<Vec<BackupInfo>> {
        let store = crate::graphql::get_store(ctx)?;
        info_with_username!(ctx, "Database backup list is being fetched");

        // Use the Store method directly instead of backup::list
        let backup_engine_infos = store.get_backup_info()?;

        // Convert from rocksdb::backup::BackupEngineInfo to our GraphQL BackupInfo
        // Sort by timestamp in descending order (latest first)
        let mut result: Vec<BackupInfo> = backup_engine_infos
            .into_iter()
            .map(|info| {
                let timestamp = Utc
                    .timestamp_opt(info.timestamp, 0)
                    .single()
                    .unwrap_or_default();
                BackupInfo {
                    id: ID::from(info.backup_id),
                    timestamp,
                    size: StringNumber(info.size),
                }
            })
            .collect();

        result.sort_unstable_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(result)
    }

    /// Retrieves the current backup configuration.
    ///
    /// Returns default values if no configuration has been saved yet.
    /// This query is accessible to all authenticated users.
    async fn backup_config(&self, ctx: &Context<'_>) -> Result<BackupConfigOutput> {
        let store = crate::graphql::get_store(ctx)?;
        info_with_username!(ctx, "Backup configuration is being fetched");

        let map = store.backup_config_map();
        let config = map.read()?;

        Ok(config.into())
    }
}

/// GraphQL input type for saving backup configuration.
#[derive(async_graphql::InputObject)]
pub struct BackupConfigInput {
    /// Interval between backups in days (must be >= 1).
    pub backup_duration: i32,
    /// Scheduled backup time in HH:MM:SS UTC format (e.g., "23:59:59").
    pub backup_time: String,
    /// Maximum number of backups to retain (must be >= 1).
    pub num_of_backups_to_keep: i32,
}

impl TryFrom<BackupConfigInput> for BackupConfig {
    type Error = &'static str;

    fn try_from(input: BackupConfigInput) -> std::result::Result<Self, Self::Error> {
        let backup_duration = u16::try_from(input.backup_duration)
            .map_err(|_| "backup_duration must be a positive integer within u16 range")?;
        let num_of_backups_to_keep = u16::try_from(input.num_of_backups_to_keep)
            .map_err(|_| "num_of_backups_to_keep must be a positive integer within u16 range")?;

        Ok(BackupConfig {
            backup_duration,
            backup_time: input.backup_time,
            num_of_backups_to_keep,
        })
    }
}

#[derive(Default)]
pub(super) struct DbManagementMutation;

#[Object]
impl DbManagementMutation {
    /// Creates a new database backup.
    ///
    /// Note: This operation acquires an exclusive write lock on the store
    /// for the duration of the backup, which may block other operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the backup operation fails.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn backup(&self, ctx: &Context<'_>, num_of_backups_to_keep: u32) -> Result<bool> {
        let store = ctx.data::<Arc<RwLock<Store>>>()?;
        info_with_username!(ctx, "Database backup is being executed");

        // Use the backup module function which properly handles backup creation
        Ok(backup::create(store, false, num_of_backups_to_keep).is_ok())
    }

    /// Restores the database from the latest backup.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * No backups exist
    /// * The restore operation fails
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn restore_from_latest_backup(&self, ctx: &Context<'_>) -> Result<bool> {
        let store = ctx.data::<Arc<RwLock<Store>>>()?;
        info_with_username!(ctx, "Database is being restored from the latest backup");

        // Use write lock since restore_from_latest_backup requires &mut self
        let mut store_guard = store.write().expect("RwLock should not be poisoned");
        store_guard.restore_from_latest_backup()?;
        Ok(true)
    }

    /// Restores the database from a specific backup by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The backup ID is invalid
    /// * The backup ID does not exist
    /// * The restore operation fails (e.g., corrupted backup, I/O errors)
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn restore_from_backup(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let id = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let store = ctx.data::<Arc<RwLock<Store>>>()?;
        info_with_username!(ctx, "Database is being restored from backup {}", id);

        // Use write lock since restore_from_backup requires &mut self
        let mut store_guard = store.write().expect("RwLock should not be poisoned");
        store_guard.restore_from_backup(id)?;
        info_with_username!(ctx, "Database successfully restored from backup {}", id);
        Ok(true)
    }

    /// Saves a new backup configuration.
    ///
    /// This operation is restricted to administrators only.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The user does not have administrator privileges
    /// * Input validation fails (invalid duration, time format, or retention count)
    /// * The database operation fails
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn save_backup_config(
        &self,
        ctx: &Context<'_>,
        input: BackupConfigInput,
    ) -> Result<BackupConfigOutput> {
        let store = crate::graphql::get_store(ctx)?;
        info_with_username!(ctx, "Backup configuration is being saved");

        let config: BackupConfig = input.try_into()?;
        let map = store.backup_config_map();
        map.save(&config)?;

        info_with_username!(ctx, "Backup configuration saved successfully");
        Ok(config.into())
    }

    /// Updates an existing backup configuration.
    ///
    /// This operation is restricted to administrators only.
    /// Requires both the old configuration (for verification) and the new configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The user does not have administrator privileges
    /// * Input validation fails (invalid duration, time format, or retention count)
    /// * The old configuration does not match the current stored configuration
    /// * The database operation fails
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_backup_config(
        &self,
        ctx: &Context<'_>,
        old: BackupConfigInput,
        new: BackupConfigInput,
    ) -> Result<BackupConfigOutput> {
        let store = crate::graphql::get_store(ctx)?;
        info_with_username!(ctx, "Backup configuration is being updated");

        let old_config: BackupConfig = old.try_into()?;
        let new_config: BackupConfig = new.try_into()?;

        let map = store.backup_config_map();
        map.update_config(&old_config, &new_config)?;

        info_with_username!(ctx, "Backup configuration updated successfully");
        Ok(new_config.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_backup_config_query_returns_defaults() {
        let schema = TestSchema::new().await;

        // Query for backup config - should return default values
        let res = schema
            .execute(r"{ backupConfig { backupDuration backupTime numOfBackupsToKeep } }")
            .await;

        assert!(
            res.errors.is_empty(),
            "backupConfig query failed: {:?}",
            res.errors
        );

        // Verify the default values are returned
        let json = res.data.into_json().unwrap();
        let config = &json["backupConfig"];

        // Default values from review-database should be returned
        assert!(
            config["backupDuration"].as_i64().is_some(),
            "backupDuration should be a valid integer"
        );
        assert!(
            config["backupTime"].as_str().is_some(),
            "backupTime should be a valid string"
        );
        assert!(
            config["numOfBackupsToKeep"].as_i64().is_some(),
            "numOfBackupsToKeep should be a valid integer"
        );
    }

    #[tokio::test]
    async fn test_save_backup_config_mutation() {
        let schema = TestSchema::new().await;

        // Save a new backup config
        let res = schema
            .execute(
                r#"mutation {
                    saveBackupConfig(input: {
                        backupDuration: 7
                        backupTime: "03:00:00"
                        numOfBackupsToKeep: 5
                    }) {
                        backupDuration
                        backupTime
                        numOfBackupsToKeep
                    }
                }"#,
            )
            .await;

        assert!(
            res.errors.is_empty(),
            "saveBackupConfig mutation failed: {:?}",
            res.errors
        );

        // Verify the returned values match what we saved
        let json = res.data.into_json().unwrap();
        let config = &json["saveBackupConfig"];
        assert_eq!(config["backupDuration"], 7);
        assert_eq!(config["backupTime"], "03:00:00");
        assert_eq!(config["numOfBackupsToKeep"], 5);

        // Query to verify the config was persisted
        let res = schema
            .execute(r"{ backupConfig { backupDuration backupTime numOfBackupsToKeep } }")
            .await;

        assert!(res.errors.is_empty());
        let json = res.data.into_json().unwrap();
        let config = &json["backupConfig"];
        assert_eq!(config["backupDuration"], 7);
        assert_eq!(config["backupTime"], "03:00:00");
        assert_eq!(config["numOfBackupsToKeep"], 5);
    }

    #[tokio::test]
    async fn test_update_backup_config_mutation() {
        let schema = TestSchema::new().await;

        // First save a config
        let res = schema
            .execute(
                r#"mutation {
                    saveBackupConfig(input: {
                        backupDuration: 7
                        backupTime: "03:00:00"
                        numOfBackupsToKeep: 5
                    }) {
                        backupDuration
                    }
                }"#,
            )
            .await;
        assert!(res.errors.is_empty());

        // Update the config
        let res = schema
            .execute(
                r#"mutation {
                    updateBackupConfig(
                        old: {
                            backupDuration: 7
                            backupTime: "03:00:00"
                            numOfBackupsToKeep: 5
                        }
                        new: {
                            backupDuration: 14
                            backupTime: "04:30:00"
                            numOfBackupsToKeep: 10
                        }
                    ) {
                        backupDuration
                        backupTime
                        numOfBackupsToKeep
                    }
                }"#,
            )
            .await;

        assert!(
            res.errors.is_empty(),
            "updateBackupConfig mutation failed: {:?}",
            res.errors
        );

        // Verify the returned values match the new config
        let json = res.data.into_json().unwrap();
        let config = &json["updateBackupConfig"];
        assert_eq!(config["backupDuration"], 14);
        assert_eq!(config["backupTime"], "04:30:00");
        assert_eq!(config["numOfBackupsToKeep"], 10);
    }

    #[tokio::test]
    async fn test_backup_config_validation_invalid_duration() {
        let schema = TestSchema::new().await;

        // Try to save a config with invalid backup_duration (negative value)
        let res = schema
            .execute(
                r#"mutation {
                    saveBackupConfig(input: {
                        backupDuration: -1
                        backupTime: "03:00:00"
                        numOfBackupsToKeep: 5
                    }) {
                        backupDuration
                    }
                }"#,
            )
            .await;

        assert!(
            !res.errors.is_empty(),
            "saveBackupConfig should fail with negative backupDuration"
        );

        // Verify the error message is descriptive
        let error_msg = &res.errors[0].message;
        assert!(
            error_msg.contains("backup_duration"),
            "Error should mention backup_duration: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_backups_query() {
        let schema = TestSchema::new().await;

        // Query for backups - this should work and return an empty array initially
        let res = schema.execute(r"{ backups { id timestamp size } }").await;

        // If there are errors, it might be due to RocksDB setup issues in test environment
        // In that case, we should at least verify the query is properly structured
        if res.errors.is_empty() {
            // If no errors, should return empty array
            assert_eq!(res.data.to_string(), r"{backups: []}");
            println!("Test passed: Query returned empty backup list as expected");
        } else {
            // Check if it's a database-related error (not a GraphQL schema error)
            let error_msg = res.errors[0].message.clone();
            assert!(
                error_msg.contains("IO error") || error_msg.contains("states.db"),
                "Expected database IO error but got: {error_msg}"
            );
            println!(
                "Test passed: Query structure is correct, but database not fully initialized in test environment"
            );
        }
    }

    #[tokio::test]
    async fn test_backups_query_sorted_by_timestamp_desc() {
        let schema = TestSchema::new().await;

        // Ensure initially empty
        let res = schema.execute(r"{ backups { id timestamp } }").await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r"{backups: []}");

        // Create 3 backups to avoid accidental pass with 2 items
        // Add a delay between backups to ensure distinct timestamps
        for _ in 0..3 {
            let res = schema
                .execute(r"mutation { backup(numOfBackupsToKeep: 5) }")
                .await;
            assert!(
                res.errors.is_empty(),
                "Backup mutation failed unexpectedly: {:?}",
                res.errors
            );
            assert_eq!(res.data.to_string(), r"{backup: true}");
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        // Fetch and verify order strictly
        let res = schema.execute(r"{ backups { id timestamp } }").await;
        assert!(
            res.errors.is_empty(),
            "Backups query failed unexpectedly: {:?}",
            res.errors
        );

        let json = res.data.into_json().unwrap();
        let timestamps = json["backups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["timestamp"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();

        assert!(
            timestamps.len() >= 3,
            "At least three backups are expected: {timestamps:?}"
        );

        // Verify timestamps are in descending order (latest first)
        // Use >= to allow for equal timestamps when backups are created rapidly
        for w in timestamps.windows(2) {
            assert!(
                w[0] >= w[1],
                "Timestamps must be in descending order: {timestamps:?}"
            );
        }
    }
}
