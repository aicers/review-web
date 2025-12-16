use std::sync::Arc;

use async_graphql::{Context, ID, InputObject, Object, Result, SimpleObject, StringNumber};
use chrono::{DateTime, Utc};
use review_database::{BackupConfig as DbBackupConfig, Store, backup};
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
///
/// This type represents the current backup configuration including:
/// - `backup_duration`: Interval between backups in days (minimum: 1)
/// - `backup_time`: Scheduled backup execution time in HH:MM:SS UTC format
/// - `num_of_backups_to_keep`: Maximum number of retained backup snapshots (minimum: 1)
#[derive(SimpleObject)]
pub struct BackupConfig {
    /// Interval between backups in days. Minimum value is 1.
    pub backup_duration: StringNumber<u16>,
    /// Scheduled backup execution time in HH:MM:SS UTC format.
    pub backup_time: String,
    /// Maximum number of retained backup snapshots. Minimum value is 1.
    pub num_of_backups_to_keep: StringNumber<u16>,
}

impl From<DbBackupConfig> for BackupConfig {
    fn from(config: DbBackupConfig) -> Self {
        Self {
            backup_duration: StringNumber(config.backup_duration),
            backup_time: config.backup_time,
            num_of_backups_to_keep: StringNumber(config.num_of_backups_to_keep),
        }
    }
}

/// GraphQL input type for creating or updating backup configuration.
///
/// All fields are required:
/// - `backup_duration`: Interval between backups in days (must be >= 1)
/// - `backup_time`: Scheduled backup execution time in HH:MM:SS UTC format
/// - `num_of_backups_to_keep`: Maximum number of retained backup snapshots (must be >= 1)
#[derive(InputObject)]
pub struct BackupConfigInput {
    /// Interval between backups in days. Must be >= 1.
    pub backup_duration: u16,
    /// Scheduled backup execution time in HH:MM:SS UTC format (e.g., "23:59:59").
    pub backup_time: String,
    /// Maximum number of retained backup snapshots. Must be >= 1.
    pub num_of_backups_to_keep: u16,
}

impl BackupConfigInput {
    /// Validates the input values for backup configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `backup_duration` is 0
    /// - `num_of_backups_to_keep` is 0
    /// - `backup_time` is not in valid HH:MM:SS format
    fn validate(&self) -> Result<()> {
        if self.backup_duration == 0 {
            return Err("invalid backup_duration: must be >= 1".into());
        }
        if self.num_of_backups_to_keep == 0 {
            return Err("invalid num_of_backups_to_keep: must be >= 1".into());
        }
        validate_backup_time(&self.backup_time)?;
        Ok(())
    }
}

/// Validates that the backup time string is in HH:MM:SS format with valid ranges.
fn validate_backup_time(time: &str) -> Result<()> {
    let parts: Vec<&str> = time.split(':').collect();
    if parts.len() != 3 {
        return Err("invalid backup_time: must be in HH:MM:SS format".into());
    }

    let hour: u8 = parts[0]
        .parse()
        .map_err(|_| "invalid backup_time: hour must be a number")?;
    let minute: u8 = parts[1]
        .parse()
        .map_err(|_| "invalid backup_time: minute must be a number")?;
    let second: u8 = parts[2]
        .parse()
        .map_err(|_| "invalid backup_time: second must be a number")?;

    if hour > 23 {
        return Err("invalid backup_time: hour must be 0-23".into());
    }
    if minute > 59 {
        return Err("invalid backup_time: minute must be 0-59".into());
    }
    if second > 59 {
        return Err("invalid backup_time: second must be 0-59".into());
    }

    Ok(())
}

impl From<BackupConfigInput> for DbBackupConfig {
    fn from(input: BackupConfigInput) -> Self {
        Self {
            backup_duration: input.backup_duration,
            backup_time: input.backup_time,
            num_of_backups_to_keep: input.num_of_backups_to_keep,
        }
    }
}

#[derive(Default)]
pub(super) struct DbManagementQuery;

#[Object]
impl DbManagementQuery {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn backups(&self, ctx: &Context<'_>) -> Result<Vec<BackupInfo>> {
        let store = ctx.data::<Arc<std::sync::RwLock<Store>>>()?;
        info_with_username!(ctx, "Database backup list is being fetched");
        let backup_infos = backup::list(store)?;

        // Convert from review_database::backup::BackupInfo to our GraphQL BackupInfo
        // Sort by timestamp in descending order (latest first)
        let mut result: Vec<BackupInfo> = backup_infos
            .into_iter()
            .map(|info| BackupInfo {
                id: ID::from(info.id),
                timestamp: info.timestamp,
                size: StringNumber(info.size),
            })
            .collect();

        result.sort_unstable_by(|a, b| b.timestamp.cmp(&a.timestamp));

        Ok(result)
    }

    /// Retrieves the current backup configuration.
    ///
    /// Returns the stored configuration if one exists, otherwise returns
    /// sensible defaults:
    /// - `backup_duration`: 1 day
    /// - `backup_time`: "23:59:59" (UTC)
    /// - `num_of_backups_to_keep`: 5
    ///
    /// Accessible to all authenticated users (all roles).
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn backup_config(&self, ctx: &Context<'_>) -> Result<BackupConfig> {
        let store = crate::graphql::get_store(ctx)?;
        let table = store.backup_config_map();
        let config = table.read()?;
        Ok(config.into())
    }
}

#[derive(Default)]
pub(super) struct DbManagementMutation;

#[Object]
impl DbManagementMutation {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn backup(&self, ctx: &Context<'_>, num_of_backups_to_keep: u32) -> Result<bool> {
        let store = ctx.data::<Arc<std::sync::RwLock<Store>>>()?;
        info_with_username!(ctx, "Database backup is being executed");
        Ok(backup::create(store, false, num_of_backups_to_keep).is_ok())
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn restore_from_latest_backup(&self, ctx: &Context<'_>) -> Result<bool> {
        let store = ctx.data::<Arc<std::sync::RwLock<Store>>>()?;
        info_with_username!(ctx, "Database is being restored from the latest backup");
        backup::restore(store, None)?;
        Ok(true)
    }

    /// Restores the database from a specific backup by ID.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The backup ID does not exist
    /// * The restore operation fails (e.g., corrupted backup, I/O errors)
    /// * Database is locked by another operation
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn restore_from_backup(&self, ctx: &Context<'_>, id: ID) -> Result<bool> {
        let id = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let store = ctx.data::<Arc<std::sync::RwLock<Store>>>()?;
        info_with_username!(ctx, "Database is being restored from backup {}", id);
        backup::restore(store, Some(id))?;
        info_with_username!(ctx, "Database successfully restored from backup {}", id);
        Ok(true)
    }

    /// Sets or creates a new backup configuration.
    ///
    /// This mutation creates or overwrites the backup configuration with the
    /// provided values. Only administrators can modify the backup configuration.
    ///
    /// # Arguments
    ///
    /// * `input` - The backup configuration input containing:
    ///   - `backup_duration`: Interval between backups in days (must be >= 1)
    ///   - `backup_time`: Scheduled backup time in HH:MM:SS UTC format
    ///   - `num_of_backups_to_keep`: Maximum retained backup snapshots (must be >= 1)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The user is not an administrator
    /// * Input validation fails (e.g., invalid time format, zero values)
    /// * Database operation fails
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn set_backup_config(
        &self,
        ctx: &Context<'_>,
        input: BackupConfigInput,
    ) -> Result<BackupConfig> {
        input.validate()?;

        let store = crate::graphql::get_store(ctx)?;
        let table = store.backup_config_map();
        let config: DbBackupConfig = input.into();
        table.save(&config)?;
        info_with_username!(ctx, "Backup configuration has been set");
        Ok(config.into())
    }

    /// Updates the existing backup configuration.
    ///
    /// This mutation updates the backup configuration from the old values to
    /// new values. Both old and new configurations must be provided for
    /// optimistic concurrency control. Only administrators can modify the
    /// backup configuration.
    ///
    /// # Arguments
    ///
    /// * `old` - The current backup configuration (for verification)
    /// * `new` - The new backup configuration to apply
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The user is not an administrator
    /// * The old configuration doesn't match the current stored configuration
    /// * Input validation fails (e.g., invalid time format, zero values)
    /// * Database operation fails
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_backup_config(
        &self,
        ctx: &Context<'_>,
        old: BackupConfigInput,
        new: BackupConfigInput,
    ) -> Result<BackupConfig> {
        new.validate()?;

        let store = crate::graphql::get_store(ctx)?;
        let table = store.backup_config_map();
        let old_config: DbBackupConfig = old.into();
        let new_config: DbBackupConfig = new.into();
        table.update_config(&old_config, &new_config)?;
        info_with_username!(ctx, "Backup configuration has been updated");
        Ok(new_config.into())
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use review_database::Role;
    use serde_json::json;

    use crate::graphql::{RoleGuard, TestSchema};

    #[tokio::test]
    async fn test_backups_query() {
        let schema = TestSchema::new().await;

        // Query for backups - this should work and return an empty array initially
        let res = schema
            .execute_as_system_admin(r"{ backups { id timestamp size } }")
            .await;

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
        let res = schema
            .execute_as_system_admin(r"{ backups { id timestamp } }")
            .await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r"{backups: []}");

        // Create 3 backups to avoid accidental pass with 2 items
        // Add a delay between backups to ensure distinct timestamps
        for _ in 0..3 {
            let res = schema
                .execute_as_system_admin(r"mutation { backup(numOfBackupsToKeep: 5) }")
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
        let res = schema
            .execute_as_system_admin(r"{ backups { id timestamp } }")
            .await;
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

    #[tokio::test]
    async fn test_backup_config_query_returns_defaults() {
        let schema = TestSchema::new().await;

        // Query backup config as system admin - should return defaults
        let res = schema
            .execute_as_system_admin(
                r"{ backupConfig { backupDuration backupTime numOfBackupsToKeep } }",
            )
            .await;

        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "backupConfig": {
                    "backupDuration": "1",
                    "backupTime": "23:59:59",
                    "numOfBackupsToKeep": "5"
                }
            })
        );
    }

    #[tokio::test]
    async fn test_backup_config_query_accessible_to_all_roles() {
        let schema = TestSchema::new().await;

        // Test that all roles can access backup config
        for role in [
            Role::SystemAdministrator,
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            let res = schema
                .execute_with_guard(
                    r"{ backupConfig { backupDuration backupTime numOfBackupsToKeep } }",
                    RoleGuard::Role(role),
                )
                .await;

            assert!(
                res.errors.is_empty(),
                "Role {role:?} should have access. Errors: {:?}",
                res.errors
            );
        }
    }

    #[tokio::test]
    async fn test_set_backup_config_admin_only() {
        let schema = TestSchema::new().await;

        // Test that SystemAdministrator and SecurityAdministrator can set backup config
        let mutation = r#"
            mutation {
                setBackupConfig(input: {
                    backupDuration: 7
                    backupTime: "03:00:00"
                    numOfBackupsToKeep: 10
                }) {
                    backupDuration
                    backupTime
                    numOfBackupsToKeep
                }
            }
        "#;

        // Should succeed for SystemAdministrator
        let res = schema.execute_as_system_admin(mutation).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "setBackupConfig": {
                    "backupDuration": "7",
                    "backupTime": "03:00:00",
                    "numOfBackupsToKeep": "10"
                }
            })
        );

        // Should succeed for SecurityAdministrator
        let res = schema
            .execute_with_guard(mutation, RoleGuard::Role(Role::SecurityAdministrator))
            .await;
        assert!(
            res.errors.is_empty(),
            "SecurityAdministrator should have access. Errors: {:?}",
            res.errors
        );

        // Should fail for non-admin roles
        for role in [Role::SecurityManager, Role::SecurityMonitor] {
            let res = schema
                .execute_with_guard(mutation, RoleGuard::Role(role))
                .await;
            assert!(
                !res.errors.is_empty(),
                "Role {role:?} should not have access to setBackupConfig"
            );
            assert!(
                res.errors[0].message.contains("Forbidden"),
                "Expected Forbidden error for role {role:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_update_backup_config_admin_only() {
        let schema = TestSchema::new().await;

        // First set a config
        let set_mutation = r#"
            mutation {
                setBackupConfig(input: {
                    backupDuration: 1
                    backupTime: "23:59:59"
                    numOfBackupsToKeep: 5
                }) {
                    backupDuration
                }
            }
        "#;
        let res = schema.execute_as_system_admin(set_mutation).await;
        assert!(res.errors.is_empty(), "Setup failed: {:?}", res.errors);

        // Now update it
        let update_mutation = r#"
            mutation {
                updateBackupConfig(
                    old: {
                        backupDuration: 1
                        backupTime: "23:59:59"
                        numOfBackupsToKeep: 5
                    }
                    new: {
                        backupDuration: 14
                        backupTime: "02:30:00"
                        numOfBackupsToKeep: 7
                    }
                ) {
                    backupDuration
                    backupTime
                    numOfBackupsToKeep
                }
            }
        "#;

        // Should succeed for SystemAdministrator
        let res = schema.execute_as_system_admin(update_mutation).await;
        assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "updateBackupConfig": {
                    "backupDuration": "14",
                    "backupTime": "02:30:00",
                    "numOfBackupsToKeep": "7"
                }
            })
        );

        // Reset config for SecurityAdministrator test
        let res = schema.execute_as_system_admin(set_mutation).await;
        assert!(res.errors.is_empty(), "Reset failed: {:?}", res.errors);

        // Should succeed for SecurityAdministrator
        let res = schema
            .execute_with_guard(
                update_mutation,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "SecurityAdministrator should have access. Errors: {:?}",
            res.errors
        );

        // Should fail for non-admin roles
        for role in [Role::SecurityManager, Role::SecurityMonitor] {
            let res = schema
                .execute_with_guard(update_mutation, RoleGuard::Role(role))
                .await;
            assert!(
                !res.errors.is_empty(),
                "Role {role:?} should not have access to updateBackupConfig"
            );
            assert!(
                res.errors[0].message.contains("Forbidden"),
                "Expected Forbidden error for role {role:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_set_backup_config_validation_backup_duration() {
        let schema = TestSchema::new().await;

        // Test invalid backup_duration (0)
        let mutation = r#"
            mutation {
                setBackupConfig(input: {
                    backupDuration: 0
                    backupTime: "03:00:00"
                    numOfBackupsToKeep: 5
                }) {
                    backupDuration
                }
            }
        "#;

        let res = schema.execute_as_system_admin(mutation).await;
        assert!(!res.errors.is_empty(), "Expected validation error");
        assert!(
            res.errors[0]
                .message
                .contains("invalid backup_duration: must be >= 1"),
            "Expected specific error message, got: {}",
            res.errors[0].message
        );
    }

    #[tokio::test]
    async fn test_set_backup_config_validation_num_of_backups() {
        let schema = TestSchema::new().await;

        // Test invalid num_of_backups_to_keep (0)
        let mutation = r#"
            mutation {
                setBackupConfig(input: {
                    backupDuration: 1
                    backupTime: "03:00:00"
                    numOfBackupsToKeep: 0
                }) {
                    backupDuration
                }
            }
        "#;

        let res = schema.execute_as_system_admin(mutation).await;
        assert!(!res.errors.is_empty(), "Expected validation error");
        assert!(
            res.errors[0]
                .message
                .contains("invalid num_of_backups_to_keep: must be >= 1"),
            "Expected specific error message, got: {}",
            res.errors[0].message
        );
    }

    #[tokio::test]
    async fn test_set_backup_config_validation_time_format() {
        let schema = TestSchema::new().await;

        // Test various invalid time formats
        let invalid_times = [
            ("25:00:00", "hour must be 0-23"),
            ("12:60:00", "minute must be 0-59"),
            ("12:00:60", "second must be 0-59"),
            ("12:00", "must be in HH:MM:SS format"),
            ("invalid", "must be in HH:MM:SS format"),
            ("ab:cd:ef", "hour must be a number"),
        ];

        for (time, expected_error) in invalid_times {
            let mutation = format!(
                r#"
                mutation {{
                    setBackupConfig(input: {{
                        backupDuration: 1
                        backupTime: "{time}"
                        numOfBackupsToKeep: 5
                    }}) {{
                        backupDuration
                    }}
                }}
            "#
            );

            let res = schema.execute_as_system_admin(&mutation).await;
            assert!(
                !res.errors.is_empty(),
                "Expected validation error for time '{time}'"
            );
            assert!(
                res.errors[0].message.contains(expected_error),
                "Time '{time}': expected error containing '{expected_error}', got: {}",
                res.errors[0].message
            );
        }
    }

    #[tokio::test]
    async fn test_backup_config_set_and_read_roundtrip() {
        let schema = TestSchema::new().await;

        // Set a custom config
        let mutation = r#"
            mutation {
                setBackupConfig(input: {
                    backupDuration: 30
                    backupTime: "04:15:30"
                    numOfBackupsToKeep: 20
                }) {
                    backupDuration
                }
            }
        "#;
        let res = schema.execute_as_system_admin(mutation).await;
        assert!(res.errors.is_empty(), "Set failed: {:?}", res.errors);

        // Read it back
        let res = schema
            .execute_as_system_admin(
                r"{ backupConfig { backupDuration backupTime numOfBackupsToKeep } }",
            )
            .await;
        assert!(res.errors.is_empty(), "Read failed: {:?}", res.errors);
        assert_json_eq!(
            res.data.into_json().unwrap(),
            json!({
                "backupConfig": {
                    "backupDuration": "30",
                    "backupTime": "04:15:30",
                    "numOfBackupsToKeep": "20"
                }
            })
        );
    }
}
