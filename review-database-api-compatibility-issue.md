# review-database API Compatibility Issue Report

## Background

Attempting to update the `review-database` dependency from `tag = "0.42.1"` to
`rev = "1eca4f6b"` in `review-web` results in compilation errors due to a
breaking API change in the backup module.

## Problem Description

The `review-database` crate at commit `1eca4f6b` has changed the backup module
API to use `std::sync::RwLock<Store>` instead of `tokio::sync::RwLock<Store>`.

### Current API in review-database (commit 1eca4f6b)

The backup functions now have the following signatures:

```rust
pub fn list(store: &Arc<RwLock<Store>>) -> Result<Vec<BackupInfo>>
pub fn create(store: &Arc<RwLock<Store>>, flush: bool, backups_to_keep: u32) -> Result<()>
pub fn restore(store: &Arc<RwLock<Store>>, backup_id: Option<u32>) -> Result<()>
```

Where `RwLock` is `std::sync::RwLock` (synchronous).

### review-web Architecture

The `review-web` application stores the `Store` in `Arc<tokio::sync::RwLock<Store>>`
throughout the codebase. This is used in:

- `src/lib.rs` - Server initialization and request handling
- `src/graphql.rs` - GraphQL schema context
- `src/graphql/db_management.rs` - Backup/restore GraphQL mutations
- `src/archive.rs` - Archive functionality
- Multiple other GraphQL modules

## Compilation Errors

When updating to commit `1eca4f6b`, the following errors occur:

```
error[E0308]: mismatched types
  --> src/graphql/db_management.rs:29:41
   |
29 |         let backup_infos = backup::list(store).await?;
   |                            ------------ ^^^^^ expected `std::sync::RwLock<Store>`,
   |                                               found `tokio::sync::RwLock<Store>`
```

The same type mismatch occurs for `backup::create` and `backup::restore` calls.

## Reason for Incompatibility

- `tokio::sync::RwLock` and `std::sync::RwLock` are distinct types
- They cannot be converted between each other without restructuring
- The application would need to either:
  1. Change the global store wrapper from `tokio::sync::RwLock` to
     `std::sync::RwLock` (significant refactoring across the entire codebase)
  2. Or, require `review-database` to provide a compatible API

## Requested Change

The `review-database` crate should provide backup API functions that are
compatible with `Arc<tokio::sync::RwLock<Store>>`, matching the previous API
behavior.

### Option A: Restore async API with tokio::sync::RwLock

Restore the previous async function signatures:

```rust
pub async fn list(store: &Arc<tokio::sync::RwLock<Store>>) -> Result<Vec<BackupInfo>>
pub async fn create(store: &Arc<tokio::sync::RwLock<Store>>, ...) -> Result<()>
pub async fn restore(store: &Arc<tokio::sync::RwLock<Store>>, ...) -> Result<()>
```

### Option B: Provide both sync and async variants

Keep the sync API with `std::sync::RwLock` and add async variants:

```rust
// Sync versions (current)
pub fn list(store: &Arc<std::sync::RwLock<Store>>) -> Result<Vec<BackupInfo>>

// Async versions (new)
pub async fn list_async(store: &Arc<tokio::sync::RwLock<Store>>) -> Result<Vec<BackupInfo>>
```

### Option C: Accept Store directly

Modify functions to accept `&Store` directly, allowing the caller to handle
lock acquisition:

```rust
pub fn list(store: &Store) -> Result<Vec<BackupInfo>>
pub fn create(store: &Store, flush: bool, backups_to_keep: u32) -> Result<()>
pub fn restore(store: &mut Store, backup_id: Option<u32>) -> Result<()>
```

## Impact

This change blocks the ability to update `review-web` to use `review-database`
commit `1eca4f6b` as specified in issue #727.

## Related

- GitHub Issue: https://github.com/aicers/review-web/issues/727
