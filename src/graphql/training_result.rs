//! The tables of a model's current or previous training result.
//!
//! A replace of a model moves its current per-model rows to mirror tables,
//! which [`Store::previous_training_results`] reads with the same table
//! types. Each function here returns the current table, or with `previous`
//! its mirror, so a resolver and its total-count object read the same view.

use review_database::{BatchInfo, Cluster, ColumnStats, OutlierInfo, Store, Table};

/// Returns the clusters of the current or the previous training results.
pub(super) fn cluster_map(store: &Store, previous: bool) -> Table<'_, Cluster> {
    if previous {
        store.previous_training_results().cluster_map()
    } else {
        store.cluster_map()
    }
}

/// Returns the outliers of the current or the previous training results.
pub(super) fn outlier_map(store: &Store, previous: bool) -> Table<'_, OutlierInfo> {
    if previous {
        store.previous_training_results().outlier_map()
    } else {
        store.outlier_map()
    }
}

/// Returns the rounds of the current or the previous training results.
pub(super) fn batch_info_map(store: &Store, previous: bool) -> Table<'_, BatchInfo> {
    if previous {
        store.previous_training_results().batch_info_map()
    } else {
        store.batch_info_map()
    }
}

/// Returns the column statistics of the current or the previous training
/// results.
pub(super) fn column_stats_map(store: &Store, previous: bool) -> Table<'_, ColumnStats> {
    if previous {
        store.previous_training_results().column_stats_map()
    } else {
        store.column_stats_map()
    }
}
