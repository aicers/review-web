//! Full-precision filter reports stored outside model bytes and statuses.

use async_graphql::{SimpleObject, StringNumber};
use review_protocol::types;

/// The endpoint sources and ordered daily exclusions of a trained run.
#[derive(SimpleObject)]
pub(super) struct TrainingFilterReport {
    /// The number of endpoint sources resolved for this training run.
    endpoint_sources: StringNumber<u32>,
    /// Daily exclusions in the report's stored order.
    days: Vec<DayFilterCounts>,
}

impl From<types::TrainingFilterReport> for TrainingFilterReport {
    fn from(report: types::TrainingFilterReport) -> Self {
        Self {
            endpoint_sources: StringNumber(report.endpoint_sources),
            days: report
                .days
                .into_iter()
                .map(|day| DayFilterCounts {
                    start: StringNumber(day.start),
                    not_extended: StringNumber(day.counts.not_extended),
                    other_os: StringNumber(day.counts.other_os),
                })
                .collect(),
        }
    }
}

/// Exclusions for one training day, with its start in Unix nanoseconds.
#[derive(SimpleObject)]
struct DayFilterCounts {
    /// The start of the day in Unix nanoseconds.
    start: StringNumber<i64>,
    /// Essential, missing-header and other records whose mode is not extended.
    not_extended: StringNumber<u64>,
    /// Records excluded for an OS mismatch.
    other_os: StringNumber<u64>,
}

/// Exclusions from the detector's matching current applied round.
#[derive(SimpleObject)]
pub(super) struct RoundFilterReport {
    /// When this round finished, in Unix nanoseconds.
    finished_at: StringNumber<i64>,
    /// The number of endpoint sources served in this round.
    served_sources: StringNumber<u32>,
    /// Essential, missing-header and other records whose mode is not extended.
    not_extended: StringNumber<u64>,
    /// Records excluded for an OS mismatch.
    other_os: StringNumber<u64>,
}

impl From<types::RoundFilterReport> for RoundFilterReport {
    fn from(report: types::RoundFilterReport) -> Self {
        Self {
            finished_at: StringNumber(report.finished_at),
            served_sources: StringNumber(report.served_sources),
            not_extended: StringNumber(report.counts.not_extended),
            other_os: StringNumber(report.counts.other_os),
        }
    }
}
