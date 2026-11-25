//! The time-series type catalog, which a time series generation policy can be
//! made from, and the reference a policy keeps to the type it was made from.
//!
//! Every value here comes from [`database::time_series_types`], the catalog
//! review-database keeps in code; nothing is read from the store.

use async_graphql::{InputObject, Object, Result, SimpleObject, StringNumber};
use review_database::{self as database};
use review_protocol::types as protocol;

use super::{
    clustering_model_type::{TrainingOperatorValue, TrainingValue, min_window_seconds},
    event::{EndpointRole, ThreatRole},
    filter::{DetectionModel, RawEventKind},
    model::ModelMethod,
    time_series_generation::{CounterpartScope, GroupByUnit, Measure, SlotSize, WindowSize},
};

/// A time-series type: a fixed recipe for generating time series from one
/// network raw event kind and training a timeseries model on them.
pub(super) struct TimeSeriesType(&'static database::TimeSeriesType);

impl From<&'static database::TimeSeriesType> for TimeSeriesType {
    fn from(inner: &'static database::TimeSeriesType) -> Self {
        Self(inner)
    }
}

/// A time-series type: a fixed recipe for generating time series from one
/// network raw event kind and training a timeseries model on them.
///
/// The values a policy's operator sets whatever the type, its name, its
/// sensors, its generator and its `utcOffset`, are not part of a type.
#[Object]
impl TimeSeriesType {
    /// The snake-case identifier, never changed; a policy made from the type
    /// names it in `timeSeriesType`.
    async fn id(&self) -> &'static str {
        self.0.id
    }

    /// The current version, raised whenever the fixed values or the allowed
    /// detection models change.
    async fn version(&self) -> StringNumber<u32> {
        StringNumber(self.0.version)
    }

    /// The position in the catalog.
    async fn order(&self) -> StringNumber<u32> {
        StringNumber(self.0.order)
    }

    /// The kind of the raw events the policy counts.
    async fn raw_event_kind(&self) -> RawEventKind {
        self.0.raw_event_kind.into()
    }

    /// The clustering method of the model trained on the series.
    async fn method(&self) -> ModelMethod {
        self.0.method.into()
    }

    /// The value counted per slot.
    async fn measure(&self) -> Measure {
        self.0.measure.into()
    }

    /// The endpoint whose IP splits the series. Every type splits by one.
    async fn group_by(&self) -> EndpointRole {
        self.0.group_by.into()
    }

    /// The unit `groupBy` splits by.
    async fn group_by_unit(&self) -> GroupByUnit {
        self.0.group_by_unit.into()
    }

    /// The filter on whether the other endpoint is internal.
    async fn counterpart_scope(&self) -> CounterpartScope {
        self.0.counterpart_scope.into()
    }

    /// The length of one slot.
    async fn slot_size(&self) -> SlotSize {
        self.0.slot_size.into()
    }

    /// The length of one window, which is one series sample.
    async fn window_size(&self) -> WindowSize {
        self.0.window_size.into()
    }

    /// The threat role of the primary subject of the type's detections.
    async fn threat_role(&self) -> ThreatRole {
        self.0.threat_role.into()
    }

    /// The top-level training definition keys the type fixes, with their
    /// values, in catalog order; empty for a type only Hog uses, on which
    /// the Unsupervised Engine trains no model.
    async fn fixed_values(&self) -> Vec<TrainingValue> {
        self.0.fixed.iter().map(TrainingValue::from).collect()
    }

    /// The training definition values the operator sets, in catalog order.
    async fn operator_values(&self) -> Vec<TrainingOperatorValue> {
        self.0
            .operator_values
            .iter()
            .map(TrainingOperatorValue::from)
            .collect()
    }

    /// The shortest training window, from `window_start` to `window_end`, in
    /// seconds; null when the type sets no minimum.
    async fn min_window_seconds(&self) -> Result<Option<i32>> {
        min_window_seconds(self.0.id, self.0.operator_values)
    }

    /// The detection models allowed to run on the model, in detection model
    /// number order.
    async fn detection_models(&self) -> Vec<DetectionModel> {
        self.0
            .detection_models
            .iter()
            .map(|model| (*model).into())
            .collect()
    }

    /// What the type counts and what its limits are, in English.
    async fn description_en(&self) -> &'static str {
        self.0.description_en
    }

    /// What the type counts and what its limits are, in Korean.
    async fn description_ko(&self) -> &'static str {
        self.0.description_ko
    }
}

/// The catalog time-series type a time series generation policy was made
/// from.
#[derive(Clone, Debug, Eq, PartialEq, SimpleObject)]
pub(super) struct TimeSeriesTypeRef {
    /// The id of the type.
    id: String,
    /// The version of the type the policy was made from.
    version: StringNumber<u32>,
}

impl From<&protocol::TimeSeriesTypeRef> for TimeSeriesTypeRef {
    fn from(input: &protocol::TimeSeriesTypeRef) -> Self {
        Self {
            id: input.id.clone(),
            version: StringNumber(input.version),
        }
    }
}

/// A catalog time-series type to make a time series generation policy from.
#[derive(InputObject)]
pub(super) struct TimeSeriesTypeRefInput {
    /// The id of the type.
    pub(super) id: String,
    /// The version of the type, which must be the catalog's.
    pub(super) version: StringNumber<u32>,
}

#[cfg(test)]
mod tests;
