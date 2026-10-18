use async_graphql::Enum;
use review_database::{self as database};

/// Traffic flow direction.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "database::event::FlowKind")]
pub(super) enum FlowKind {
    Inbound,
    Outbound,
    Internal,
}

/// Learning method.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "database::event::LearningMethod")]
pub(super) enum LearningMethod {
    Unsupervised,
    SemiSupervised,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(remote = "database::event::TrafficDirection")]
pub(super) enum TrafficDirection {
    From,
    To,
}
