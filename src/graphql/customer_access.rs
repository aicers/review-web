//! Customer-scoping utilities for GraphQL authorization.

mod scope;

pub(crate) use scope::{has_any_membership, users_customers};
