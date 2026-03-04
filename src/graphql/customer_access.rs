//! Customer-scoping utilities for GraphQL authorization.

mod scope;

pub(crate) use scope::{is_member, users_customers};
