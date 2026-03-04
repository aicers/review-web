//! Customer-scoping utilities for GraphQL authorization.

mod hostname;
mod node;
mod scope;

pub(crate) use hostname::check_hostname_access;
pub(crate) use node::{can_access_node, check_node_access};
pub(crate) use scope::{is_member, users_customers};
