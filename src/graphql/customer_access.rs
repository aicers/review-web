//! Customer-scoping utilities for GraphQL authorization.

mod hostname;
mod node;
mod scope;

pub(crate) use hostname::check_hostname_access;
pub(crate) use node::{can_access_node, load_accessible_node};
pub(crate) use scope::{check_customer_membership, is_member, users_customers};
