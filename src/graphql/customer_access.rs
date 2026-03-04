//! Customer-scoping utilities for GraphQL authorization.

mod hostname;
mod node;
mod scope;

pub(crate) use hostname::{
    check_hostname_access, derive_customer_id_from_hostname, hostname_customer_id_map,
    sensor_from_key,
};
pub(crate) use node::{can_access_node, check_node_access};
pub(crate) use scope::{is_member, users_customers};
