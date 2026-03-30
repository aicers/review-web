//! Customer-scoping utilities for GraphQL authorization.

mod hostname;
mod scope;

pub(crate) use hostname::{
    check_hostname_access, derive_customer_id_from_hostname, hostname_customer_id_map,
    sensor_from_key,
};
pub(crate) use scope::{has_all_membership, is_member, users_customers};
