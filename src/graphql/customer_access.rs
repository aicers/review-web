//! Customer-scoping utilities for GraphQL authorization.

mod event_sensor;
mod hostname;
mod model;
mod node;
mod scope;

pub(crate) use event_sensor::{event_sensor_customer_id_map, event_sensor_names};
pub(crate) use hostname::{
    check_hostname_access, derive_customer_id_from_hostname, hostname_customer_id_map,
    sensor_from_key,
};
pub(crate) use model::{can_access_model, load_accessible_model};
pub(crate) use node::{can_access_node, load_accessible_node};
pub(crate) use scope::{check_customer_membership, is_member, users_customers};
