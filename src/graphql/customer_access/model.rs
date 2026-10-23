use async_graphql::{Context, Result};
use review_database::{Iterable, ModelDigest, Store, event::Direction};

use super::{is_member, users_customers};
use crate::graphql::refusal::{RefusalCode, model_not_found, refusal};

/// Checks whether the requester can access the given model.
///
/// Returns `true` if the requester is admin (`users_customers` is `None`) or
/// the model's customer is in the requester's scope.
#[must_use]
pub(crate) fn can_access_model(users_customers: Option<&[u32]>, model: &ModelDigest) -> bool {
    is_member(users_customers, model.customer_id)
}

/// Loads the record of the given model and checks whether the requester can
/// access it.
///
/// Scope is decided from the record's `customer_id`, never from a customer id
/// the request carries. `field` names the argument `model_id` came from, for
/// the `NOT_FOUND` refusal.
///
/// # Errors
///
/// Returns an error if the GraphQL context is missing required authorization
/// data or the store cannot be read.
///
/// Returns `NOT_FOUND`, with `field` and `value`, if no model has the id.
///
/// Returns `Forbidden` if the requester is not allowed to access the model.
pub(crate) fn load_accessible_model(
    ctx: &Context<'_>,
    field: &str,
    model_id: u32,
) -> Result<ModelDigest> {
    let users_customers = users_customers(ctx)?;
    let store = crate::graphql::get_store(ctx)?;
    let Some(model) = store.model_map().get_by_id(model_id)? else {
        return Err(model_not_found(field, model_id));
    };
    if can_access_model(users_customers.as_deref(), &model) {
        Ok(model)
    } else {
        Err("Forbidden".into())
    }
}

/// Loads the record of the model named `name` and checks whether the
/// requester can access it.
///
/// It is [`load_accessible_model`] keyed by the model's name. Scope is decided
/// from the record's `customer_id`. `field` names the argument `name` came
/// from, for the `NOT_FOUND` refusal.
///
/// # Errors
///
/// Returns an error if the GraphQL context is missing required authorization
/// data or the store cannot be read.
///
/// Returns `NOT_FOUND`, with `field` and `value`, if no model has the name.
///
/// Returns `Forbidden` if the requester is not allowed to access the model.
pub(crate) fn load_accessible_model_by_name(
    ctx: &Context<'_>,
    field: &str,
    name: &str,
) -> Result<ModelDigest> {
    let users_customers = users_customers(ctx)?;
    let store = crate::graphql::get_store(ctx)?;
    let Some(model) = model_by_name(&store, name)? else {
        return Err(refusal(
            RefusalCode::NotFound,
            format!("model {name:?} not found"),
            field,
            name,
        ));
    };
    if can_access_model(users_customers.as_deref(), &model) {
        Ok(model)
    } else {
        Err("Forbidden".into())
    }
}

/// Returns the record of the model named `name`, or `None` if no model has
/// the name.
///
/// `model_map().load_model_by_name` returns the same untyped error for an
/// absent name as for a failed read, so the record is read here from the
/// table, which is keyed by name, to tell the two apart.
///
/// # Errors
///
/// Returns an error if the store cannot be read.
pub(crate) fn model_by_name(store: &Store, name: &str) -> Result<Option<ModelDigest>> {
    let map = store.model_map();
    let Some(entry) = map.iter(Direction::Forward, Some(name.as_bytes())).next() else {
        return Ok(None);
    };
    let model = entry.map_err(|e| format!("cannot read model {name:?}: {e}"))?;
    Ok((model.name == name).then_some(model))
}
