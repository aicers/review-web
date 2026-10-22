use async_graphql::{Context, Result};
use review_database::ModelDigest;

use super::{is_member, users_customers};
use crate::graphql::refusal::model_not_found;

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
