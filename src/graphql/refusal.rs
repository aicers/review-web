//! The refusal codes of the Unsupervised Engine model and training surface.
//!
//! A refusal is an `async_graphql::Error` whose `extensions.code` names one
//! [`RefusalCode`], with the extensions `field` (the offending key, as a
//! dotted path) and `value` (the offending value, as text), and further
//! extensions where the refusal names a detector or a training definition.

use async_graphql::ErrorExtensions;

/// The closed list of refusal codes the model and training resolvers return.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefusalCode {
    /// An indicator update or removal while a document or definition names
    /// it.
    IndicatorInUse,
    /// An indicator update that would move it to another model.
    IndicatorModelChange,
    /// No such model, definition, run or indicator.
    NotFound,
}

impl RefusalCode {
    /// Returns the code as it appears in `extensions.code`.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::IndicatorInUse => "INDICATOR_IN_USE",
            Self::IndicatorModelChange => "INDICATOR_MODEL_CHANGE",
            Self::NotFound => "NOT_FOUND",
        }
    }
}

/// Returns a refusal with `code`, `message`, and the extensions `field` and
/// `value`.
///
/// Further extensions are added with [`ErrorExtensions::extend_with`], which
/// keeps these.
#[must_use]
pub(crate) fn refusal(
    code: RefusalCode,
    message: impl Into<String>,
    field: &str,
    value: impl Into<String>,
) -> async_graphql::Error {
    let value = value.into();
    async_graphql::Error::new(message).extend_with(|_, extensions| {
        extensions.set("code", code.as_str());
        extensions.set("field", field);
        extensions.set("value", value);
    })
}

/// Returns the `NOT_FOUND` refusal of a model id that names no model.
#[must_use]
pub(crate) fn model_not_found(field: &str, model_id: u32) -> async_graphql::Error {
    refusal(
        RefusalCode::NotFound,
        format!("model {model_id} not found"),
        field,
        model_id.to_string(),
    )
}
