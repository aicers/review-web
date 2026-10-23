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
    /// An address override by someone other than a System Administrator.
    AddressOverrideForbidden,
    /// Assign of a model that has an instance, or to an instance of another
    /// customer.
    AssignRefused,
    /// A bound of RFC 0006 §5.2.
    BoundViolated,
    /// A cross-customer clone by someone other than a System Administrator.
    CrossCustomerForbidden,
    /// A node customer or hostname change, or a new node, refused by RFC 0006
    /// §5.11.
    CustomerChangeRefused,
    /// A `server_name` that is not an installed Data Store.
    DataStoreNotInstalled,
    /// Run once of a detector id absent from the applied document.
    DetectorNotFound,
    /// A repeated source, a repeated detector id, or a model named by two
    /// detectors.
    DuplicateEntry,
    /// The instance received the request and refused it.
    EngineRefused,
    /// An event kind the method does not take.
    EventKindNotAllowed,
    /// A change of method or event kind after the model exists.
    FieldFixed,
    /// A field the method forbids or requires.
    FieldNotAllowed,
    /// An indicator update or removal while a document or definition names
    /// it.
    IndicatorInUse,
    /// An indicator update that would move it to another model.
    IndicatorModelChange,
    /// `suspicious_tokens` naming no indicator, or an indicator of another
    /// customer's model.
    IndicatorNotAllowed,
    /// A target that is not an installed Unsupervised Engine instance on a
    /// node with an applied profile and hostname, or a model or definition
    /// that has no instance.
    InstanceNotEligible,
    /// A run or run once on a stopped instance.
    InstanceStopped,
    /// A relay request that did not reach the instance, or a start or stop
    /// that did not complete.
    InstanceUnreachable,
    /// TOML that does not parse, a required field missing, or a value of the
    /// wrong type.
    InvalidDocument,
    /// A model delete refused by the guard, or a definition removal refused
    /// because it has a model.
    ModelInUse,
    /// A document naming a model that does not exist or belongs to another
    /// instance.
    ModelNotOfInstance,
    /// A name the model-name rule refuses.
    NameInvalid,
    /// A definition or clone name already used by a model or a definition.
    NameTaken,
    /// No such model, definition, run or indicator.
    NotFound,
    /// Another run active on the instance or the definition, a definition
    /// edit during a run, or a clone's source retrained while the clone was
    /// prepared.
    RunInProgress,
    /// A cancel of a run that has finished.
    RunNotActive,
    /// A source that is not a source name of the instance's customer, or any
    /// detector on a node without an applied profile.
    SourceNotAllowed,
    /// Method `timeseries`, not supported in phase 1.
    TimeseriesUnsupported,
    /// A key outside the schema, at any level.
    UnknownField,
}

impl RefusalCode {
    /// Returns the code as it appears in `extensions.code`.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AddressOverrideForbidden => "ADDRESS_OVERRIDE_FORBIDDEN",
            Self::AssignRefused => "ASSIGN_REFUSED",
            Self::BoundViolated => "BOUND_VIOLATED",
            Self::CrossCustomerForbidden => "CROSS_CUSTOMER_FORBIDDEN",
            Self::CustomerChangeRefused => "CUSTOMER_CHANGE_REFUSED",
            Self::DataStoreNotInstalled => "DATA_STORE_NOT_INSTALLED",
            Self::DetectorNotFound => "DETECTOR_NOT_FOUND",
            Self::DuplicateEntry => "DUPLICATE_ENTRY",
            Self::EngineRefused => "ENGINE_REFUSED",
            Self::EventKindNotAllowed => "EVENT_KIND_NOT_ALLOWED",
            Self::FieldFixed => "FIELD_FIXED",
            Self::FieldNotAllowed => "FIELD_NOT_ALLOWED",
            Self::IndicatorInUse => "INDICATOR_IN_USE",
            Self::IndicatorModelChange => "INDICATOR_MODEL_CHANGE",
            Self::IndicatorNotAllowed => "INDICATOR_NOT_ALLOWED",
            Self::InstanceNotEligible => "INSTANCE_NOT_ELIGIBLE",
            Self::InstanceStopped => "INSTANCE_STOPPED",
            Self::InstanceUnreachable => "INSTANCE_UNREACHABLE",
            Self::InvalidDocument => "INVALID_DOCUMENT",
            Self::ModelInUse => "MODEL_IN_USE",
            Self::ModelNotOfInstance => "MODEL_NOT_OF_INSTANCE",
            Self::NameInvalid => "NAME_INVALID",
            Self::NameTaken => "NAME_TAKEN",
            Self::NotFound => "NOT_FOUND",
            Self::RunInProgress => "RUN_IN_PROGRESS",
            Self::RunNotActive => "RUN_NOT_ACTIVE",
            Self::SourceNotAllowed => "SOURCE_NOT_ALLOWED",
            Self::TimeseriesUnsupported => "TIMESERIES_UNSUPPORTED",
            Self::UnknownField => "UNKNOWN_FIELD",
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
