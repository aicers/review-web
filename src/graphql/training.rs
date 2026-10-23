//! Training definitions, model runs, and the model lifecycle mutations of the
//! Unsupervised Engine (RFC 0006 §5.4–§5.6, §5.11).
//!
//! A training definition says what data trains a model; a run trains or
//! clones a model on an engine instance, relayed through the
//! [`AgentManager`](crate::backend::AgentManager). Every writer that checks or
//! creates a reference to a source, a model or an indicator holds the engine
//! configuration lock from its checks through its store write, and releases
//! it before any relay.

mod definition;

use std::{collections::HashSet, net::SocketAddr};

use async_graphql::{
    Context, Enum, ErrorExtensions, InputObject, MaybeUndefined, Object, Result, SimpleObject,
    types::ID,
};
use chrono::{DateTime, Utc};
use review_database::{
    self as database, NewTrainingDefinition, Referrer, RunId, RunKind, Store,
    TrainingDefinitionUpdate, TrainingError,
};
use tracing::warn;

pub(crate) use self::definition::{TrainingDocument, sources_of};
use super::{
    Role, RoleGuard, SharedAgentManager,
    customer_access::{
        is_member, is_system_admin, load_accessible_model_by_name, model_by_name, users_customers,
    },
    engine_config::lock_engine_config,
    gen_agent_lookup_key,
    model::{ModelDigest, ModelInstance, ModelMethod},
    refusal::{RefusalCode, refusal},
    unsupervised::{DataStore, data_store_addrs},
};
use crate::backend::EngineRefused;

/// The reason a run fails when its request or cancel did not reach the
/// instance and the agent manager left it active.
const INSTANCE_UNREACHABLE: &str = "instance unreachable";

#[derive(Default)]
pub(super) struct TrainingQuery;

#[Object]
impl TrainingQuery {
    /// The training definitions of the caller's customers, in name order.
    ///
    /// A System Administrator sees every definition.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn training_definitions(&self, ctx: &Context<'_>) -> Result<Vec<TrainingDefinition>> {
        let users_customers = users_customers(ctx)?;
        let store = super::get_store(ctx)?;
        Ok(store
            .training_definitions()?
            .into_iter()
            .filter(|definition| is_member(users_customers.as_deref(), definition.customer_id))
            .map(Into::into)
            .collect())
    }

    /// The training definition `name`, or null if no definition has the
    /// name.
    ///
    /// A definition of none of the caller's customers is refused with
    /// `Forbidden`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn training_definition(
        &self,
        ctx: &Context<'_>,
        name: String,
    ) -> Result<Option<TrainingDefinition>> {
        let users_customers = users_customers(ctx)?;
        let store = super::get_store(ctx)?;
        let Some(definition) = store.training_definition(&name)? else {
            return Ok(None);
        };
        if !is_member(users_customers.as_deref(), definition.customer_id) {
            return Err("Forbidden".into());
        }
        Ok(Some(definition.into()))
    }

    /// The runs that create or replace the model `model`, and the clone runs
    /// from it, ascending by id.
    ///
    /// Scope is the customer of the training definition named `model`, or of
    /// the model record when no definition has the name. A cross-customer
    /// clone run from the model is left out for callers who are not System
    /// Administrators.
    ///
    /// Refused with `extensions.code` `NOT_FOUND` when neither a definition
    /// nor a model has the name, and with `Forbidden` for a model of none of
    /// the caller's customers.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn model_runs(&self, ctx: &Context<'_>, model: String) -> Result<Vec<ModelRun>> {
        let users_customers = users_customers(ctx)?;
        let system_admin = is_system_admin(ctx);
        let store = super::get_store(ctx)?;
        let Some(customer_id) = name_customer(&store, &model)? else {
            return Err(refusal(
                RefusalCode::NotFound,
                format!("no training definition or model is named {model:?}"),
                "model",
                model.as_str(),
            ));
        };
        if !is_member(users_customers.as_deref(), customer_id) {
            return Err("Forbidden".into());
        }
        Ok(store
            .model_runs(&model)?
            .into_iter()
            .filter_map(|run| visible_run(run, &model, system_admin))
            .collect())
    }
}

/// Returns the customer of the training definition `name`, or of the model
/// record when no definition has the name, or `None` when neither exists.
fn name_customer(store: &Store, name: &str) -> Result<Option<u32>> {
    if let Some(definition) = store.training_definition(name)? {
        return Ok(Some(definition.customer_id));
    }
    Ok(model_by_name(store, name)?.map(|model| model.customer_id))
}

#[derive(Default)]
pub(super) struct TrainingMutation;

#[Object]
impl TrainingMutation {
    /// Stores the training definition `name` on the engine instance
    /// `agentKey` of node `nodeId`, returning the name.
    ///
    /// `definition` is the TOML document of review-protocol's
    /// `TrainModelRequest::definition`. Scope is the customer of the
    /// instance's node; an instance of none of the caller's customers is
    /// refused with `Forbidden`.
    ///
    /// Refusals carry `extensions.code`: `INVALID_DOCUMENT`,
    /// `UNKNOWN_FIELD`, `FIELD_NOT_ALLOWED`, `DUPLICATE_ENTRY`,
    /// `BOUND_VIOLATED`, `TIMESERIES_UNSUPPORTED`, `EVENT_KIND_NOT_ALLOWED`,
    /// `SOURCE_NOT_ALLOWED`, `DATA_STORE_NOT_INSTALLED`,
    /// `ADDRESS_OVERRIDE_FORBIDDEN` and `INDICATOR_NOT_ALLOWED` for the
    /// definition; `NAME_TAKEN`, `NAME_INVALID` and `INSTANCE_NOT_ELIGIBLE`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_training_definition(
        &self,
        ctx: &Context<'_>,
        node_id: ID,
        agent_key: String,
        name: String,
        definition: String,
    ) -> Result<String> {
        let node_id = parse_node_id(&node_id)?;
        let document = TrainingDocument::parse_and_validate(&definition)?;
        let addrs = data_store_addrs(ctx, &document.data_store.server_name).await;

        let _lock = lock_engine_config(ctx).await?;
        let users_customers = users_customers(ctx)?;
        let system_admin = is_system_admin(ctx);
        let store = super::get_store(ctx)?;
        let target = resolve_instance(&store, users_customers.as_deref(), node_id, &agent_key)?;
        document.check_stored(
            &store,
            target.customer_id,
            &addrs,
            &HashSet::new(),
            system_admin,
        )?;
        store
            .insert_training_definition(NewTrainingDefinition {
                name: name.clone(),
                customer_id: target.customer_id,
                instance: target.instance,
                method: document.method.into(),
                event_kind: document.event_kind.clone(),
                sources: document.sources.clone(),
                indicator: document.suspicious_tokens.clone(),
                definition,
            })
            .map_err(|e| store_refusal(e, StoreWrite::InsertDefinition, Some(&document)))?;
        Ok(name)
    }

    /// Replaces the training definition `name` with `definition`, returning
    /// the name.
    ///
    /// Scope is the stored definition's customer, and the definition is
    /// validated for that customer. A definition of none of the caller's
    /// customers is refused with `Forbidden`.
    ///
    /// Refusals carry `extensions.code`: the codes of the definition, as
    /// `insertTrainingDefinition` lists them; `NOT_FOUND`, `RUN_IN_PROGRESS`
    /// while a run of the definition is active, and `FIELD_FIXED` when the
    /// method or the event kind would change after the model exists.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_training_definition(
        &self,
        ctx: &Context<'_>,
        name: String,
        definition: String,
    ) -> Result<String> {
        let document = TrainingDocument::parse_and_validate(&definition)?;
        let addrs = data_store_addrs(ctx, &document.data_store.server_name).await;

        let _lock = lock_engine_config(ctx).await?;
        let users_customers = users_customers(ctx)?;
        let system_admin = is_system_admin(ctx);
        let store = super::get_store(ctx)?;
        let stored = accessible_definition(&store, users_customers.as_deref(), &name)?;
        let kept = kept_pair(&stored.definition);
        document.check_stored(&store, stored.customer_id, &addrs, &kept, system_admin)?;
        store
            .update_training_definition(
                &name,
                TrainingDefinitionUpdate {
                    method: document.method.into(),
                    event_kind: document.event_kind.clone(),
                    sources: document.sources.clone(),
                    indicator: document.suspicious_tokens.clone(),
                    definition,
                },
            )
            .map_err(|e| store_refusal(e, StoreWrite::UpdateDefinition, Some(&document)))?;
        Ok(name)
    }

    /// Removes the training definition `name` with its runs, returning the
    /// name.
    ///
    /// Scope is the stored definition's customer. Refusals carry
    /// `extensions.code`: `NOT_FOUND`; `MODEL_IN_USE` while a model of the
    /// name exists, with `definition`; `RUN_IN_PROGRESS` while a run of the
    /// definition is active.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_training_definition(&self, ctx: &Context<'_>, name: String) -> Result<String> {
        let users_customers = users_customers(ctx)?;
        let store = super::get_store(ctx)?;
        accessible_definition(&store, users_customers.as_deref(), &name)?;
        store
            .remove_training_definition(&name)
            .map_err(|e| store_refusal(e, StoreWrite::RemoveDefinition, None))?;
        Ok(name)
    }

    /// Starts a training run of the definition `name` on its instance,
    /// returning the run id.
    ///
    /// Scope is the definition's customer. The stored definition is checked
    /// again for its customer's sources and an installed Data Store, and the
    /// definition text the run starts with is relayed to the instance.
    ///
    /// Refusals carry `extensions.code`: `NOT_FOUND`; `INVALID_DOCUMENT` if
    /// the stored definition does not parse; `SOURCE_NOT_ALLOWED` and
    /// `DATA_STORE_NOT_INSTALLED`; `INSTANCE_NOT_ELIGIBLE`,
    /// `INSTANCE_STOPPED` and `RUN_IN_PROGRESS`; and, once the run is
    /// stored, `ENGINE_REFUSED` with the engine's reason in `value` or
    /// `INSTANCE_UNREACHABLE`, either leaving the run failed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn train_model(&self, ctx: &Context<'_>, name: String) -> Result<ID> {
        let (agent_lookup_key, started) = {
            let _lock = lock_engine_config(ctx).await?;
            let users_customers = users_customers(ctx)?;
            let system_admin = is_system_admin(ctx);
            let store = super::get_store(ctx)?;
            let stored = accessible_definition(&store, users_customers.as_deref(), &name)?;
            let Some(instance) = stored.instance.as_ref() else {
                return Err(no_instance("name", &name));
            };
            let Some(hostname) = applied_hostname(&store, instance.node_id)? else {
                return Err(no_hostname(instance));
            };
            let document = TrainingDocument::parse(&stored.definition).map_err(|_| {
                refusal(
                    RefusalCode::InvalidDocument,
                    format!("the stored definition {name:?} does not parse"),
                    "name",
                    &name,
                )
            })?;
            document.check_sources(&store, stored.customer_id)?;
            document.check_data_store(
                &store,
                &[],
                &HashSet::from([document.data_store.pair()]),
                system_admin,
            )?;
            let started = store
                .start_training_run(&name)
                .map_err(|e| store_refusal(e, StoreWrite::StartTraining, None))?;
            (
                gen_agent_lookup_key(&started.run.instance.agent_key, &hostname),
                started,
            )
        };

        let run_id = started.run.id;
        let agent_manager = ctx.data::<SharedAgentManager>()?;
        if let Err(e) = agent_manager
            .train_model(&agent_lookup_key, run_id, &name, &started.definition)
            .await
        {
            fail_unless_ended(ctx, run_id);
            return Err(relay_refusal(&e, "name", &agent_lookup_key));
        }
        Ok(ID(run_id.to_string()))
    }

    /// Asks the instance performing the active run `runId` to cancel it,
    /// returning the run id.
    ///
    /// Scope is the customer of the definition the run's model names, for a
    /// clone the target's. The request goes to the instance that performs
    /// the run, for a clone the source model's.
    ///
    /// Refusals carry `extensions.code`: `NOT_FOUND`; `RUN_NOT_ACTIVE` for a
    /// finished run; `ENGINE_REFUSED` with the engine's reason in `value` or
    /// `INSTANCE_UNREACHABLE`, either leaving the run failed (a clone run is
    /// removed with its target definition).
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn cancel_model_run(&self, ctx: &Context<'_>, run_id: ID) -> Result<ID> {
        let not_found = || {
            refusal(
                RefusalCode::NotFound,
                format!("model run {} not found", run_id.as_str()),
                "runId",
                run_id.as_str(),
            )
        };
        let id = run_id.as_str().parse::<RunId>().map_err(|_| not_found())?;
        let agent_lookup_key = {
            let users_customers = users_customers(ctx)?;
            let store = super::get_store(ctx)?;
            let Some(run) = store.model_run(id)? else {
                return Err(not_found());
            };
            let Some(customer_id) = name_customer(&store, &run.model)? else {
                return Err(not_found());
            };
            if !is_member(users_customers.as_deref(), customer_id) {
                return Err("Forbidden".into());
            }
            if !run.state.is_active() {
                return Err(refusal(
                    RefusalCode::RunNotActive,
                    format!("model run {id} is {:?}, not active", run.state),
                    "runId",
                    run_id.as_str(),
                ));
            }
            let Some(hostname) = applied_hostname(&store, run.instance.node_id)? else {
                fail_run(&store, id);
                return Err(refusal(
                    RefusalCode::InstanceUnreachable,
                    format!(
                        "node {} of the instance performing model run {id} has no applied \
                         hostname",
                        run.instance.node_id
                    ),
                    "runId",
                    run_id.as_str(),
                ));
            };
            gen_agent_lookup_key(&run.instance.agent_key, &hostname)
        };

        let agent_manager = ctx.data::<SharedAgentManager>()?;
        if let Err(e) = agent_manager.cancel_run(&agent_lookup_key, id).await {
            fail_unless_ended(ctx, id);
            return Err(relay_refusal(&e, "runId", &agent_lookup_key));
        }
        Ok(run_id)
    }

    /// Clones the model `source` into the new model `targetName` on the
    /// engine instance `agentKey` of node `nodeId`, returning the run id.
    ///
    /// The target's definition is the source's trained definition, the one
    /// that produced its classifier, with `dataStore`, `sources` and
    /// `suspiciousTokens` replaced. Left out, `suspiciousTokens` keeps the
    /// trained definition's indicator for a clone within a customer and
    /// clears it for a clone to another customer; null clears it.
    ///
    /// The caller must belong to the source's customer and the target
    /// instance's, or is refused with `Forbidden`; a clone to another
    /// customer is refused with `CROSS_CUSTOMER_FORBIDDEN` to anyone but a
    /// System Administrator.
    ///
    /// Refusals carry `extensions.code`: the codes of the definition, as
    /// `insertTrainingDefinition` lists them; `NOT_FOUND`, `NAME_TAKEN`,
    /// `NAME_INVALID`, `INSTANCE_NOT_ELIGIBLE`, `INSTANCE_STOPPED`,
    /// `RUN_IN_PROGRESS` (also when the source was retrained while the clone
    /// was prepared, with the source's name in `value`) and
    /// `CROSS_CUSTOMER_FORBIDDEN`; and, once the run is stored,
    /// `ENGINE_REFUSED` with the engine's reason in `value` or
    /// `INSTANCE_UNREACHABLE`, either removing the run with its target
    /// definition.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    #[allow(clippy::too_many_arguments)]
    async fn clone_model(
        &self,
        ctx: &Context<'_>,
        source: String,
        target_name: String,
        node_id: ID,
        agent_key: String,
        data_store: DataStoreInput,
        sources: Vec<String>,
        suspicious_tokens: MaybeUndefined<String>,
    ) -> Result<ID> {
        let node_id = parse_node_id(&node_id)?;
        let address = data_store.address.parse::<SocketAddr>().map_err(|e| {
            refusal(
                RefusalCode::InvalidDocument,
                format!("data_store.address is not a socket address: {e}"),
                "data_store.address",
                data_store.address.as_str(),
            )
        })?;
        let data_store = DataStore {
            address,
            server_name: data_store.server_name,
        };
        let addrs = data_store_addrs(ctx, &data_store.server_name).await;

        let (agent_lookup_key, run) = {
            let _lock = lock_engine_config(ctx).await?;
            let model = load_accessible_model_by_name(ctx, "source", &source)?;
            let users_customers = users_customers(ctx)?;
            let system_admin = is_system_admin(ctx);
            let store = super::get_store(ctx)?;
            let target = resolve_instance(&store, users_customers.as_deref(), node_id, &agent_key)?;
            let cross_customer = target.customer_id != model.customer_id;
            if cross_customer && !system_admin {
                return Err(refusal(
                    RefusalCode::CrossCustomerForbidden,
                    "only a System Administrator may clone a model to another customer",
                    "nodeId",
                    target.instance.node_id.to_string(),
                ));
            }
            let Some(instance) = model.instance.as_ref() else {
                return Err(no_instance("source", &source));
            };
            let Some(hostname) = applied_hostname(&store, instance.node_id)? else {
                return Err(no_hostname(instance));
            };
            let document = clone_document(
                &model.trained_definition,
                &source,
                data_store,
                sources,
                suspicious_tokens,
                cross_customer,
            )?;
            let trained_pair = TrainingDocument::parse(&model.trained_definition)
                .map(|trained| HashSet::from([trained.data_store.pair()]))
                .unwrap_or_default();
            document.check_stored(
                &store,
                target.customer_id,
                &addrs,
                &trained_pair,
                system_admin,
            )?;
            let run = store
                .start_clone_run(
                    &source,
                    model.trained_run_id,
                    NewTrainingDefinition {
                        name: target_name.clone(),
                        customer_id: target.customer_id,
                        instance: target.instance,
                        method: document.method.into(),
                        event_kind: document.event_kind.clone(),
                        sources: document.sources.clone(),
                        indicator: document.suspicious_tokens.clone(),
                        definition: document.to_text()?,
                    },
                )
                .map_err(|e| store_refusal(e, StoreWrite::StartClone, Some(&document)))?;
            (
                gen_agent_lookup_key(&run.instance.agent_key, &hostname),
                run,
            )
        };

        let strip_events = matches!(
            run.kind,
            RunKind::Clone {
                strip_events: true,
                ..
            }
        );
        let agent_manager = ctx.data::<SharedAgentManager>()?;
        if let Err(e) = agent_manager
            .clone_model(
                &agent_lookup_key,
                run.id,
                &source,
                &target_name,
                strip_events,
            )
            .await
        {
            fail_unless_ended(ctx, run.id);
            return Err(relay_refusal(&e, "source", &agent_lookup_key));
        }
        Ok(ID(run.id.to_string()))
    }

    /// Deletes the model `name` with everything stored for it, returning the
    /// name.
    ///
    /// Scope is the model's customer. Refusals carry `extensions.code`:
    /// `NOT_FOUND`; `MODEL_IN_USE` while a detector names the model (with
    /// `detectorId`, `nodeId` and `agentKey`), a run of the model is active
    /// (with the run id in `value`), or one of its indicators is named by a
    /// detector or another definition (with the indicator in `value`, and
    /// `detectorId`, `nodeId` and `agentKey`, or `definition`).
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_model(&self, ctx: &Context<'_>, name: String) -> Result<String> {
        let _lock = lock_engine_config(ctx).await?;
        load_accessible_model_by_name(ctx, "name", &name)?;
        let store = super::get_store(ctx)?;
        store
            .delete_model(&name)
            .map_err(|e| store_refusal(e, StoreWrite::DeleteModel, None))?;
        Ok(name)
    }

    /// Gives the model `name`, which has no instance, the engine instance
    /// `agentKey` of node `nodeId`, returning the name.
    ///
    /// The caller must belong to the model's customer and the instance's, or
    /// is refused with `Forbidden`. Refusals carry `extensions.code`:
    /// `NOT_FOUND`; `ASSIGN_REFUSED` for a model that has an instance or an
    /// instance of another customer than the model's;
    /// `INSTANCE_NOT_ELIGIBLE`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn assign_model(
        &self,
        ctx: &Context<'_>,
        name: String,
        node_id: ID,
        agent_key: String,
    ) -> Result<String> {
        let node_id = parse_node_id(&node_id)?;
        let _lock = lock_engine_config(ctx).await?;
        load_accessible_model_by_name(ctx, "name", &name)?;
        let users_customers = users_customers(ctx)?;
        let store = super::get_store(ctx)?;
        let target = resolve_instance(&store, users_customers.as_deref(), node_id, &agent_key)?;
        store
            .assign_model(&name, &target.instance)
            .map_err(|e| store_refusal(e, StoreWrite::AssignModel, None))?;
        Ok(name)
    }
}

/// The Data Store a clone's target reads from.
#[derive(InputObject)]
struct DataStoreInput {
    /// The address the engine dials, `ip:port`.
    address: String,
    /// The name of the Data Store, `<instance:03>.giganto.<hostname>`.
    server_name: String,
}

fn parse_node_id(node_id: &ID) -> Result<u32> {
    node_id
        .as_str()
        .parse::<u32>()
        .map_err(|_| "invalid node ID".into())
}

/// Reads the training definition `name` and checks whether the requester can
/// access it.
fn accessible_definition(
    store: &Store,
    users_customers: Option<&[u32]>,
    name: &str,
) -> Result<database::TrainingDefinition> {
    let Some(definition) = store.training_definition(name)? else {
        return Err(refusal(
            RefusalCode::NotFound,
            format!("training definition {name:?} not found"),
            "name",
            name,
        ));
    };
    if is_member(users_customers, definition.customer_id) {
        Ok(definition)
    } else {
        Err("Forbidden".into())
    }
}

/// Returns the `(server_name, address)` pair of a stored definition text, the
/// pair the Data Store rule keeps for an update of it; none if the text does
/// not parse.
fn kept_pair(text: &str) -> HashSet<(String, SocketAddr)> {
    TrainingDocument::parse(text)
        .map(|document| HashSet::from([document.data_store.pair()]))
        .unwrap_or_default()
}

/// Returns the target definition of a clone: the source's trained definition
/// with the Data Store, the sources and the indicator replaced, validated as
/// a definition is.
fn clone_document(
    trained: &str,
    source: &str,
    data_store: DataStore,
    sources: Vec<String>,
    suspicious_tokens: MaybeUndefined<String>,
    cross_customer: bool,
) -> Result<TrainingDocument> {
    let mut document = TrainingDocument::parse(trained).map_err(|_| {
        refusal(
            RefusalCode::InvalidDocument,
            format!("the trained definition of model {source:?} does not parse"),
            "source",
            source,
        )
    })?;
    document.data_store = data_store;
    document.sources = sources;
    document.suspicious_tokens = match suspicious_tokens {
        MaybeUndefined::Undefined if cross_customer => None,
        MaybeUndefined::Undefined => document.suspicious_tokens,
        MaybeUndefined::Null => None,
        MaybeUndefined::Value(indicator) => Some(indicator),
    };
    // Validates the text that is stored and relayed, which a serialization of
    // the schema types makes free of comments and keys outside the schema.
    TrainingDocument::parse_and_validate(&document.to_text()?)
}

/// An engine instance a request names, resolved with the lock held.
struct TargetInstance {
    instance: database::ModelInstance,
    customer_id: u32,
}

/// Resolves the engine instance `agent_key` of node `node_id` and checks
/// whether the requester can access its customer.
///
/// The instance must be an Unsupervised Engine agent with an instance number,
/// on a node whose applied profile has a hostname; otherwise the request is
/// refused with `INSTANCE_NOT_ELIGIBLE`. Its customer is that profile's.
fn resolve_instance(
    store: &Store,
    users_customers: Option<&[u32]>,
    node_id: u32,
    agent_key: &str,
) -> Result<TargetInstance> {
    let not_eligible = |reason: &str, field: &str, value: String| {
        refusal(
            RefusalCode::InstanceNotEligible,
            format!("agent {agent_key:?} of node {node_id} {reason}"),
            field,
            value,
        )
    };
    let Some((node, _, _)) = store.node_map().get_by_id(node_id)? else {
        return Err(not_eligible(
            "does not exist",
            "nodeId",
            node_id.to_string(),
        ));
    };
    let Some(profile) = node.profile.as_ref() else {
        return Err(not_eligible(
            "is on a node with no applied profile",
            "nodeId",
            node_id.to_string(),
        ));
    };
    if !is_member(users_customers, profile.customer_id) {
        return Err("Forbidden".into());
    }
    if profile.hostname.is_empty() {
        return Err(not_eligible(
            "is on a node with no applied hostname",
            "nodeId",
            node_id.to_string(),
        ));
    }
    let eligible = node.agents.iter().any(|agent| {
        agent.key == agent_key
            && agent.kind == database::AgentKind::Unsupervised
            && agent.instance.is_some()
    });
    if !eligible {
        return Err(not_eligible(
            "is not an installed Unsupervised Engine instance",
            "agentKey",
            agent_key.to_string(),
        ));
    }
    Ok(TargetInstance {
        instance: database::ModelInstance {
            node_id,
            agent_key: agent_key.to_string(),
        },
        customer_id: profile.customer_id,
    })
}

/// Returns the hostname of the applied profile of node `node_id`, or `None`
/// if the node does not exist or has no applied profile with a hostname.
fn applied_hostname(store: &Store, node_id: u32) -> Result<Option<String>> {
    Ok(store
        .node_map()
        .get_by_id(node_id)?
        .and_then(|(node, _, _)| node.profile)
        .map(|profile| profile.hostname)
        .filter(|hostname| !hostname.is_empty()))
}

/// Returns the `INSTANCE_NOT_ELIGIBLE` refusal of a definition or model,
/// named by the argument `field`, that has no instance.
fn no_instance(field: &str, name: &str) -> async_graphql::Error {
    refusal(
        RefusalCode::InstanceNotEligible,
        format!("{name:?} has no instance"),
        field,
        name,
    )
}

/// Returns the `INSTANCE_NOT_ELIGIBLE` refusal of an instance whose node has
/// no applied hostname, which a relay cannot address.
fn no_hostname(instance: &database::ModelInstance) -> async_graphql::Error {
    refusal(
        RefusalCode::InstanceNotEligible,
        format!(
            "node {} of instance {:?} has no applied hostname",
            instance.node_id, instance.agent_key
        ),
        "agentKey",
        instance.agent_key.as_str(),
    )
    .extend_with(|_, extensions| {
        extensions.set("nodeId", instance.node_id.to_string());
        extensions.set("agentKey", instance.agent_key.as_str());
    })
}

/// Ends the run `run_id` as failed after a relay error, unless the agent
/// manager already ended it.
fn fail_unless_ended(ctx: &Context<'_>, run_id: RunId) {
    match super::get_store(ctx) {
        Ok(store) => fail_run(&store, run_id),
        Err(e) => warn!("cannot fail model run {run_id}: {e:?}"),
    }
}

/// Ends the run `run_id` as failed with the reason "instance unreachable".
///
/// A run that has ended meanwhile, or is gone, is left as it is; any other
/// failure is logged, since the caller returns its own refusal.
fn fail_run(store: &Store, run_id: RunId) {
    if let Err(e) = store.fail_run(run_id, INSTANCE_UNREACHABLE) {
        let ended = matches!(
            e.downcast_ref::<TrainingError>(),
            Some(TrainingError::RunNotActive { .. } | TrainingError::RunNotFound { .. })
        );
        if !ended {
            warn!("cannot fail model run {run_id}: {e:#}");
        }
    }
}

/// Maps a relay error: `ENGINE_REFUSED`, with the engine's reason in `value`,
/// when the instance received the request and refused it, and
/// `INSTANCE_UNREACHABLE`, with the agent lookup key in `value`, otherwise.
fn relay_refusal(
    error: &anyhow::Error,
    field: &str,
    agent_lookup_key: &str,
) -> async_graphql::Error {
    if let Some(refused) = error.downcast_ref::<EngineRefused>() {
        refusal(
            RefusalCode::EngineRefused,
            refused.to_string(),
            field,
            refused.reason.as_str(),
        )
    } else {
        refusal(
            RefusalCode::InstanceUnreachable,
            format!("the request did not reach {agent_lookup_key}: {error:#}"),
            field,
            agent_lookup_key,
        )
    }
}

/// The store write a refusal comes from, which decides how some refusals map.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreWrite {
    InsertDefinition,
    UpdateDefinition,
    RemoveDefinition,
    StartTraining,
    StartClone,
    DeleteModel,
    AssignModel,
}

impl StoreWrite {
    /// The argument that names the definition or model the write acts on.
    fn name_field(self) -> &'static str {
        match self {
            Self::StartClone => "targetName",
            _ => "name",
        }
    }
}

/// Maps the [`TrainingError`] refusals of review-database's training writes
/// to their refusal codes, passing every other error through as an internal
/// error.
///
/// `document` is the definition the write stores, if any, for the values of
/// `FIELD_FIXED` and of a clone's `INVALID_DOCUMENT`.
// One arm per refusal, each building its own extensions.
#[allow(clippy::too_many_lines)]
fn store_refusal(
    error: anyhow::Error,
    write: StoreWrite,
    document: Option<&TrainingDocument>,
) -> async_graphql::Error {
    let Some(training_error) = error.downcast_ref::<TrainingError>() else {
        return error.into();
    };
    let message = training_error.to_string();
    let name_field = write.name_field();
    match training_error {
        TrainingError::DefinitionNotFound { name } => {
            refusal(RefusalCode::NotFound, message, "name", name.as_str())
        }
        TrainingError::ModelNotFound { name } => {
            let field = if write == StoreWrite::StartClone {
                "source"
            } else {
                "name"
            };
            refusal(RefusalCode::NotFound, message, field, name.as_str())
        }
        TrainingError::RunNotFound { run_id } => {
            refusal(RefusalCode::NotFound, message, "runId", run_id.to_string())
        }
        TrainingError::NameTaken { name } => {
            refusal(RefusalCode::NameTaken, message, name_field, name.as_str())
        }
        TrainingError::InvalidName { name, .. } => {
            refusal(RefusalCode::NameInvalid, message, name_field, name.as_str())
        }
        TrainingError::InstanceNotEligible { node_id, agent_key } => refusal(
            RefusalCode::InstanceNotEligible,
            message,
            "agentKey",
            agent_key.as_str(),
        )
        .extend_with(|_, extensions| {
            extensions.set("nodeId", node_id.to_string());
            extensions.set("agentKey", agent_key.as_str());
        }),
        TrainingError::NoAppliedProfile { node_id } => refusal(
            RefusalCode::InstanceNotEligible,
            message,
            "nodeId",
            node_id.to_string(),
        ),
        TrainingError::NoInstance { name } => {
            let field = if write == StoreWrite::StartClone {
                "source"
            } else {
                "name"
            };
            refusal(
                RefusalCode::InstanceNotEligible,
                message,
                field,
                name.as_str(),
            )
        }
        TrainingError::CustomerMismatch { node_id, .. } => {
            let code = if write == StoreWrite::AssignModel {
                RefusalCode::AssignRefused
            } else {
                RefusalCode::InstanceNotEligible
            };
            refusal(code, message, "nodeId", node_id.to_string())
        }
        TrainingError::InstanceStopped { node_id, agent_key } => refusal(
            RefusalCode::InstanceStopped,
            message,
            "agentKey",
            agent_key.as_str(),
        )
        .extend_with(|_, extensions| {
            extensions.set("nodeId", node_id.to_string());
            extensions.set("agentKey", agent_key.as_str());
        }),
        TrainingError::RunInProgress { run_id } => {
            let (code, field) = match write {
                StoreWrite::DeleteModel => (RefusalCode::ModelInUse, "name"),
                StoreWrite::StartClone => (RefusalCode::RunInProgress, "source"),
                _ => (RefusalCode::RunInProgress, "name"),
            };
            refusal(code, message, field, run_id.to_string())
        }
        TrainingError::SourceRetrained { source, .. } => refusal(
            RefusalCode::RunInProgress,
            message,
            "source",
            source.as_str(),
        ),
        TrainingError::FieldFixed { name, field } => {
            let (field, value) = match field {
                database::FixedField::Method => (
                    "method",
                    document.map(|d| method_name(d.method)).unwrap_or_default(),
                ),
                database::FixedField::EventKind => (
                    "event_kind",
                    document.map(|d| d.event_kind.clone()).unwrap_or_default(),
                ),
            };
            refusal(RefusalCode::FieldFixed, message, field, value)
                .extend_with(|_, extensions| extensions.set("definition", name.as_str()))
        }
        TrainingError::IndicatorNotFound { indicator } => refusal(
            RefusalCode::IndicatorNotAllowed,
            message,
            "suspicious_tokens",
            indicator.as_str(),
        ),
        TrainingError::MethodMismatch { .. } => refusal(
            RefusalCode::InvalidDocument,
            message,
            "method",
            document.map(|d| method_name(d.method)).unwrap_or_default(),
        ),
        TrainingError::EventKindMismatch { expected, .. } => refusal(
            RefusalCode::InvalidDocument,
            message,
            "event_kind",
            expected.as_str(),
        ),
        TrainingError::RunNotActive { run_id, .. } => refusal(
            RefusalCode::RunNotActive,
            message,
            "runId",
            run_id.to_string(),
        ),
        TrainingError::HasModel { name } => {
            refusal(RefusalCode::ModelInUse, message, "name", name.as_str())
                .extend_with(|_, extensions| extensions.set("definition", name.as_str()))
        }
        TrainingError::ModelInUse {
            name,
            instance,
            detector_id,
        } => refusal(RefusalCode::ModelInUse, message, "name", name.as_str()).extend_with(
            |_, extensions| {
                extensions.set("detectorId", *detector_id);
                extensions.set("nodeId", instance.node_id.to_string());
                extensions.set("agentKey", instance.agent_key.as_str());
            },
        ),
        TrainingError::IndicatorInUse { indicator, by } => {
            refusal(RefusalCode::ModelInUse, message, "name", indicator.as_str()).extend_with(
                |_, extensions| match by {
                    Referrer::Detector {
                        instance,
                        detector_id,
                    } => {
                        extensions.set("detectorId", *detector_id);
                        extensions.set("nodeId", instance.node_id.to_string());
                        extensions.set("agentKey", instance.agent_key.as_str());
                    }
                    Referrer::Definition { name } => {
                        extensions.set("definition", name.as_str());
                    }
                },
            )
        }
        TrainingError::ModelHasInstance { name, instance } => {
            refusal(RefusalCode::AssignRefused, message, "name", name.as_str()).extend_with(
                |_, extensions| {
                    extensions.set("nodeId", instance.node_id.to_string());
                    extensions.set("agentKey", instance.agent_key.as_str());
                },
            )
        }
        _ => error.into(),
    }
}

/// Returns the name a definition gives `method`.
fn method_name(method: definition::Method) -> String {
    match method {
        definition::Method::Multidimension => "multidimension",
        definition::Method::Prefix => "prefix",
        definition::Method::Timeseries => "timeseries",
    }
    .to_string()
}

/// Returns `run` as a read that shows it on the model or definition
/// `shown_on` returns it, or `None` if the caller may not see it.
///
/// A clone run to another customer names that customer's model, so callers
/// who are not System Administrators see it neither on its source model nor
/// on the source's definition, and never see its `source`. Every other run is
/// shown in full.
pub(super) fn visible_run(
    run: database::ModelRun,
    shown_on: &str,
    system_admin: bool,
) -> Option<ModelRun> {
    let show_source = match &run.kind {
        RunKind::Clone {
            source,
            strip_events: true,
        } => {
            if !system_admin && source == shown_on {
                return None;
            }
            system_admin
        }
        RunKind::Clone { .. } | RunKind::Train => true,
    };
    Some(ModelRun {
        inner: run,
        show_source,
    })
}

/// Returns the active run concerning `name` that the caller may see.
pub(super) fn visible_active_run(
    ctx: &Context<'_>,
    store: &Store,
    name: &str,
) -> Result<Option<ModelRun>> {
    let system_admin = is_system_admin(ctx);
    Ok(store
        .active_run(name)?
        .and_then(|run| visible_run(run, name, system_admin)))
}

/// A training definition: what data trains a model (RFC 0006 §5.5).
pub(super) struct TrainingDefinition {
    inner: database::TrainingDefinition,
}

impl From<database::TrainingDefinition> for TrainingDefinition {
    fn from(inner: database::TrainingDefinition) -> Self {
        Self { inner }
    }
}

#[Object]
impl TrainingDefinition {
    /// The name of the definition, which is also the name of its model.
    async fn name(&self) -> &str {
        &self.inner.name
    }

    /// The customer the definition belongs to.
    async fn customer_id(&self) -> ID {
        ID(self.inner.customer_id.to_string())
    }

    /// The engine instance the definition trains on, or null in the "no
    /// instance" state.
    async fn instance(&self) -> Option<ModelInstance> {
        self.inner.instance.as_ref().map(Into::into)
    }

    /// The clustering method the definition trains with.
    async fn method(&self) -> ModelMethod {
        self.inner.method.into()
    }

    /// The event kind the definition trains on.
    async fn event_kind(&self) -> &str {
        &self.inner.event_kind
    }

    /// The source names the definition reads events of.
    async fn sources(&self) -> &[String] {
        &self.inner.sources
    }

    /// The model indicator `suspicious_tokens` names, if any.
    async fn suspicious_tokens(&self) -> Option<&str> {
        self.inner.indicator.as_deref()
    }

    /// The definition, a TOML document: the settings of the model's next
    /// training.
    async fn definition(&self) -> &str {
        &self.inner.definition
    }

    /// The state of the definition.
    async fn state(&self, ctx: &Context<'_>) -> Result<TrainingDefinitionState> {
        let store = super::get_store(ctx)?;
        store
            .training_definition_state(&self.inner.name)?
            .map(Into::into)
            .ok_or_else(|| format!("training definition {:?} not found", self.inner.name).into())
    }

    /// The model the definition trained, or null until it is trained.
    async fn model(&self, ctx: &Context<'_>) -> Result<Option<ModelDigest>> {
        let store = super::get_store(ctx)?;
        Ok(model_by_name(&store, &self.inner.name)?.map(Into::into))
    }

    /// The active run that creates or replaces the model, or clones from it.
    async fn active_run(&self, ctx: &Context<'_>) -> Result<Option<ModelRun>> {
        let store = super::get_store(ctx)?;
        visible_active_run(ctx, &store, &self.inner.name)
    }

    /// The last run of the definition.
    async fn last_run(&self, ctx: &Context<'_>) -> Result<Option<ModelRun>> {
        let Some(run_id) = self.inner.last_run else {
            return Ok(None);
        };
        let store = super::get_store(ctx)?;
        let system_admin = is_system_admin(ctx);
        Ok(store
            .model_run(run_id)?
            .and_then(|run| visible_run(run, &self.inner.name, system_admin)))
    }

    /// When the definition was created.
    async fn created_at(&self) -> DateTime<Utc> {
        self.inner.created_at
    }

    /// When the definition was last updated.
    async fn updated_at(&self) -> DateTime<Utc> {
        self.inner.updated_at
    }
}

/// The state of a training definition (RFC 0006 §5.10).
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::TrainingDefinitionState")]
pub(super) enum TrainingDefinitionState {
    /// No model exists and no run failed.
    NeverTrained,
    /// A training run of the definition is active.
    Training,
    /// The definition was created by a clone that has not succeeded yet.
    Cloning,
    /// A model of the definition's name exists.
    Ready,
    /// No model exists and the last run failed.
    TrainingFailed,
    /// The definition has no instance.
    NoInstance,
}

/// A training or clone run.
pub(super) struct ModelRun {
    inner: database::ModelRun,
    /// Whether the read may show a clone run's source.
    show_source: bool,
}

#[Object]
impl ModelRun {
    /// The id the Central Manager issued for the run.
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    /// What the run does.
    async fn kind(&self) -> ModelRunKind {
        match self.inner.kind {
            RunKind::Train => ModelRunKind::Train,
            RunKind::Clone { .. } => ModelRunKind::Clone,
        }
    }

    /// The model the run creates or replaces; for a clone, the target.
    async fn model(&self) -> &str {
        &self.inner.model
    }

    /// The model a clone run copies, or null for a training run. Null also
    /// for a clone to another customer unless the caller is a System
    /// Administrator.
    async fn source(&self) -> Option<&str> {
        match &self.inner.kind {
            RunKind::Clone { source, .. } if self.show_source => Some(source),
            _ => None,
        }
    }

    /// The state of the run.
    async fn state(&self) -> ModelRunState {
        self.inner.state.into()
    }

    /// The reason given with the last state change, if any.
    async fn reason(&self) -> Option<&str> {
        self.inner.reason.as_deref()
    }

    /// When the run was requested.
    async fn requested_at(&self) -> DateTime<Utc> {
        self.inner.requested_at
    }

    /// When the state of the run last changed.
    async fn updated_at(&self) -> DateTime<Utc> {
        self.inner.updated_at
    }
}

/// What a run does.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
pub(super) enum ModelRunKind {
    /// Trains the model of a training definition.
    Train,
    /// Clones a model into a new one.
    Clone,
}

/// The state of a run.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
#[graphql(remote = "database::RunState")]
pub(super) enum ModelRunState {
    Requested,
    Started,
    Succeeded,
    Failed,
    Cancelled,
}

/// A detector of an engine instance's applied or pending document that names
/// a model.
#[derive(SimpleObject)]
pub(super) struct ModelDetectorUse {
    /// The node of the instance.
    node_id: ID,
    /// The key of the instance's agent on the node.
    agent_key: String,
    /// The id of the detector.
    detector_id: ID,
    /// Whether the applied document's detector names the model.
    applied: bool,
    /// Whether the pending document's detector names the model.
    pending: bool,
}

impl From<database::ModelUse> for ModelDetectorUse {
    fn from(user: database::ModelUse) -> Self {
        Self {
            node_id: ID(user.instance.node_id.to_string()),
            agent_key: user.instance.agent_key,
            detector_id: ID(user.detector_id.to_string()),
            applied: user.applied,
            pending: user.pending,
        }
    }
}

#[cfg(test)]
mod tests;
