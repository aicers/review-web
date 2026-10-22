use async_graphql::{Context, ErrorExtensions, ID, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database::{self as database, Referrer, Store, TrainingError};

use super::customer_access::{is_member, users_customers};
use super::engine_config::lock_engine_config;
use super::refusal::{RefusalCode, refusal};
use crate::graphql::{Role, RoleGuard};

#[derive(Default)]
pub(super) struct IndicatorQuery;

#[Object]
impl IndicatorQuery {
    /// Look up an Indicator by the given name.
    ///
    /// Returns null for an indicator whose model belongs to none of the
    /// caller's customers, as for a name no indicator has. An indicator whose
    /// model does not exist is visible to System Administrators only.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn indicator(&self, ctx: &Context<'_>, name: String) -> Result<Option<ModelIndicator>> {
        let users_customers = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let Some(indicator) = store.model_indicator_map().get(&name)? else {
            return Ok(None);
        };
        if is_visible(&store, users_customers.as_deref(), &indicator)? {
            Ok(Some(indicator.into()))
        } else {
            Ok(None)
        }
    }

    /// A list of Indicators.
    ///
    /// Lists only the indicators whose model belongs to one of the caller's
    /// customers. An indicator whose model does not exist is visible to System
    /// Administrators only.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn indicator_list(&self, ctx: &Context<'_>) -> Result<Vec<ModelIndicator>> {
        use database::Iterable;

        let users_customers = users_customers(ctx)?;
        let store = super::get_store(ctx)?;
        let map = store.model_indicator_map();
        let mut indicators = Vec::new();
        for res in map.iter(database::event::Direction::Forward, None) {
            let indicator = res?;
            if is_visible(&store, users_customers.as_deref(), &indicator)? {
                indicators.push(indicator.into());
            }
        }
        Ok(indicators)
    }
}

/// Checks whether an indicator is visible to a requester with the given
/// customers: its model belongs to one of them, or, for an indicator whose
/// model does not exist, the requester is unscoped.
fn is_visible(
    store: &Store,
    users_customers: Option<&[u32]>,
    indicator: &database::ModelIndicator,
) -> Result<bool> {
    Ok(match store.model_map().get_by_id(indicator.model_id)? {
        Some(model) => is_member(users_customers, model.customer_id),
        None => users_customers.is_none(),
    })
}

#[derive(Default)]
pub(super) struct IndicatorMutation;

#[Object]
impl IndicatorMutation {
    /// Inserts a new Indicator, or updates the Indicator of the same name as
    /// `updateIndicator` does. Returns the indicator's name.
    ///
    /// Refusals of an update of an existing name carry `extensions.code`:
    /// `INDICATOR_IN_USE` while an engine document or a training definition
    /// names the indicator, and `INDICATOR_MODEL_CHANGE` if the new data would
    /// move it to another model.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn insert_indicator(
        &self,
        ctx: &Context<'_>,
        name: String,
        dbfile: String,
    ) -> Result<String> {
        let indicator = database::ModelIndicator::new(&name, &dbfile)?;
        let _lock = lock_engine_config(ctx).await?;
        let store = super::get_store(ctx)?;
        let result = if store.model_indicator_map().get(&name)?.is_some() {
            store.update_model_indicator(indicator)
        } else {
            store.insert_model_indicator(indicator)
        };
        result.map_err(indicator_refusal)?;
        Ok(name)
    }

    /// Removes Indicators, all or none, returning the given names.
    ///
    /// A name no indicator has is skipped. The removal is refused with
    /// `extensions.code` `INDICATOR_IN_USE` while an engine document or a
    /// training definition names one of the indicators.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn remove_indicator(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] names: Vec<String>,
    ) -> Result<Vec<String>> {
        let _lock = lock_engine_config(ctx).await?;
        let store = super::get_store(ctx)?;
        store
            .remove_model_indicators(&names)
            .map_err(indicator_refusal)?;
        Ok(names)
    }

    /// Updates the given indicator, returning the indicator name that was updated.
    ///
    /// Refusals carry `extensions.code`: `NOT_FOUND` if no indicator has the
    /// name, `INDICATOR_MODEL_CHANGE` if the new data would move the indicator
    /// to another model, and `INDICATOR_IN_USE` while an engine document or a
    /// training definition names it.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn update_indicator(
        &self,
        ctx: &Context<'_>,
        name: String,
        new: String,
    ) -> Result<String> {
        let indicator = database::ModelIndicator::new(&name, &new)?;
        let _lock = lock_engine_config(ctx).await?;
        let store = super::get_store(ctx)?;
        store
            .update_model_indicator(indicator)
            .map_err(indicator_refusal)?;
        Ok(name)
    }
}

/// Maps the refusals of review-database's guarded indicator writes to their
/// refusal codes, passing every other error through.
///
/// `INDICATOR_IN_USE` names what holds the indicator: a detector with
/// `detectorId` (an integer), `nodeId` and `agentKey`, or a training
/// definition with `definition`.
fn indicator_refusal(error: anyhow::Error) -> async_graphql::Error {
    let Some(training_error) = error.downcast_ref::<TrainingError>() else {
        return error.into();
    };
    let message = training_error.to_string();
    match training_error {
        TrainingError::IndicatorInUse { indicator, by } => refusal(
            RefusalCode::IndicatorInUse,
            message,
            "name",
            indicator.as_str(),
        )
        .extend_with(|_, extensions| match by {
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
        }),
        TrainingError::IndicatorModelChange { new_model_id, .. } => refusal(
            RefusalCode::IndicatorModelChange,
            message,
            "model_id",
            new_model_id.to_string(),
        ),
        TrainingError::IndicatorNotFound { indicator } => {
            refusal(RefusalCode::NotFound, message, "name", indicator.as_str())
        }
        _ => error.into(),
    }
}

struct ModelIndicator {
    inner: database::ModelIndicator,
}

#[Object]
impl ModelIndicator {
    /// The name of the model indicator.
    async fn name(&self) -> &str {
        &self.inner.name
    }

    /// The description of the model indicator.
    async fn description(&self) -> &str {
        &self.inner.description
    }

    /// The model ID of the model indicator.
    async fn model_id(&self) -> ID {
        ID(self.inner.model_id.to_string())
    }

    /// The size of the model indicator in string within the representable
    /// range of a `usize`
    async fn size(&self) -> StringNumber<usize> {
        StringNumber(self.inner.tokens.len())
    }

    /// The last modified time of the model indicator.
    async fn last_modified(&self) -> DateTime<Utc> {
        self.inner.last_modification_time
    }
}

impl From<database::ModelIndicator> for ModelIndicator {
    fn from(inner: database::ModelIndicator) -> Self {
        Self { inner }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::graphql::model_test_support::{
        TEST_AGENT_KEY, TestModel, data, indicator_dbfile, insert_definition, insert_engine_node,
        insert_indicator, name_in_applied_document, replace_model, single_error,
    };
    use crate::graphql::{Role, TestSchema};

    /// Customer A's model, on an installed engine instance.
    const CUSTOMER_A: u32 = 1;
    /// Customer B's model.
    const CUSTOMER_B: u32 = 2;
    /// A model id no model has.
    const MISSING_MODEL: u32 = 99;

    struct Fixture {
        schema: TestSchema,
        instance: review_database::ModelInstance,
        model_a: u32,
        model_b: u32,
    }

    /// Stores customer A's model `model-a` on an installed engine instance of
    /// A, and customer B's model `model-b`.
    async fn fixture() -> Fixture {
        let schema = TestSchema::new().await;
        let (instance, model_a, model_b) = {
            let store = schema.store();
            let instance = insert_engine_node(&store, CUSTOMER_A);
            let model_a = TestModel {
                instance: instance.clone(),
                ..TestModel::new("model-a", CUSTOMER_A)
            }
            .replace(&store);
            let model_b = replace_model(&store, "model-b", CUSTOMER_B);
            (instance, model_a, model_b)
        };
        Fixture {
            schema,
            instance,
            model_a,
            model_b,
        }
    }

    fn description(schema: &TestSchema, name: &str) -> Option<String> {
        schema
            .store()
            .model_indicator_map()
            .get(name)
            .unwrap()
            .map(|indicator| indicator.description)
    }

    fn insert(name: &str, model_id: u32, description: &str) -> String {
        format!(
            r#"mutation {{ insertIndicator(name: "{name}", dbfile: "{}") }}"#,
            indicator_dbfile(model_id, description)
        )
    }

    fn update(name: &str, model_id: u32, description: &str) -> String {
        format!(
            r#"mutation {{ updateIndicator(name: "{name}", new: "{}") }}"#,
            indicator_dbfile(model_id, description)
        )
    }

    fn remove(names: &[&str]) -> String {
        let names = names
            .iter()
            .map(|name| format!("{name:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("mutation {{ removeIndicator(names: [{names}]) }}")
    }

    #[tokio::test]
    async fn indicator_writes_are_limited_to_system_administrators() {
        let f = fixture().await;
        insert_indicator(&f.schema.store(), "held", f.model_a);
        for role in [
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            for customers in [vec![CUSTOMER_A], vec![CUSTOMER_A, CUSTOMER_B]] {
                for query in [
                    insert("new", f.model_a, "new"),
                    insert("held", f.model_a, "changed"),
                    update("held", f.model_a, "changed"),
                    remove(&["held"]),
                ] {
                    let res = f
                        .schema
                        .execute_as_scoped_user(&query, role, Some(customers.clone()))
                        .await;
                    assert_eq!(single_error(&res).0, "Forbidden", "{role:?}: {query}");
                }
            }
        }
        assert_eq!(description(&f.schema, "new"), None);
        assert_eq!(
            description(&f.schema, "held").as_deref(),
            Some("indicator held")
        );

        let res = f
            .schema
            .execute_as_system_admin(&insert("new", f.model_a, "new"))
            .await;
        assert_eq!(data(res), json!({ "insertIndicator": "new" }));
        let res = f
            .schema
            .execute_as_system_admin(&update("held", f.model_a, "changed"))
            .await;
        assert_eq!(data(res), json!({ "updateIndicator": "held" }));
        assert_eq!(description(&f.schema, "held").as_deref(), Some("changed"));
        let res = f
            .schema
            .execute_as_system_admin(&remove(&["held", "new"]))
            .await;
        assert_eq!(data(res), json!({ "removeIndicator": ["held", "new"] }));
        assert_eq!(description(&f.schema, "held"), None);
    }

    #[tokio::test]
    async fn indicator_reads_follow_the_model_customer() {
        let f = fixture().await;
        {
            let store = f.schema.store();
            insert_indicator(&store, "a", f.model_a);
            insert_indicator(&store, "b", f.model_b);
            insert_indicator(&store, "orphan", MISSING_MODEL);
        }
        let lookup = |name: &str| format!(r#"{{ indicator(name: "{name}") {{ name }} }}"#);
        let list = "{ indicatorList { name } }";

        let scoped = |query: String, role: Role, customers: Vec<u32>| {
            let schema = &f.schema;
            async move {
                data(
                    schema
                        .execute_as_scoped_user(&query, role, Some(customers))
                        .await,
                )
            }
        };
        let customer_b = vec![CUSTOMER_B];
        let res = scoped(lookup("a"), Role::SecurityAdministrator, customer_b.clone()).await;
        assert_eq!(res, json!({ "indicator": null }));
        let res = scoped(lookup("b"), Role::SecurityAdministrator, customer_b.clone()).await;
        assert_eq!(res, json!({ "indicator": { "name": "b" } }));
        let res = scoped(
            lookup("orphan"),
            Role::SecurityAdministrator,
            vec![CUSTOMER_A, CUSTOMER_B],
        )
        .await;
        assert_eq!(res, json!({ "indicator": null }));
        let res = scoped(
            lookup("none"),
            Role::SecurityAdministrator,
            customer_b.clone(),
        )
        .await;
        assert_eq!(res, json!({ "indicator": null }));
        for role in [
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            let res = scoped(list.to_string(), role, customer_b.clone()).await;
            assert_eq!(
                res,
                json!({ "indicatorList": [{ "name": "b" }] }),
                "{role:?}"
            );
            let res = scoped(list.to_string(), role, vec![CUSTOMER_A, CUSTOMER_B]).await;
            assert_eq!(
                res,
                json!({ "indicatorList": [{ "name": "a" }, { "name": "b" }] }),
                "{role:?}"
            );
        }

        for name in ["a", "b", "orphan"] {
            let res = data(f.schema.execute_as_system_admin(&lookup(name)).await);
            assert_eq!(res, json!({ "indicator": { "name": name } }));
        }
        let res = data(f.schema.execute_as_system_admin(list).await);
        assert_eq!(
            res,
            json!({ "indicatorList": [{ "name": "a" }, { "name": "b" }, { "name": "orphan" }] })
        );
    }

    #[tokio::test]
    async fn update_indicator_refusals_carry_codes() {
        let f = fixture().await;
        {
            let store = f.schema.store();
            insert_indicator(&store, "free", f.model_a);
            insert_indicator(&store, "by-detector", f.model_a);
            insert_indicator(&store, "by-definition", f.model_a);
            name_in_applied_document(&store, &f.instance, 7, "model-a", "by-detector");
            insert_definition(
                &store,
                "definition-a",
                CUSTOMER_A,
                &f.instance,
                "by-definition",
            );
        }
        let node_id = f.instance.node_id.to_string();

        for query in [
            update("missing", f.model_a, "changed"),
            update("by-detector", f.model_a, "changed"),
            update("by-definition", f.model_a, "changed"),
            update("free", f.model_b, "changed"),
        ] {
            let res = f.schema.execute_as_system_admin(&query).await;
            let (message, extensions) = single_error(&res);
            if query.contains("\"missing\"") {
                assert_eq!(
                    extensions,
                    json!({ "code": "NOT_FOUND", "field": "name", "value": "missing" })
                );
            } else if query.contains("\"by-detector\"") {
                assert_eq!(
                    extensions,
                    json!({
                        "code": "INDICATOR_IN_USE",
                        "field": "name",
                        "value": "by-detector",
                        "detectorId": 7,
                        "nodeId": node_id,
                        "agentKey": TEST_AGENT_KEY,
                    })
                );
                assert!(message.contains(&node_id), "{message}");
                assert!(message.contains(TEST_AGENT_KEY), "{message}");
            } else if query.contains("\"by-definition\"") {
                assert_eq!(
                    extensions,
                    json!({
                        "code": "INDICATOR_IN_USE",
                        "field": "name",
                        "value": "by-definition",
                        "definition": "definition-a",
                    })
                );
            } else {
                assert_eq!(
                    extensions,
                    json!({
                        "code": "INDICATOR_MODEL_CHANGE",
                        "field": "model_id",
                        "value": f.model_b.to_string(),
                    })
                );
            }
        }
        for name in ["free", "by-detector", "by-definition"] {
            let expected = format!("indicator {name}");
            assert_eq!(
                description(&f.schema, name).as_deref(),
                Some(expected.as_str())
            );
        }
        assert_eq!(description(&f.schema, "missing"), None);
    }

    #[tokio::test]
    async fn insert_indicator_over_an_existing_name_is_an_update() {
        let f = fixture().await;
        {
            let store = f.schema.store();
            insert_indicator(&store, "free", f.model_a);
            insert_indicator(&store, "held", f.model_a);
            insert_definition(&store, "definition-a", CUSTOMER_A, &f.instance, "held");
        }

        let res = f
            .schema
            .execute_as_system_admin(&insert("held", f.model_a, "changed"))
            .await;
        assert_eq!(
            single_error(&res).1,
            json!({
                "code": "INDICATOR_IN_USE",
                "field": "name",
                "value": "held",
                "definition": "definition-a",
            })
        );
        let res = f
            .schema
            .execute_as_system_admin(&insert("free", f.model_b, "changed"))
            .await;
        assert_eq!(
            single_error(&res).1,
            json!({
                "code": "INDICATOR_MODEL_CHANGE",
                "field": "model_id",
                "value": f.model_b.to_string(),
            })
        );
        assert_eq!(
            description(&f.schema, "held").as_deref(),
            Some("indicator held")
        );
        assert_eq!(
            description(&f.schema, "free").as_deref(),
            Some("indicator free")
        );

        let res = f
            .schema
            .execute_as_system_admin(&insert("free", f.model_a, "changed"))
            .await;
        assert_eq!(data(res), json!({ "insertIndicator": "free" }));
        assert_eq!(description(&f.schema, "free").as_deref(), Some("changed"));
        let res = f
            .schema
            .execute_as_system_admin(&insert("new", MISSING_MODEL, "new"))
            .await;
        assert_eq!(data(res), json!({ "insertIndicator": "new" }));
        assert_eq!(description(&f.schema, "new").as_deref(), Some("new"));
    }

    #[tokio::test]
    async fn remove_indicator_removes_all_or_none() {
        let f = fixture().await;
        {
            let store = f.schema.store();
            insert_indicator(&store, "free", f.model_a);
            insert_indicator(&store, "held", f.model_a);
            name_in_applied_document(&store, &f.instance, 3, "model-a", "held");
        }

        let res = f
            .schema
            .execute_as_system_admin(&remove(&["free", "held", "missing"]))
            .await;
        assert_eq!(
            single_error(&res).1,
            json!({
                "code": "INDICATOR_IN_USE",
                "field": "name",
                "value": "held",
                "detectorId": 3,
                "nodeId": f.instance.node_id.to_string(),
                "agentKey": TEST_AGENT_KEY,
            })
        );
        assert!(description(&f.schema, "free").is_some());
        assert!(description(&f.schema, "held").is_some());

        let res = f
            .schema
            .execute_as_system_admin(&remove(&["missing", "free"]))
            .await;
        assert_eq!(data(res), json!({ "removeIndicator": ["missing", "free"] }));
        assert_eq!(description(&f.schema, "free"), None);
        assert!(description(&f.schema, "held").is_some());
    }

    #[tokio::test]
    async fn indicator_writes_wait_for_the_engine_config_lock() {
        let f = fixture().await;
        {
            let store = f.schema.store();
            insert_indicator(&store, "updated", f.model_a);
            insert_indicator(&store, "removed", f.model_a);
        }
        let schema = &f.schema;

        for query in [
            update("updated", f.model_a, "changed"),
            remove(&["removed"]),
        ] {
            let stored = |schema: &TestSchema| {
                (
                    description(schema, "updated"),
                    description(schema, "removed"),
                )
            };
            let before = stored(schema);
            let guard = schema.hold_engine_config_lock().await;
            let query = query.as_str();
            let (res, ()) = tokio::join!(schema.execute_as_system_admin(query), async move {
                // Waits until the write waits for the lock the test holds.
                while schema.engine_config_lock_users() < 2 {
                    tokio::task::yield_now().await;
                }
                assert_eq!(stored(schema), before, "{query}");
                drop(guard);
            });
            assert!(res.errors.is_empty(), "{res:?}");
            assert_eq!(schema.engine_config_lock_users(), 0);
        }
        assert_eq!(description(schema, "updated").as_deref(), Some("changed"));
        assert_eq!(description(schema, "removed"), None);
    }
}
