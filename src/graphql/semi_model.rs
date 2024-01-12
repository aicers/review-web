use super::{BoxedAgentManager, Role, RoleGuard};
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, InputObject, Object, Result, SimpleObject,
};
use bincode::Options;
use chrono::{DateTime, Utc};
use database::types::FromKeyValue;
use review_database::{self as database, IterableMap, Store};
use serde::{Deserialize, Serialize};

#[derive(Default)]
pub(super) struct SemiModelQuery;

#[Object]
impl SemiModelQuery {
    /// A list of semi-supervised model list.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn semi_model_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, SemiModelInfo, SemiModelInfoTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }
}

#[derive(Default)]
pub(super) struct SemiModelMutation;

#[Object]
impl SemiModelMutation {
    /// Inserts a new semi-supervised model, Returns true if the insertion was successful.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_semi_model(&self, ctx: &Context<'_>, input_model: SemiModel) -> Result<bool> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.semi_models_map();

        let key = input_model.model_name.clone();
        let value = bincode::serialize::<SemiModelValue>(&(input_model, Utc::now()))?;
        map.put(key.as_bytes(), &value)?;
        Ok(true)
    }

    /// Removes a semi-supervised models using model name , Returns true if the deletion was successful.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_semi_models(&self, ctx: &Context<'_>, models: Vec<String>) -> Result<bool> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.semi_models_map();
        for model in models {
            map.delete(model.as_bytes())?;
        }
        Ok(true)
    }

    /// Download semi-supervised models using model name , Returns true if the deletion was successful.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn download_semi_models(
        &self,
        ctx: &Context<'_>,
        input_models: Vec<SemiModel>,
    ) -> Result<bool> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.semi_models_map();

        let iter = map.iter_forward()?;
        for (key, _) in iter {
            map.delete(&key)?;
        }
        for model in input_models {
            let key = model.model_name.clone();
            let value = bincode::serialize::<SemiModelValue>(&(model, Utc::now()))?;
            map.put(key.as_bytes(), &value)?;
        }
        Ok(true)
    }

    /// Broadcast the semi-supervised model list to all Hogs.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn apply_semi_model(&self, ctx: &Context<'_>) -> Result<bool> {
        let store = crate::graphql::get_store(ctx).await?;
        let list = get_semi_model_list(&store)?;
        let serialized_semi_model = bincode::DefaultOptions::new().serialize(&list)?;
        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        agent_manager
            .broadcast_semi_model_list(&serialized_semi_model)
            .await?;
        Ok(true)
    }
}
type SemiModelValue = (SemiModel, DateTime<Utc>);

#[derive(InputObject, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
struct SemiModel {
    model_type: i32,
    model_name: String,
    model_version: String,
    model_description: String,
    model_data: Vec<u8>,
}

#[derive(SimpleObject, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct SemiModelInfo {
    model_type: i32,
    model_name: String,
    model_version: String,
    model_description: String,
    model_data: Vec<u8>,
    time: DateTime<Utc>,
}

impl SemiModelInfo {
    fn new(semi_model: SemiModel, time: DateTime<Utc>) -> Self {
        Self {
            model_type: semi_model.model_type,
            model_name: semi_model.model_name,
            model_version: semi_model.model_version,
            model_description: semi_model.model_description,
            time,
            model_data: semi_model.model_data,
        }
    }
}

impl FromKeyValue for SemiModelInfo {
    fn from_key_value(_key: &[u8], value: &[u8]) -> Result<Self, anyhow::Error> {
        let (semi_info, time) = bincode::deserialize::<SemiModelValue>(value)?;
        Ok(SemiModelInfo::new(semi_info, time))
    }
}

struct SemiModelInfoTotalCount;

#[Object]
impl SemiModelInfoTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.semi_models_map();
        let count = map.iter_forward()?.count();
        Ok(count)
    }
}

/// Returns the semi supervised model list.
///
/// # Errors
///
/// Returns an error if semi supervised model database could not be retrieved.
pub fn get_semi_model_list(db: &Store) -> Result<Vec<SemiModelInfo>> {
    let map = db.semi_models_map();
    let mut semi_model_list = vec![];
    for (_, value) in map.iter_forward()? {
        let (semi_info, time) = bincode::deserialize::<SemiModelValue>(&value)?;
        semi_model_list.push(SemiModelInfo::new(semi_info, time));
    }
    Ok(semi_model_list)
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, SemiModelInfo, SemiModelInfoTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.semi_models_map();
    super::load(&map, after, before, first, last, SemiModelInfoTotalCount)
}
