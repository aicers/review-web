use async_graphql::{Context, Object, Result, StringNumber};
use chrono::{DateTime, Utc};
use review_database::{self as database};

use crate::graphql::{Role, RoleGuard};

#[derive(Default)]
pub(super) struct IndicatorQuery;

#[Object]
impl IndicatorQuery {
    /// Look up an Indicator by the given name.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn indicator(&self, ctx: &Context<'_>, name: String) -> Result<Option<ModelIndicator>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.model_indicator_map();
        map.get(&name)
            .map(|indicator| indicator.map(Into::into))
            .map_err(Into::into)
    }

    /// A list of Indicators.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn indicator_list(&self, ctx: &Context<'_>) -> Result<Vec<ModelIndicator>> {
        use database::Iterable;

        let store = super::get_store(ctx).await?;
        let map = store.model_indicator_map();
        map.iter(database::Direction::Forward, None)
            .map(|res| res.map(Into::into).map_err(Into::into))
            .collect()
    }
}

#[derive(Default)]
pub(super) struct IndicatorMutation;

#[Object]
impl IndicatorMutation {
    /// Inserts a new Indicator, overwriting any existing Indicator if same name and version exist already.
    /// Returns the inserted db's name and version.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_indicator(
        &self,
        ctx: &Context<'_>,
        name: String,
        dbfile: String,
    ) -> Result<String> {
        let indicator = database::ModelIndicator::new(&name, &dbfile)?;
        let store = super::get_store(ctx).await?;
        let map = store.model_indicator_map();
        map.insert(indicator).map_err(Into::into).map(|()| name)
    }

    /// Removes Indicator, returning the db's name and version that no longer exist.
    ///
    /// On error, some Indicators may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_indicator(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] names: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = super::get_store(ctx).await?;
        let map = store.model_indicator_map();

        let count = names.len();
        let removed = names
            .into_iter()
            .try_fold(Vec::with_capacity(count), |mut removed, name| {
                if map.remove(std::iter::once(name.as_str())).is_ok() {
                    removed.push(name);
                    Ok(removed)
                } else {
                    Err(removed)
                }
            })
            .unwrap_or_else(|removed| removed);

        if removed.is_empty() {
            return Err("None of the specified indicators were removed.".into());
        }

        if removed.len() < count {
            return Err("Some indicators were removed, but not all.".into());
        }

        Ok(removed)
    }

    /// Updates the given indicator, returning the indicator name that was updated.
    ///
    /// Will return error if it failed to access database
    /// Will return error if it failed to delete or add indicator into database
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_indicator(
        &self,
        ctx: &Context<'_>,
        name: String,
        new: String,
    ) -> Result<String> {
        let indicator = database::ModelIndicator::new(&name, &new)?;
        let store = super::get_store(ctx).await?;
        let map = store.model_indicator_map();
        map.update(indicator).map_err(Into::into).map(|()| name)
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
    async fn model_id(&self) -> i32 {
        self.inner.model_id
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
