#[cfg(not(feature = "auth-mtls"))]
use anyhow::{Context as AnyhowContext, anyhow};
use async_graphql::Enum;
#[cfg(not(feature = "auth-mtls"))]
use async_graphql::{Context, ID, InputObject, Object, Result, SimpleObject};
#[cfg(not(feature = "auth-mtls"))]
use chrono::{DateTime, Utc};
use review_database::{self as database};
#[cfg(not(feature = "auth-mtls"))]
use serde::{Deserialize, Serialize};

#[cfg(not(feature = "auth-mtls"))]
use super::{Role, RoleGuard, customer::HostNetworkGroup, event::EndpointInput};

#[cfg(not(feature = "auth-mtls"))]
#[derive(Clone, Eq, PartialEq, InputObject)]
pub(super) struct PeriodForSearchInput {
    recent: Option<String>,
    custom: Option<PeriodInput>,
}

#[cfg(not(feature = "auth-mtls"))]
#[derive(Clone, Eq, PartialEq, InputObject)]
pub(super) struct PeriodInput {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

#[cfg(not(feature = "auth-mtls"))]
impl From<PeriodForSearchInput> for database::PeriodForSearch {
    fn from(input: PeriodForSearchInput) -> Self {
        match (input.recent, input.custom) {
            (None, Some(custom)) => database::PeriodForSearch::Custom(custom.start, custom.end),
            (Some(recent), Some(_) | None) => database::PeriodForSearch::Recent(recent), // Prefer recent if both provided
            (None, None) => database::PeriodForSearch::Recent("1 hour".to_string()), // Default to 1 hour
        }
    }
}

#[cfg(not(feature = "auth-mtls"))]
#[derive(Default)]
pub(super) struct FilterQuery;

#[cfg(not(feature = "auth-mtls"))]
#[Object]
impl FilterQuery {
    /// A list of filters
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn filter_list(&self, ctx: &Context<'_>) -> Result<Vec<Filter>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.filter_map();
        let username = ctx.data::<String>()?;
        Ok(map.list(username)?.into_iter().map(Into::into).collect())
    }

    /// A filter for the given name.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn filter(&self, ctx: &Context<'_>, name: String) -> Result<Option<Filter>> {
        let db = crate::graphql::get_store(ctx)?;
        let username = ctx.data::<String>()?;
        let map = db.filter_map();

        Ok(map.get(username, &name)?.map(Into::into))
    }
}

#[cfg(not(feature = "auth-mtls"))]
#[derive(Default)]
pub(super) struct FilterMutation;

#[cfg(not(feature = "auth-mtls"))]
#[Object]
impl FilterMutation {
    /// Inserts a new filter to the current account.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    #[allow(clippy::too_many_arguments)]
    async fn insert_filter(
        &self,
        ctx: &Context<'_>,
        name: String,
        directions: Option<Vec<FlowKind>>,
        keywords: Option<Vec<String>>,
        network_tags: Option<Vec<ID>>,
        customers: Option<Vec<ID>>,
        endpoints: Option<Vec<EndpointInput>>,
        sensors: Option<Vec<ID>>,
        os: Option<Vec<ID>>,
        devices: Option<Vec<ID>>,
        hostnames: Option<Vec<String>>,
        user_ids: Option<Vec<String>>,
        user_names: Option<Vec<String>>,
        user_departments: Option<Vec<String>>,
        countries: Option<Vec<String>>,
        categories: Option<Vec<u8>>,
        levels: Option<Vec<u8>>,
        kinds: Option<Vec<String>>,
        learning_methods: Option<Vec<LearningMethod>>,
        confidence_min: Option<f32>,
        confidence_max: Option<f32>,
        period: Option<PeriodForSearchInput>,
    ) -> Result<String> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.filter_map();
        let username = ctx.data::<String>()?;
        let endpoints = if let Some(endpoints_input) = endpoints {
            let mut endpoints = Vec::with_capacity(endpoints_input.len());
            for endpoint_input in endpoints_input {
                let endpoint = endpoint_input.try_into()?;
                endpoints.push(endpoint);
            }
            Some(endpoints)
        } else {
            None
        };
        let filter = database::Filter {
            username: username.clone(),
            name: name.clone(),
            directions: directions.map(|v| v.into_iter().map(Into::into).collect()),
            keywords,
            network_tags: network_tags
                .map(|ids| ids.into_iter().map(Into::into).collect::<Vec<_>>()),
            customers: customers
                .map(|values| values.into_iter().map(Into::into).collect::<Vec<_>>()),
            endpoints,
            sensors: sensors.map(|values| values.into_iter().map(Into::into).collect::<Vec<_>>()),
            os: os.map(|values| values.into_iter().map(Into::into).collect::<Vec<_>>()),
            devices: devices.map(|values| values.into_iter().map(Into::into).collect::<Vec<_>>()),
            hostnames,
            user_ids,
            user_names,
            user_departments,
            countries,
            categories,
            levels,
            kinds,
            learning_methods: learning_methods.map(|v| v.into_iter().map(Into::into).collect()),
            confidence_min,
            confidence_max,
            period: period.map_or_else(
                || database::PeriodForSearch::Recent("1 hour".to_string()),
                Into::into,
            ),
        };

        map.insert(filter)?;

        Ok(name)
    }

    /// Removes filters, returning the filter names that no longer exist.
    ///
    /// On error, some filters may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn remove_filters(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] names: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.filter_map();
        let username = ctx.data::<String>()?;
        map.remove(username, names.iter().map(String::as_str))?;
        Ok(names)
    }

    /// Updates the given filter, returning the filter name that was updated.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn replace_filter(
        &self,
        ctx: &Context<'_>,
        old: FilterInput,
        new: FilterInput,
    ) -> Result<String> {
        let store = crate::graphql::get_store(ctx)?;
        let table = store.filter_map();
        let username = ctx.data::<String>()?;

        let mut new = database::Filter::try_from(new)?;
        new.username.clone_from(username);

        let Some(old_filter) = table.get(username, &old.name)? else {
            return Err("no such filter".into());
        };

        if &old_filter != old {
            return Err("filter does not match".into());
        }

        table.remove(username, std::iter::once(old.name.as_str()))?;
        table.insert(new)?;

        Ok(old.name)
    }
}

#[cfg(not(feature = "auth-mtls"))]
#[derive(Clone, Copy, Enum, Eq, PartialEq, Deserialize, Serialize)]
enum EndpointKind {
    Source,
    Destination,
    Both,
}

#[cfg(not(feature = "auth-mtls"))]
struct Endpoint<'a> {
    inner: &'a database::event::FilterEndpoint,
}

#[cfg(not(feature = "auth-mtls"))]
impl PartialEq<EndpointInput> for database::event::FilterEndpoint {
    fn eq(&self, other: &EndpointInput) -> bool {
        let other_predefined = if let Some(id) = &other.predefined {
            if let Ok(id) = id.parse() {
                Some(id)
            } else {
                return false;
            }
        } else {
            None
        };
        let other_custom = if let Some(network) = &other.custom {
            if let Ok(network) = network.try_into() {
                Some(network)
            } else {
                return false;
            }
        } else {
            None
        };
        self.direction == other.direction.map(Into::into)
            && self.predefined == other_predefined
            && self.custom == other_custom
    }
}

#[cfg(not(feature = "auth-mtls"))]
impl TryFrom<EndpointInput> for database::event::FilterEndpoint {
    type Error = anyhow::Error;

    fn try_from(input: EndpointInput) -> anyhow::Result<Self> {
        if let Some(id) = input.predefined {
            let id = id.parse().context("invalid ID")?;
            Ok(Self {
                direction: input.direction.map(Into::into),
                predefined: Some(id),
                custom: None,
            })
        } else if let Some(network) = input.custom {
            let network = network.try_into().context("invalid custom network")?;
            Ok(Self {
                direction: input.direction.map(Into::into),
                predefined: None,
                custom: Some(network),
            })
        } else {
            Err(anyhow!("endpoint must be predefined or custom"))
        }
    }
}

#[cfg(not(feature = "auth-mtls"))]
#[Object]
impl Endpoint<'_> {
    async fn direction(&self) -> Option<TrafficDirection> {
        self.inner.direction.map(Into::into)
    }

    /// Returns the network ID of the endpoint.
    #[graphql(name = "networkId")]
    async fn predefined(&self) -> Option<ID> {
        self.inner.predefined.map(|id| ID(id.to_string()))
    }

    async fn custom(&self) -> Option<HostNetworkGroup<'_>> {
        self.inner.custom.as_ref().map(Into::into)
    }
}

#[cfg(not(feature = "auth-mtls"))]
impl<'a> From<&'a database::event::FilterEndpoint> for Endpoint<'a> {
    fn from(inner: &'a database::event::FilterEndpoint) -> Self {
        Self { inner }
    }
}

#[cfg(not(feature = "auth-mtls"))]
struct PeriodForSearch<'a> {
    inner: &'a database::PeriodForSearch,
}

#[cfg(not(feature = "auth-mtls"))]
#[derive(Clone, Eq, PartialEq, SimpleObject)]
struct CustomPeriod {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

#[cfg(not(feature = "auth-mtls"))]
#[Object]
impl PeriodForSearch<'_> {
    async fn recent(&self) -> Option<String> {
        match self.inner {
            database::PeriodForSearch::Recent(recent) => Some(recent.clone()),
            database::PeriodForSearch::Custom(..) => None,
        }
    }

    async fn custom(&self) -> Option<CustomPeriod> {
        match self.inner {
            database::PeriodForSearch::Custom(start, end) => Some(CustomPeriod {
                start: *start,
                end: *end,
            }),
            database::PeriodForSearch::Recent(_) => None,
        }
    }
}

#[cfg(not(feature = "auth-mtls"))]
impl<'a> From<&'a database::PeriodForSearch> for PeriodForSearch<'a> {
    fn from(inner: &'a database::PeriodForSearch) -> Self {
        Self { inner }
    }
}

#[cfg(not(feature = "auth-mtls"))]
struct Filter {
    inner: database::Filter,
}

#[cfg(not(feature = "auth-mtls"))]
#[Object]
impl Filter {
    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn directions(&self) -> Option<Vec<FlowKind>> {
        self.inner.directions.as_deref().map(|directions| {
            directions
                .iter()
                .copied()
                .map(Into::into)
                .collect::<Vec<_>>()
        })
    }

    async fn keywords(&self) -> Option<&[String]> {
        self.inner.keywords.as_deref()
    }

    async fn network_tags(&self) -> Option<Vec<ID>> {
        self.inner
            .network_tags
            .as_ref()
            .map(|tags| tags.iter().map(Into::into).collect::<Vec<_>>())
    }

    async fn customers(&self) -> Option<Vec<ID>> {
        self.inner
            .customers
            .as_ref()
            .map(|customers| customers.iter().map(Into::into).collect::<Vec<_>>())
    }

    async fn endpoints(&self) -> Option<Vec<Endpoint<'_>>> {
        self.inner
            .endpoints
            .as_ref()
            .map(|endpoints| endpoints.iter().map(Into::into).collect::<Vec<_>>())
    }

    async fn sensors(&self) -> Option<Vec<ID>> {
        self.inner
            .sensors
            .as_ref()
            .map(|sensors| sensors.iter().map(Into::into).collect::<Vec<_>>())
    }

    async fn os(&self) -> Option<Vec<ID>> {
        self.inner
            .os
            .as_ref()
            .map(|os| os.iter().map(Into::into).collect::<Vec<_>>())
    }

    async fn devices(&self) -> Option<Vec<ID>> {
        self.inner
            .devices
            .as_ref()
            .map(|devices| devices.iter().map(Into::into).collect::<Vec<_>>())
    }

    async fn hostnames(&self) -> Option<Vec<&str>> {
        self.inner
            .hostnames
            .as_ref()
            .map(|names| names.iter().map(String::as_str).collect())
    }

    async fn user_ids(&self) -> Option<Vec<&str>> {
        self.inner
            .user_ids
            .as_ref()
            .map(|ids| ids.iter().map(String::as_str).collect())
    }

    async fn user_names(&self) -> Option<Vec<&str>> {
        self.inner
            .user_names
            .as_ref()
            .map(|names| names.iter().map(String::as_str).collect())
    }

    async fn user_departments(&self) -> Option<Vec<&str>> {
        self.inner
            .user_departments
            .as_ref()
            .map(|departments| departments.iter().map(String::as_str).collect())
    }

    async fn countries(&self) -> Option<Vec<&str>> {
        self.inner
            .countries
            .as_ref()
            .map(|countries| countries.iter().map(String::as_str).collect())
    }

    async fn categories(&self) -> Option<&Vec<u8>> {
        self.inner.categories.as_ref()
    }

    async fn levels(&self) -> Option<&Vec<u8>> {
        self.inner.levels.as_ref()
    }

    async fn kinds(&self) -> Option<Vec<&str>> {
        self.inner
            .kinds
            .as_ref()
            .map(|kinds| kinds.iter().map(String::as_str).collect())
    }

    async fn learning_methods(&self) -> Option<Vec<LearningMethod>> {
        self.inner
            .learning_methods
            .as_deref()
            .map(|learning_methods| {
                learning_methods
                    .iter()
                    .copied()
                    .map(Into::into)
                    .collect::<Vec<_>>()
            })
    }

    async fn confidence_min(&self) -> Option<f32> {
        self.inner.confidence_min
    }

    async fn confidence_max(&self) -> Option<f32> {
        self.inner.confidence_max
    }

    async fn period_for_search(&self) -> PeriodForSearch<'_> {
        (&self.inner.period).into()
    }
}

#[cfg(not(feature = "auth-mtls"))]
impl From<database::Filter> for Filter {
    fn from(filter: database::Filter) -> Self {
        Self { inner: filter }
    }
}

#[cfg(not(feature = "auth-mtls"))]
impl TryFrom<FilterInput> for database::Filter {
    type Error = anyhow::Error;

    fn try_from(input: FilterInput) -> anyhow::Result<Self> {
        let endpoints = if let Some(endpoints_input) = input.endpoints {
            let mut endpoints = Vec::with_capacity(endpoints_input.len());
            for endpoint_input in endpoints_input {
                endpoints.push(endpoint_input.try_into()?);
            }
            Some(endpoints)
        } else {
            None
        };
        Ok(Self {
            username: String::new(),
            name: input.name,
            directions: input
                .directions
                .map(|values| values.into_iter().map(Into::into).collect()),
            keywords: input.keywords,
            network_tags: input
                .network_tags
                .map(|values| values.into_iter().map(Into::into).collect()),
            customers: input
                .customers
                .map(|values| values.into_iter().map(Into::into).collect()),
            endpoints,
            sensors: input
                .sensors
                .map(|values| values.into_iter().map(Into::into).collect()),
            os: input
                .os
                .map(|values| values.into_iter().map(Into::into).collect()),
            devices: input
                .devices
                .map(|values| values.into_iter().map(Into::into).collect()),
            hostnames: input.hostnames,
            user_ids: input.user_ids,
            user_names: input.user_names,
            user_departments: input.user_departments,
            countries: input.countries,
            categories: input.categories,
            levels: input.levels,
            kinds: input.kinds,
            learning_methods: input
                .learning_methods
                .map(|values| values.into_iter().map(Into::into).collect()),
            confidence_min: input.confidence_min,
            confidence_max: input.confidence_max,
            period: input.period.map_or_else(
                || database::PeriodForSearch::Recent("1 hour".to_string()),
                Into::into,
            ),
        })
    }
}

#[cfg(not(feature = "auth-mtls"))]
impl PartialEq<FilterInput> for &database::Filter {
    fn eq(&self, rhs: &FilterInput) -> bool {
        let network_eq = match (&self.endpoints, &rhs.endpoints) {
            (Some(lhs), Some(rhs)) => lhs.iter().zip(rhs.iter()).all(|(lhs, rhs)| *lhs == *rhs),
            (None, None) => true,
            _ => false,
        };
        let period: database::PeriodForSearch = if let Some(rhs) = &rhs.period {
            rhs.clone().into()
        } else {
            database::PeriodForSearch::Recent("1 hour".to_string())
        };
        self.name == rhs.name
            && match (&self.directions, &rhs.directions) {
                (Some(lhs), Some(rhs)) => lhs
                    .iter()
                    .zip(rhs.iter())
                    .all(|(lhs, rhs)| FlowKind::from(*lhs) == *rhs),
                (None, None) => true,
                _ => false,
            }
            && self.keywords == rhs.keywords
            && cmp_option_vec_string_with_id(self.network_tags.as_ref(), rhs.network_tags.as_ref())
            && cmp_option_vec_string_with_id(self.customers.as_ref(), rhs.customers.as_ref())
            && network_eq
            && cmp_option_vec_string_with_id(self.sensors.as_ref(), rhs.sensors.as_ref())
            && cmp_option_vec_string_with_id(self.os.as_ref(), rhs.os.as_ref())
            && cmp_option_vec_string_with_id(self.devices.as_ref(), rhs.devices.as_ref())
            && self.hostnames == rhs.hostnames
            && self.user_ids == rhs.user_ids
            && self.user_names == rhs.user_names
            && self.user_departments == rhs.user_departments
            && self.countries == rhs.countries
            && self.categories == rhs.categories
            && self.levels == rhs.levels
            && self.kinds == rhs.kinds
            && self.period == period
    }
}

/// Traffic flow direction.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "database::event::FlowKind")]
pub(super) enum FlowKind {
    Inbound,
    Outbound,
    Internal,
}

/// Learning method.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "database::event::LearningMethod")]
pub(super) enum LearningMethod {
    Unsupervised,
    SemiSupervised,
}

#[derive(InputObject)]
#[cfg(not(feature = "auth-mtls"))]
struct FilterInput {
    name: String,
    directions: Option<Vec<FlowKind>>,
    keywords: Option<Vec<String>>,
    network_tags: Option<Vec<ID>>,
    customers: Option<Vec<ID>>,
    endpoints: Option<Vec<EndpointInput>>,
    sensors: Option<Vec<ID>>,
    os: Option<Vec<ID>>,
    devices: Option<Vec<ID>>,
    hostnames: Option<Vec<String>>,
    user_ids: Option<Vec<String>>,
    user_names: Option<Vec<String>>,
    user_departments: Option<Vec<String>>,
    countries: Option<Vec<String>>,
    categories: Option<Vec<u8>>,
    levels: Option<Vec<u8>>,
    kinds: Option<Vec<String>>,
    learning_methods: Option<Vec<LearningMethod>>,
    confidence_min: Option<f32>,
    confidence_max: Option<f32>,
    period: Option<PeriodForSearchInput>,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(remote = "database::event::TrafficDirection")]
pub(super) enum TrafficDirection {
    From,
    To,
}

#[cfg(not(feature = "auth-mtls"))]
fn cmp_option_vec_string_with_id(lhs: Option<&Vec<String>>, rhs: Option<&Vec<ID>>) -> bool {
    match (lhs, rhs) {
        (Some(lhs), Some(rhs)) => lhs
            .iter()
            .zip(rhs.iter())
            .all(|(lhs, rhs)| lhs.as_str() == rhs.as_str()),
        (None, None) => true,
        _ => false,
    }
}

#[cfg(all(test, not(feature = "auth-mtls")))]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn filter() {
        let schema = TestSchema::new().await;
        let res = schema.execute_as_system_admin(r"{filterList{name}}").await;
        assert_eq!(res.data.to_string(), r"{filterList: []}");

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertFilter(name: "foo", directions: [INBOUND, OUTBOUND])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertFilter: "foo"}"#);

        let res = schema.execute_as_system_admin(r"{filterList{name}}").await;
        assert_eq!(res.data.to_string(), r#"{filterList: [{name: "foo"}]}"#);

        let res = schema.execute_as_system_admin(
            r#"mutation {
                replaceFilter(old: {name: "foo", directions: [INBOUND, OUTBOUND]}, new: {name: "foo", directions: [INBOUND]})
            }"#,
        ).await;
        assert_eq!(res.data.to_string(), r#"{replaceFilter: "foo"}"#);

        let res = schema
            .execute_as_system_admin(r#"{filter(name: "foo"){directions}}"#)
            .await;
        assert_eq!(res.data.to_string(), r"{filter: {directions: [INBOUND]}}");

        let res = schema
            .execute_as_system_admin(r#"mutation {removeFilters(names: ["foo"])}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeFilters: ["foo"]}"#);
    }
}
