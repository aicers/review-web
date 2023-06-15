use super::{customer::HostNetworkGroup, event::EndpointInput, Role, RoleGuard};
use anyhow::{anyhow, Context as AnyhowContext};
use async_graphql::{Context, Enum, InputObject, Object, Result, SimpleObject, ID};
use bincode::Options;
use review_database::{self as database};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Default)]
pub(super) struct FilterQuery;

#[Object]
impl FilterQuery {
    /// A list of filters
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn filter_list(&self, ctx: &Context<'_>) -> Result<Vec<Filter>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.filter_map();
        let username = ctx.data::<String>()?;
        let mut filters = if let Some(value) = map.get(username.as_bytes())? {
            bincode::DefaultOptions::new()
                .deserialize::<HashMap<String, database::Filter>>(value.as_ref())
                .map_err(|e| format!("corrupt filter entry for account \"{username}\": {e}"))?
                .into_values()
                .map(std::convert::Into::into)
                .collect::<Vec<Filter>>()
        } else {
            return Ok(Vec::new());
        };
        filters.sort_unstable_by(|a, b| a.inner.name.cmp(&b.inner.name));
        Ok(filters)
    }

    /// A filter for the given name.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn filter(&self, ctx: &Context<'_>, name: String) -> Result<Option<Filter>> {
        let db = crate::graphql::get_store(ctx).await?;
        let username = ctx.data::<String>()?;
        let map = db.filter_map();
        let mut filters = if let Some(value) = map.get(username.as_bytes())? {
            bincode::DefaultOptions::new()
                .deserialize::<HashMap<String, database::Filter>>(value.as_ref())
                .map_err(|e| format!("corrupt filter entry for account \"{username}\": {e}"))?
        } else {
            return Ok(None);
        };
        Ok(filters.remove(&name).map(Into::into))
    }
}

#[derive(Default)]
pub(super) struct FilterMutation;

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
        host_names: Option<Vec<String>>,
        user_ids: Option<Vec<String>>,
        user_names: Option<Vec<String>>,
        user_departments: Option<Vec<String>>,
        countries: Option<Vec<String>>,
        categories: Option<Vec<u8>>,
        levels: Option<Vec<u8>>,
        kinds: Option<Vec<String>>,
        learning_methods: Option<Vec<LearningMethod>>,
        confidence: Option<f32>,
    ) -> Result<String> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.filter_map();
        let account = ctx.data::<String>()?;
        let codec = bincode::DefaultOptions::new();
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
        let new_filter = database::Filter {
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
            host_names,
            user_ids,
            user_names,
            user_departments,
            countries,
            categories,
            levels,
            kinds,
            learning_methods: learning_methods.map(|v| v.into_iter().map(Into::into).collect()),
            confidence,
        };

        if let Some(old_value) = map.get(account.as_bytes())? {
            let mut filters = codec
                .deserialize::<HashMap<String, database::Filter>>(old_value.as_ref())
                .map_err(|e| format!("corrupt filter entry for account \"{account}\": {e}"))?;
            if filters.contains_key(&name) {
                return Err(format!("filter \"{name}\" already exists").into());
            }
            filters.insert(name.clone(), new_filter);
            let new_value = codec.serialize(&filters)?;
            map.update(
                (account.as_bytes(), old_value.as_ref()),
                (account.as_bytes(), &new_value),
            )?;
        } else {
            let mut filters = HashMap::new();
            filters.insert(name.clone(), new_filter);
            map.insert(account.as_bytes(), &codec.serialize(&filters)?)?;
        };
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
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.filter_map();
        let username = ctx.data::<String>()?;
        let codec = bincode::DefaultOptions::new();

        let Some(old_value) = map.get(username.as_bytes())? else {
            return Ok(names);
        };
        let mut filters = codec
            .deserialize::<HashMap<String, database::Filter>>(old_value.as_ref())
            .map_err(|e| format!("corrupt filter entry for account \"{username}\": {e}"))?;
        for name in &names {
            filters.remove(name);
        }
        let new_value = codec.serialize(&filters)?;
        map.update(
            (username.as_bytes(), old_value.as_ref()),
            (username.as_bytes(), &new_value),
        )?;
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
        let new = database::Filter::try_from(new)?;

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.filter_map();
        let username = ctx.data::<String>()?;
        let codec = bincode::DefaultOptions::new();

        let Some(old_value) = map.get(username.as_bytes())? else {
            return Err("no such filter".into());
        };
        let mut filters = codec
            .deserialize::<HashMap<String, database::Filter>>(old_value.as_ref())
            .map_err(|e| format!("corrupt filter entry for account \"{username}\": {e}"))?;
        let Some(old_filter) = filters.get(&old.name) else {
            return Err("no such filter".into());
        };
        if old_filter != old {
            return Err("filter does not match".into());
        }

        filters.remove(&old.name);
        filters.insert(new.name.clone(), new);
        let new_value = codec.serialize(&filters)?;
        map.update(
            (username.as_bytes(), old_value.as_ref()),
            (username.as_bytes(), &new_value),
        )?;
        Ok(old.name)
    }
}

#[derive(Clone, Copy, Enum, Eq, PartialEq, Deserialize, Serialize)]
enum EndpointKind {
    Source,
    Destination,
    Both,
}

struct Endpoint<'a> {
    inner: &'a database::FilterEndpoint,
}

impl PartialEq<EndpointInput> for database::FilterEndpoint {
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

impl TryFrom<EndpointInput> for database::FilterEndpoint {
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

    async fn custom(&self) -> Option<HostNetworkGroup> {
        self.inner.custom.as_ref().map(Into::into)
    }
}

impl<'a> From<&'a database::FilterEndpoint> for Endpoint<'a> {
    fn from(inner: &'a database::FilterEndpoint) -> Self {
        Self { inner }
    }
}

#[derive(Clone, Deserialize, Serialize, SimpleObject)]
struct NetworkInputPoint {
    network: String,
    endpoint_kind: EndpointKind,
}

impl From<NetworkInputPointInput> for NetworkInputPoint {
    fn from(input: NetworkInputPointInput) -> Self {
        Self {
            network: input.network,
            endpoint_kind: input.endpoint_kind,
        }
    }
}

impl PartialEq<NetworkInputPointInput> for NetworkInputPoint {
    fn eq(&self, other: &NetworkInputPointInput) -> bool {
        self.network == other.network && self.endpoint_kind == other.endpoint_kind
    }
}

struct Filter {
    inner: database::Filter,
}

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

    async fn endpoints(&self) -> Option<Vec<Endpoint>> {
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

    async fn host_names(&self) -> Option<Vec<&str>> {
        self.inner
            .host_names
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

    async fn confidence(&self) -> Option<f32> {
        self.inner.confidence
    }
}

impl From<database::Filter> for Filter {
    fn from(filter: database::Filter) -> Self {
        Self { inner: filter }
    }
}

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
            host_names: input.host_names,
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
            confidence: input.confidence,
        })
    }
}

impl PartialEq<FilterInput> for &database::Filter {
    fn eq(&self, rhs: &FilterInput) -> bool {
        let network_eq = match (&self.endpoints, &rhs.endpoints) {
            (Some(lhs), Some(rhs)) => lhs.iter().zip(rhs.iter()).all(|(lhs, rhs)| *lhs == *rhs),
            (None, None) => true,
            _ => false,
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
            && cmp_option_vec_string_with_id(&self.network_tags, &rhs.network_tags)
            && cmp_option_vec_string_with_id(&self.customers, &rhs.customers)
            && network_eq
            && cmp_option_vec_string_with_id(&self.sensors, &rhs.sensors)
            && cmp_option_vec_string_with_id(&self.os, &rhs.os)
            && cmp_option_vec_string_with_id(&self.devices, &rhs.devices)
            && self.host_names == rhs.host_names
            && self.user_ids == rhs.user_ids
            && self.user_names == rhs.user_names
            && self.user_departments == rhs.user_departments
            && self.countries == rhs.countries
            && self.categories == rhs.categories
            && self.levels == rhs.levels
            && self.kinds == rhs.kinds
    }
}

/// Traffic flow direction.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "database::FlowKind")]
pub(super) enum FlowKind {
    Inbound,
    Outbound,
    Internal,
}

/// Learning method.
#[derive(Clone, Copy, Enum, Eq, PartialEq)]
#[graphql(remote = "database::LearningMethod")]
pub(super) enum LearningMethod {
    Unsupervised,
    SemiSupervised,
}

#[derive(InputObject)]
struct NetworkInputPointInput {
    network: String,
    endpoint_kind: EndpointKind,
}

#[derive(InputObject)]
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
    host_names: Option<Vec<String>>,
    user_ids: Option<Vec<String>>,
    user_names: Option<Vec<String>>,
    user_departments: Option<Vec<String>>,
    countries: Option<Vec<String>>,
    categories: Option<Vec<u8>>,
    levels: Option<Vec<u8>>,
    kinds: Option<Vec<String>>,
    learning_methods: Option<Vec<LearningMethod>>,
    confidence: Option<f32>,
}

#[derive(Enum, Copy, Clone, Eq, PartialEq)]
#[graphql(remote = "database::TrafficDirection")]
pub(super) enum TrafficDirection {
    From,
    To,
}

fn cmp_option_vec_string_with_id(lhs: &Option<Vec<String>>, rhs: &Option<Vec<ID>>) -> bool {
    match (lhs, rhs) {
        (Some(lhs), Some(rhs)) => lhs
            .iter()
            .zip(rhs.iter())
            .all(|(lhs, rhs)| lhs.as_str() == rhs.as_str()),
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn filter() {
        let schema = TestSchema::new().await;
        let res = schema.execute(r#"{filterList{name}}"#).await;
        assert_eq!(res.data.to_string(), r#"{filterList: []}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertFilter(name: "foo", directions: [INBOUND, OUTBOUND])
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertFilter: "foo"}"#);

        let res = schema.execute(r#"{filterList{name}}"#).await;
        assert_eq!(res.data.to_string(), r#"{filterList: [{name: "foo"}]}"#);

        let res = schema.execute(
            r#"mutation {
                replaceFilter(old: {name: "foo", directions: [INBOUND, OUTBOUND]}, new: {name: "foo", directions: [INBOUND]})
            }"#,
        ).await;
        assert_eq!(res.data.to_string(), r#"{replaceFilter: "foo"}"#);

        let res = schema.execute(r#"{filter(name: "foo"){directions}}"#).await;
        assert_eq!(res.data.to_string(), r#"{filter: {directions: [INBOUND]}}"#);

        let res = schema
            .execute(r#"mutation {removeFilters(names: ["foo"])}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeFilters: ["foo"]}"#);
    }
}
