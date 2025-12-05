use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, InputObject, Object, Result,
    connection::{Connection, EmptyFields},
    types::ID,
};
use chrono::{DateTime, Utc};
use itertools::Itertools;
use tracing::info;

use super::{Role, RoleGuard};
use crate::graphql::{
    cluster::try_id_args_into_ints, network::id_args_into_uints, query_with_constraints,
};
use crate::info_with_username;

#[allow(clippy::module_name_repetitions)]
pub struct TriageResponse {
    inner: review_database::TriageResponse,
}

impl From<review_database::TriageResponse> for TriageResponse {
    fn from(inner: review_database::TriageResponse) -> Self {
        Self { inner }
    }
}

#[Object]
impl TriageResponse {
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    async fn remarks(&self) -> &str {
        &self.inner.remarks
    }

    async fn tag_ids(&self) -> Vec<ID> {
        self.inner
            .tag_ids()
            .iter()
            .map(Into::into)
            .collect::<Vec<_>>()
    }
}

struct TriageResponseTotalCount;

#[Object]
impl TriageResponseTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        use review_database::{Iterable, event::Direction};

        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_response_map();
        Ok(map.iter(Direction::Forward, None).count())
    }
}

#[derive(Clone, InputObject)]
pub(super) struct TriageResponseInput {
    key: Vec<u8>,
    tag_ids: Option<Vec<ID>>,
    remarks: Option<String>,
}

impl TryFrom<TriageResponseInput> for review_database::TriageResponseUpdate {
    type Error = async_graphql::Error;

    fn try_from(input: TriageResponseInput) -> Result<Self, Self::Error> {
        let tag_ids = try_id_args_into_ints::<u32>(input.tag_ids)?;
        Ok(Self::new(input.key, tag_ids, input.remarks))
    }
}

#[Object]
impl super::TriageResponseQuery {
    /// A list of triage responses.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn triage_response_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<
        Connection<OpaqueCursor<Vec<u8>>, TriageResponse, TriageResponseTotalCount, EmptyFields>,
    > {
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    /// Looks up a triage response by the given id.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn triage_response(
        &self,
        ctx: &Context<'_>,
        sensor: String,
        time: DateTime<Utc>,
    ) -> Result<Option<TriageResponse>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_response_map();
        let response: Option<TriageResponse> = map.get(&sensor, &time)?.map(Into::into);

        if let Some(ref triage_response) = response {
            let tag_ids_str = triage_response.inner.tag_ids().iter().join(", ");
            info_with_username!(
                ctx,
                "Retrieved TriageResponse: id: {}, sensor: \"{}\", time: {}, tag_ids: [{}], remarks: \"{}\"",
                triage_response.inner.id,
                sensor,
                time,
                tag_ids_str,
                triage_response.inner.remarks
            );
        } else {
            info_with_username!(
                ctx,
                "No TriageResponse found for sensor: \"{}\", time: {}",
                sensor,
                time
            );
        }

        Ok(response)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, TriageResponse, TriageResponseTotalCount, EmptyFields>>
{
    let store = crate::graphql::get_store(ctx)?;
    let table = store.triage_response_map();
    crate::graphql::load_edges(&table, after, before, first, last, TriageResponseTotalCount)
}

#[Object]
impl super::TriageResponseMutation {
    /// Inserts a new triage response, returning the ID of the new node.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_triage_response(
        &self,
        ctx: &Context<'_>,
        sensor: String,
        time: DateTime<Utc>,
        tag_ids: Vec<ID>,
        remarks: String,
    ) -> Result<ID> {
        let tag_ids_converted = id_args_into_uints(&tag_ids)?;
        let tag_ids_str = tag_ids_converted.iter().join(", ");
        let pol = review_database::TriageResponse::new(
            sensor.clone(),
            time,
            tag_ids_converted,
            remarks.clone(),
        );
        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_response_map();
        let id = map.put(pol)?;
        info_with_username!(
            ctx,
            "Triage response has been registered: id: {}, sensor: \"{}\", time: {}, tag_ids: [{}], remarks: \"{}\"",
            id,
            sensor,
            time,
            tag_ids_str,
            remarks
        );
        Ok(ID(id.to_string()))
    }

    /// Removes triage responses, returning the IDs that no longer exist.
    ///
    /// On error, some triage responses may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_triage_responses(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_response_map();

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let _key = map.remove(i)?;
            info_with_username!(ctx, "Triage response {i} has been deleted");

            removed.push(i.to_string());
        }

        Ok(removed)
    }

    /// Updates an existing triage response.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_triage_response(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: TriageResponseInput,
        new: TriageResponseInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let old_tag_ids_str = old.tag_ids.as_ref().map_or_else(
            || "None".to_string(),
            |ids| ids.iter().map(|id| id.as_str()).join(", "),
        );
        let new_tag_ids_str = new.tag_ids.as_ref().map_or_else(
            || "None".to_string(),
            |ids| ids.iter().map(|id| id.as_str()).join(", "),
        );
        let old_remarks_str = old.remarks.as_deref().unwrap_or("None").to_string();
        let new_remarks_str = new.remarks.as_deref().unwrap_or("None").to_string();

        let store = crate::graphql::get_store(ctx)?;
        let mut map = store.triage_response_map();
        let old_update: review_database::TriageResponseUpdate = old.try_into()?;
        let new_update: review_database::TriageResponseUpdate = new.try_into()?;
        map.update(i, &old_update, &new_update)?;
        info_with_username!(
            ctx,
            "Updated TriageResponse: id: {}, old_tag_ids: [{}], new_tag_ids: [{}], old_remarks: \"{}\", new_remarks: \"{}\"",
            i,
            old_tag_ids_str,
            new_tag_ids_str,
            old_remarks_str,
            new_remarks_str
        );

        Ok(id)
    }
}
