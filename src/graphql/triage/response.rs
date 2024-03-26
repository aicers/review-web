use super::{Role, RoleGuard};
use crate::graphql::validate_and_process_pagination_params;
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    types::ID,
    Context, InputObject, Object, Result,
};
use chrono::{DateTime, Utc};

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

    async fn tag_ids(&self) -> &[u32] {
        self.inner.tag_ids()
    }
}

struct TriageResponseTotalCount;

#[Object]
impl TriageResponseTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        use review_database::{Direction, Iterable};

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.triage_response_map();
        Ok(map.iter(Direction::Forward, None).count())
    }
}

#[derive(Clone, InputObject)]
pub(super) struct TriageResponseInput {
    key: Vec<u8>,
    tag_ids: Option<Vec<u32>>,
    remarks: Option<String>,
}

impl From<TriageResponseInput> for review_database::TriageResponseUpdate {
    fn from(input: TriageResponseInput) -> Self {
        Self::new(input.key, input.tag_ids, input.remarks)
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
    ) -> Result<Connection<String, TriageResponse, TriageResponseTotalCount, EmptyFields>> {
        let (after, before, first, last) =
            validate_and_process_pagination_params(after, before, first, last)?;

        query(
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
        source: String,
        time: DateTime<Utc>,
    ) -> Result<Option<TriageResponse>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.triage_response_map();
        Ok(map.get(&source, &time)?.map(Into::into))
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, TriageResponse, TriageResponseTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
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
        source: String,
        time: DateTime<Utc>,
        tag_ids: Vec<u32>,
        remarks: String,
    ) -> Result<ID> {
        let pol = review_database::TriageResponse::new(source, time, tag_ids, remarks);
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.triage_response_map();
        let id = map.put(pol)?;

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
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.triage_response_map();

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let _key = map.remove(i)?;

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

        let store = crate::graphql::get_store(ctx).await?;
        let mut map = store.triage_response_map();
        let old: review_database::TriageResponseUpdate = old.into();
        let new: review_database::TriageResponseUpdate = new.into();
        map.update(i, &old, &new)?;

        Ok(id)
    }
}
