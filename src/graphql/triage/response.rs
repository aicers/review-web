use super::{Role, RoleGuard};
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    types::ID,
    ComplexObject, Context, InputObject, Object, Result, SimpleObject,
};
use bincode::Options;
use chrono::{DateTime, Utc};
use review_database::{
    Indexable, Indexed, IndexedMap, IndexedMapIterator, IndexedMapUpdate, IterableMap,
};
use serde::{Deserialize, Serialize};

#[allow(clippy::module_name_repetitions)]
#[derive(Deserialize, Serialize, SimpleObject)]
#[graphql(complex)]
pub struct TriageResponse {
    #[graphql(skip)]
    id: u32,
    key: Vec<u8>,
    source: String,
    time: DateTime<Utc>,
    pub tag_ids: Vec<u32>,
    pub remarks: String,
    creation_time: DateTime<Utc>,
    last_modified_time: DateTime<Utc>,
}

#[ComplexObject]
impl TriageResponse {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }
}

struct TriageResponseTotalCount;

#[Object]
impl TriageResponseTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        Ok(store.triage_response_map().count()?)
    }
}

impl Indexable for TriageResponse {
    fn key(&self) -> &[u8] {
        &self.key
    }

    fn value(&self) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .serialize(self)
            .expect("serializable")
    }

    fn set_index(&mut self, index: u32) {
        self.id = index;
    }
}

#[derive(Clone, InputObject)]
pub(super) struct TriageResponseInput {
    key: Vec<u8>,
    tag_ids: Option<Vec<u32>>,
    remarks: Option<String>,
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
        let key = key(&source, time);

        let value = if let Some(value) = map.get_by_key(&key)? {
            let value: TriageResponse = bincode::DefaultOptions::new()
                .deserialize(value.as_ref())
                .map_err(|_| "invalid value in database")?;
            Some(value)
        } else {
            None
        };

        Ok(value)
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
    let map = store.triage_response_map();
    super::super::load::<
        '_,
        IndexedMap,
        IndexedMapIterator,
        TriageResponse,
        TriageResponse,
        TriageResponseTotalCount,
    >(&map, after, before, first, last, TriageResponseTotalCount)
}

pub fn key(source: &str, time: DateTime<Utc>) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(source.as_bytes());
    key.extend_from_slice(&time.timestamp_nanos_opt().unwrap_or_default().to_be_bytes());
    key
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
        mut tag_ids: Vec<u32>,
        remarks: String,
    ) -> Result<ID> {
        let key = key(&source, time);
        tag_ids.sort_unstable();
        tag_ids.dedup();
        let time = Utc::now();
        let pol = TriageResponse {
            id: u32::MAX,
            key,
            source,
            time,
            tag_ids,
            remarks,
            creation_time: time,
            last_modified_time: time,
        };
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.triage_response_map();
        let id = map.insert(pol)?;

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
        let map = store.triage_response_map();
        map.update(i, &old, &new)?;

        Ok(id)
    }
}

impl IndexedMapUpdate for TriageResponseInput {
    type Entry = TriageResponse;

    fn key(&self) -> Option<&[u8]> {
        Some(&self.key)
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        if let Some(remarks) = self.remarks.as_deref() {
            value.remarks.clear();
            value.remarks.push_str(remarks);
        }
        if let Some(tag_ids) = self.tag_ids.as_deref() {
            let mut tag_ids = tag_ids.to_vec();
            tag_ids.sort_unstable();
            tag_ids.dedup();
            value.tag_ids.clear();
            value.tag_ids.extend(tag_ids.iter());
        }
        value.last_modified_time = Utc::now();

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if self.key != value.key {
            return false;
        }
        if let Some(remarks) = self.remarks.as_deref() {
            if remarks != value.remarks {
                return false;
            }
        }
        if let Some(tag_ids) = self.tag_ids.as_deref() {
            let mut tag_ids = tag_ids.to_vec();
            tag_ids.sort_unstable();
            tag_ids.dedup();
            if tag_ids != value.tag_ids {
                return false;
            }
        }

        true
    }
}

pub(in crate::graphql) async fn remove_tag(ctx: &Context<'_>, tag_id: u32) -> Result<()> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.triage_response_map();
    let mut updates = Vec::new();
    for (_, value) in map.iter_forward()? {
        let triage_response = bincode::DefaultOptions::new()
            .deserialize::<TriageResponse>(value.as_ref())
            .map_err(|_| "invalid value in database")?;
        if triage_response.tag_ids.iter().all(|x| *x != tag_id) {
            continue;
        }

        let old_tag_ids = triage_response.tag_ids;
        let mut new_tag_ids = old_tag_ids.clone();
        new_tag_ids.retain(|&id| id != tag_id);
        updates.push((
            triage_response.id,
            triage_response.key,
            old_tag_ids,
            new_tag_ids,
            triage_response.remarks,
        ));
    }

    for (id, key, old_tag_ids, new_tag_ids, remarks) in updates {
        let old = TriageResponseInput {
            key: key.clone(),
            tag_ids: Some(old_tag_ids),
            remarks: Some(remarks.clone()),
        };
        let new = TriageResponseInput {
            key: key.clone(),
            tag_ids: Some(new_tag_ids),
            remarks: Some(remarks),
        };
        map.update(id, &old, &new)
            .map_err(|e| format!("failed to update triage response: {e}"))?;
    }

    Ok(())
}
