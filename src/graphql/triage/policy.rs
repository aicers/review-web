use super::{
    ConfidenceInput, PacketAttrInput, ResponseInput, TiInput, TriagePolicy, TriagePolicyInput,
    TriagePolicyMutation, TriagePolicyQuery,
};
use super::{Role, RoleGuard};
use anyhow::anyhow;
use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, Object, Result, ID,
};
use bincode::Options;
use chrono::Utc;
use core::convert::TryInto;
use review_database::{
    self as database, Indexed, IndexedMap, IndexedMapIterator, IndexedMapUpdate,
};

struct TriagePolicyTotalCount;

#[Object]
impl TriagePolicyTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        let store = crate::graphql::get_store(ctx).await?;
        Ok(store.triage_policy_map().count()?)
    }
}

#[Object]
impl TriagePolicyQuery {
    /// A list of triage policies.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn triage_policy_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, TriagePolicy, TriagePolicyTotalCount, EmptyFields>> {
        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }

    /// Looks up a triage policy by the given id.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn triage_policy(&self, ctx: &Context<'_>, id: ID) -> Result<TriagePolicy> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.triage_policy_map();
        let Some(value) = map.get_by_id(i)? else {
            return Err("no such triage policy".into());
        };
        Ok(TriagePolicy {
            inner: bincode::DefaultOptions::new()
                .deserialize(value.as_ref())
                .map_err(|_| "invalid value in database")?,
        })
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, TriagePolicy, TriagePolicyTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.triage_policy_map();
    super::super::load::<
        '_,
        IndexedMap,
        IndexedMapIterator,
        TriagePolicy,
        database::TriagePolicy,
        TriagePolicyTotalCount,
    >(&map, after, before, first, last, TriagePolicyTotalCount)
}

#[Object]
impl TriagePolicyMutation {
    /// Inserts a new triage policy, returning the ID of the new triage.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_triage_policy(
        &self,
        ctx: &Context<'_>,
        name: String,
        ti_db: Vec<TiInput>,
        packet_attr: Vec<PacketAttrInput>,
        confidence: Vec<ConfidenceInput>,
        response: Vec<ResponseInput>,
    ) -> Result<ID> {
        let mut packet_attr_convert: Vec<database::PacketAttr> = Vec::new();
        for p in &packet_attr {
            packet_attr_convert.push(p.try_into()?);
        }
        packet_attr_convert.sort_unstable();
        let mut ti_db = ti_db.iter().map(Into::into).collect::<Vec<database::Ti>>();
        ti_db.sort_unstable();
        let mut confidence = confidence
            .iter()
            .map(Into::into)
            .collect::<Vec<database::Confidence>>();
        confidence.sort_unstable();
        let mut response = response
            .iter()
            .map(Into::into)
            .collect::<Vec<database::Response>>();
        response.sort_unstable();
        let triage = database::TriagePolicy {
            id: u32::MAX,
            name,
            ti_db,
            packet_attr: packet_attr_convert,
            confidence,
            response,
            creation_time: Utc::now(),
        };

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.triage_policy_map();
        let id = map.insert(triage)?;

        Ok(ID(id.to_string()))
    }

    /// Removes triage policies, returning the IDs that no longer exist.
    ///
    /// On error, some triage policies may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_triage_policies(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.triage_policy_map();

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let key = map.remove(i)?;

            let name = match String::from_utf8(key) {
                Ok(key) => key,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
            };
            removed.push(name);
        }

        Ok(removed)
    }

    /// Updates an existing triage policy.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_triage_policy(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: TriagePolicyInput,
        new: TriagePolicyInput,
    ) -> Result<ID> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.triage_policy_map();
        map.update(i, &old, &new)?;

        Ok(id)
    }
}

impl IndexedMapUpdate for TriagePolicyInput {
    type Entry = database::TriagePolicy;

    fn key(&self) -> Option<&[u8]> {
        Some(self.name.as_bytes())
    }

    fn apply(&self, mut value: Self::Entry) -> Result<Self::Entry, anyhow::Error> {
        value.name.clear();
        value.name.push_str(&self.name);
        let mut ti_db = self
            .ti_db
            .iter()
            .map(Into::into)
            .collect::<Vec<database::Ti>>();
        ti_db.sort_unstable();
        value.ti_db = ti_db;
        let mut packet_attr: Vec<database::PacketAttr> = Vec::new();
        for p in &self.packet_attr {
            packet_attr.push(p.try_into().map_err(|e| anyhow!("{}", e))?);
        }
        packet_attr.sort_unstable();
        value.packet_attr = packet_attr;
        let mut confidence = self
            .confidence
            .iter()
            .map(Into::into)
            .collect::<Vec<database::Confidence>>();
        confidence.sort_unstable();
        value.confidence = confidence;
        let mut response = self
            .response
            .iter()
            .map(Into::into)
            .collect::<Vec<database::Response>>();
        response.sort_unstable();
        value.response = response;

        Ok(value)
    }

    fn verify(&self, value: &Self::Entry) -> bool {
        if self.name != value.name {
            return false;
        }
        let mut ti_db = self
            .ti_db
            .iter()
            .map(Into::into)
            .collect::<Vec<database::Ti>>();
        ti_db.sort_unstable();
        if ti_db != value.ti_db {
            return false;
        }
        let mut packet_attr: Vec<database::PacketAttr> = Vec::new();
        for p in &self.packet_attr {
            if let Ok(p) = p.try_into() {
                packet_attr.push(p);
            }
        }
        packet_attr.sort_unstable();
        if packet_attr != value.packet_attr {
            return false;
        }
        let mut confidence = self
            .confidence
            .iter()
            .map(Into::into)
            .collect::<Vec<database::Confidence>>();
        confidence.sort_unstable();
        if confidence != value.confidence {
            return false;
        }
        let mut response = self
            .response
            .iter()
            .map(Into::into)
            .collect::<Vec<database::Response>>();
        response.sort_unstable();
        if response != value.response {
            return false;
        }
        true
    }
}
