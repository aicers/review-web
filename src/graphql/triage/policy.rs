use std::cmp;

use async_graphql::{
    Context, ID, Object, Result, StringNumber,
    connection::{Connection, Edge, EmptyFields, OpaqueCursor},
};
use chrono::Utc;
use review_database::{self as database, Iterable, UniqueKey, event::Direction};
use tracing::info;

use super::{
    ConfidenceInput, PacketAttrInput, ResponseInput, TriagePolicy, TriagePolicyInput,
    TriagePolicyMutation, TriagePolicyQuery,
};
use super::{Role, RoleGuard};
use crate::graphql::query_with_constraints;
use crate::info_with_username;

const DEFAULT_CONNECTION_SIZE: usize = 100;
type PolicyEdge = (Vec<u8>, TriagePolicy);

struct TriagePolicyTotalCount {
    customer_id: Option<u32>,
}

#[Object]
impl TriagePolicyTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_policy_map();
        Ok(StringNumber(
            map.iter(Direction::Forward, None)
                .filter(|res| {
                    res.as_ref()
                        .map(|policy| matches_customer(policy, self.customer_id))
                        .unwrap_or(false)
                })
                .count(),
        ))
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
        customer_id: Option<ID>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, TriagePolicy, TriagePolicyTotalCount, EmptyFields>>
    {
        let customer_id = customer_id
            .map(|id| {
                id.as_str()
                    .parse::<u32>()
                    .map_err(|_| "invalid customer ID")
            })
            .transpose()?;
        if let Some(customer_id) = customer_id {
            let store = crate::graphql::get_store(ctx)?;
            let customer_map = store.customer_map();
            if customer_map.get_by_id(customer_id)?.is_none() {
                return Err("no such customer".into());
            }
        }
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load(ctx, after, before, first, last, customer_id).await
            },
        )
        .await
    }

    /// Looks up a triage policy by the given id.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn triage_policy(&self, ctx: &Context<'_>, id: ID) -> Result<TriagePolicy> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_policy_map();
        let Some(inner) = map.get_by_id(i)? else {
            return Err("no such triage policy".into());
        };
        Ok(TriagePolicy { inner })
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
    customer_id: Option<u32>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, TriagePolicy, TriagePolicyTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx)?;
    let map = store.triage_policy_map();
    let after = after.map(|c| c.0);
    let before = before.map(|c| c.0);

    let (policies, has_previous, has_next) = if let Some(last) = last {
        let (mut policies, has_more) = iter_to_policies(
            &map,
            Direction::Reverse,
            before.as_deref(),
            after.as_deref(),
            cmp::Ordering::is_ge,
            last,
            customer_id,
        )?;
        policies.reverse();
        (policies, has_more, false)
    } else {
        let first = first.unwrap_or(DEFAULT_CONNECTION_SIZE);
        let (policies, has_more) = iter_to_policies(
            &map,
            Direction::Forward,
            after.as_deref(),
            before.as_deref(),
            cmp::Ordering::is_le,
            first,
            customer_id,
        )?;
        (policies, false, has_more)
    };

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        TriagePolicyTotalCount { customer_id },
    );
    connection.edges.extend(
        policies
            .into_iter()
            .map(|(key, policy)| Edge::new(OpaqueCursor(key), policy)),
    );
    Ok(connection)
}

fn iter_to_policies(
    map: &database::IndexedTable<'_, database::TriagePolicy>,
    direction: Direction,
    start: Option<&[u8]>,
    bound: Option<&[u8]>,
    cond: fn(cmp::Ordering) -> bool,
    len: usize,
    customer_id: Option<u32>,
) -> anyhow::Result<(Vec<PolicyEdge>, bool)> {
    let mut policies = Vec::new();
    let mut exceeded = false;
    let mut iter = map.iter(direction, start);
    // exclusive start cursor: skip the first item when a start is provided
    if start.is_some() {
        iter.next();
    }
    for item in iter {
        let policy = item?;
        let key = policy.unique_key();

        if let Some(b) = bound
            && !(cond)(key.as_slice().cmp(b))
        {
            break;
        }
        if !matches_customer(&policy, customer_id) {
            continue;
        }
        policies.push((key, policy.into()));
        exceeded = policies.len() > len;
        if exceeded {
            break;
        }
    }
    if exceeded {
        policies.pop();
    }
    Ok((policies, exceeded))
}

// Matches a policy against the caller's customer scope:
//
// customer_id Some: allow global policies (customer None) or policies for that specific customer.
// customer_id None: System administrator context, so all policies are visible.
fn matches_customer(policy: &database::TriagePolicy, customer_id: Option<u32>) -> bool {
    match customer_id {
        Some(id) => policy.customer_id.is_none() || policy.customer_id == Some(id),
        None => true,
    }
}

#[Object]
impl TriagePolicyMutation {
    /// Inserts a new triage policy, returning the ID of the new triage.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_triage_policy(
        &self,
        ctx: &Context<'_>,
        name: String,
        triage_exclusion_id: Vec<ID>,
        packet_attr: Vec<PacketAttrInput>,
        confidence: Vec<ConfidenceInput>,
        response: Vec<ResponseInput>,
        customer_id: Option<ID>,
    ) -> Result<ID> {
        let mut packet_attr_convert: Vec<database::PacketAttr> = Vec::new();
        for p in &packet_attr {
            packet_attr_convert.push(p.into());
        }
        packet_attr_convert.sort_unstable();
        let mut triage_exclusion_id = triage_exclusion_id
            .iter()
            .map(|id| id.as_str().parse::<u32>().map_err(|_| "invalid ID"))
            .collect::<Result<Vec<_>, _>>()?;
        triage_exclusion_id.sort_unstable();
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
        let store = crate::graphql::get_store(ctx)?;
        let customer_id = customer_id
            .map(|id| id.as_str().parse::<u32>())
            .transpose()
            .map_err(|_| "invalid customer ID")?;
        if let Some(customer_id) = customer_id {
            let customer_map = store.customer_map();
            if customer_map.get_by_id(customer_id)?.is_none() {
                return Err("no such customer".into());
            }
        }
        let exclusion_map = store.triage_exclusion_reason_map();
        for id in &triage_exclusion_id {
            if exclusion_map.get_by_id(*id)?.is_none() {
                return Err("no such triage exclusion reason".into());
            }
        }

        let triage = database::TriagePolicy {
            id: u32::MAX,
            name: name.clone(),
            triage_exclusion_id,
            packet_attr: packet_attr_convert,
            confidence,
            response,
            creation_time: Utc::now(),
            customer_id,
        };

        let map = store.triage_policy_map();
        let id = map.put(triage)?;
        info_with_username!(ctx, "Triage policy {name} has been registered");

        Ok(ID(id.to_string()))
    }

    /// Removes triage policies, returning the names that no longer exist.
    ///
    /// On error, some triage policies may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_triage_policies(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_policy_map();

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let key = map.remove(i)?;

            let name = match String::from_utf8(key) {
                Ok(key) => key,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into(),
            };
            info_with_username!(ctx, "Triage policy {name} has been deleted");
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
        let old: review_database::TriagePolicyUpdate = old.try_into()?;
        let new: review_database::TriagePolicyUpdate = new.try_into()?;

        let store = crate::graphql::get_store(ctx)?;
        let customer_map = store.customer_map();
        if let Some(customer_id) = old.customer_id
            && customer_map.get_by_id(customer_id)?.is_none()
        {
            return Err(format!(
                "Customer not found for current policy (customerId: {customer_id})"
            )
            .into());
        }
        if let Some(customer_id) = new.customer_id
            && customer_map.get_by_id(customer_id)?.is_none()
        {
            return Err(format!(
                "Customer not found for updated policy (customerId: {customer_id})"
            )
            .into());
        }

        let exclusion_map = store.triage_exclusion_reason_map();
        for id in &old.triage_exclusion_id {
            if exclusion_map.get_by_id(*id)?.is_none() {
                return Err(format!(
                    "Triage exclusion reason not found for current policy (id: {id})"
                )
                .into());
            }
        }
        for id in &new.triage_exclusion_id {
            if exclusion_map.get_by_id(*id)?.is_none() {
                return Err(format!(
                    "Triage exclusion reason not found for updated policy (id: {id})"
                )
                .into());
            }
        }

        let mut map = store.triage_policy_map();
        map.update(i, &old, &new)?;
        info_with_username!(
            ctx,
            "Triage policy {} has been updated to {}",
            old.name,
            new.name
        );

        Ok(id)
    }
}
