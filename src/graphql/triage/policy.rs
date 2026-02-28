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
use crate::graphql::customer_access::{is_member, users_customers};
use crate::graphql::query_with_constraints;
use crate::info_with_username;

const DEFAULT_CONNECTION_SIZE: usize = 100;
type PolicyEdge = (Vec<u8>, TriagePolicy);

struct TriagePolicyTotalCount {
    customer_id: Option<u32>,
    users_customers: Option<Vec<u32>>,
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
                        .map(|policy| {
                            matches_customer(policy, self.customer_id)
                                && can_access_policy(self.users_customers.as_deref(), policy)
                        })
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
        let users_customers = users_customers(ctx)?;
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
                load(
                    ctx,
                    after,
                    before,
                    first,
                    last,
                    customer_id,
                    users_customers,
                )
                .await
            },
        )
        .await
    }

    /// Looks up a triage policy by the given id.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn triage_policy(&self, ctx: &Context<'_>, id: ID) -> Result<TriagePolicy> {
        let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let users_customers = users_customers(ctx)?;

        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_policy_map();
        let Some(inner) = map.get_by_id(i)? else {
            return Err("no such triage policy".into());
        };

        if !can_access_policy(users_customers.as_deref(), &inner) {
            return Err("access denied: policy belongs to a different customer".into());
        }

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
    users_customers: Option<Vec<u32>>,
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
            users_customers.as_deref(),
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
            users_customers.as_deref(),
        )?;
        (policies, false, has_more)
    };

    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        TriagePolicyTotalCount {
            customer_id,
            users_customers,
        },
    );
    connection.edges.extend(
        policies
            .into_iter()
            .map(|(key, policy)| Edge::new(OpaqueCursor(key), policy)),
    );
    Ok(connection)
}

#[allow(clippy::too_many_arguments)]
fn iter_to_policies(
    map: &database::IndexedTable<'_, database::TriagePolicy>,
    direction: Direction,
    start: Option<&[u8]>,
    bound: Option<&[u8]>,
    cond: fn(cmp::Ordering) -> bool,
    len: usize,
    customer_id: Option<u32>,
    users_customers: Option<&[u32]>,
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
        // Filter by explicit customer_id parameter and by user's customer scope
        if !matches_customer(&policy, customer_id) || !can_access_policy(users_customers, &policy) {
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

/// Checks if the user can access a policy based on their customer scope.
///
/// Returns `true` if:
/// - The user is an admin (`users_customers` is `None`), or
/// - The policy is global (`policy.customer_id` is `None`), or
/// - The policy's `customer_id` is in the user's customer list.
fn can_access_policy(users_customers: Option<&[u32]>, policy: &database::TriagePolicy) -> bool {
    match users_customers {
        None => true, // Admin has access to all policies
        Some(_) => match policy.customer_id {
            None => true, // Global policies are visible to all users
            Some(policy_customer_id) => is_member(users_customers, policy_customer_id),
        },
    }
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
        let users_customers = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_policy_map();

        // Check access for all policies before removing any
        for id in &ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let Some(policy) = map.get_by_id(i)? else {
                return Err("no such triage policy".into());
            };
            if !can_access_policy(users_customers.as_deref(), &policy) {
                return Err("access denied: policy belongs to a different customer".into());
            }
        }

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
        let users_customers = users_customers(ctx)?;
        let old: review_database::TriagePolicyUpdate = old.try_into()?;
        let new: review_database::TriagePolicyUpdate = new.try_into()?;

        let store = crate::graphql::get_store(ctx)?;

        // Verify access to the policy based on its current state
        let policy_map = store.triage_policy_map();
        let Some(policy) = policy_map.get_by_id(i)? else {
            return Err("no such triage policy".into());
        };
        if !can_access_policy(users_customers.as_deref(), &policy) {
            return Err("access denied: policy belongs to a different customer".into());
        }

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

#[cfg(test)]
mod tests {
    use review_database::{Role, types};

    use crate::graphql::{RoleGuard, TestSchema};

    fn create_account(
        store: &std::sync::RwLockReadGuard<'_, review_database::Store>,
        username: &str,
        customer_ids: Option<Vec<u32>>,
    ) {
        let account = types::Account::new(
            username,
            "password",
            Role::SecurityAdministrator,
            "Test User".to_string(),
            "Testing".to_string(),
            None,
            None,
            None,
            None,
            customer_ids,
        )
        .expect("create account");
        store
            .account_map()
            .insert(&account)
            .expect("insert account");
    }

    #[tokio::test]
    async fn test_triage_policy_read_allowed_for_admin() {
        let schema = TestSchema::new().await;
        // Create admin account with no customer_ids (admin)
        create_account(&schema.store(), "testuser", None);

        // Create customer and exclusion reason
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason"
                        description: "reason"
                        domain: ["example.com"]
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // Create a customer-scoped policy
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Customer Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "0"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        // Admin can read any policy
        let res = schema
            .execute_as_system_admin(r#"{ triagePolicy(id: "0") { name customerId } }"#)
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicy: {name: "Customer Policy", customerId: "0"}}"#
        );
    }

    #[tokio::test]
    async fn test_triage_policy_read_allowed_for_matching_customer() {
        let schema = TestSchema::new().await;
        // Create scoped user with customer_ids = [0]
        create_account(&schema.store(), "testuser", Some(vec![0]));

        // Create customer and exclusion reason
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason"
                        description: "reason"
                        domain: ["example.com"]
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // Create a policy for customer 0
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Customer Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "0"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        // Scoped user can read policy for their customer
        let res = schema
            .execute_with_guard(
                r#"{ triagePolicy(id: "0") { name customerId } }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicy: {name: "Customer Policy", customerId: "0"}}"#
        );
    }

    #[tokio::test]
    async fn test_triage_policy_read_denied_for_different_customer() {
        let schema = TestSchema::new().await;
        // Create scoped user with customer_ids = [0]
        create_account(&schema.store(), "testuser", Some(vec![0]));

        // Create two customers
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c2", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "1"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason"
                        description: "reason"
                        domain: ["example.com"]
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // Create a policy for customer 1 (user only has access to customer 0)
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Other Customer Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "1"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        // Scoped user should be denied access
        let res = schema
            .execute_with_guard(
                r#"{ triagePolicy(id: "0") { name } }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(
            res.errors[0].message.contains("access denied"),
            "Expected access denied error: {:?}",
            res.errors
        );
    }

    #[tokio::test]
    async fn test_triage_policy_read_global_allowed_for_scoped_user() {
        let schema = TestSchema::new().await;
        create_account(&schema.store(), "testuser", Some(vec![0]));

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason"
                        description: "reason"
                        domain: ["example.com"]
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // Create a global policy (no customer_id)
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Global Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        // Scoped user can read global policies
        let res = schema
            .execute_with_guard(
                r#"{ triagePolicy(id: "0") { name customerId } }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicy: {name: "Global Policy", customerId: null}}"#
        );
    }

    #[tokio::test]
    async fn test_triage_policy_delete_denied_for_different_customer() {
        let schema = TestSchema::new().await;
        create_account(&schema.store(), "testuser", Some(vec![0]));

        // Create customers
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c2", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "1"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason"
                        description: "reason"
                        domain: ["example.com"]
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // Create a policy for customer 1
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Other Customer Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "1"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        // Scoped user should be denied from deleting
        let res = schema
            .execute_with_guard(
                r#"mutation { removeTriagePolicies(ids: ["0"]) }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(
            res.errors[0].message.contains("access denied"),
            "Expected access denied error: {:?}",
            res.errors
        );
    }

    #[tokio::test]
    async fn test_triage_policy_list_filters_by_user_scope() {
        let schema = TestSchema::new().await;
        create_account(&schema.store(), "testuser", Some(vec![0]));

        // Create customers
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c2", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "1"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason"
                        description: "reason"
                        domain: ["example.com"]
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // Create a global policy
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Global Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        // Create a policy for customer 0 (user's customer)
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Customer 0 Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "0"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "1"}"#);

        // Create a policy for customer 1 (not user's customer)
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Customer 1 Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "1"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "2"}"#);

        // Scoped user should only see global and customer 0 policies
        let res = schema
            .execute_with_guard(
                r"{ triagePolicyList(first: 10) { totalCount nodes { name customerId } } }",
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "2");
        let nodes = json["triagePolicyList"]["nodes"].as_array().unwrap();
        let names: Vec<&str> = nodes.iter().map(|n| n["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"Global Policy"));
        assert!(names.contains(&"Customer 0 Policy"));
        assert!(!names.contains(&"Customer 1 Policy"));
    }

    #[tokio::test]
    async fn test_triage_policy_admin_sees_all_policies() {
        let schema = TestSchema::new().await;
        create_account(&schema.store(), "testuser", None);

        // Create customers
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c2", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "1"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason"
                        description: "reason"
                        domain: ["example.com"]
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // Create policies for different customers
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Global Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Customer 0 Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "0"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "1"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Customer 1 Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "1"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "2"}"#);

        // Admin should see all policies
        let res = schema
            .execute_as_system_admin(
                r"{ triagePolicyList(first: 10) { totalCount nodes { name } } }",
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "3");
    }

    #[tokio::test]
    async fn test_triage_policy_update_denied_for_different_customer() {
        let schema = TestSchema::new().await;
        create_account(&schema.store(), "testuser", Some(vec![0]));

        // Create customers
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c2", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "1"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason"
                        description: "reason"
                        domain: ["example.com"]
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // Create a policy for customer 1
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Other Customer Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "1"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        // Scoped user should be denied from updating
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    updateTriagePolicy(
                        id: 0
                        old: {
                            name: "Other Customer Policy"
                            triageExclusionId: ["0"]
                            packetAttr: []
                            confidence: []
                            response: []
                            customerId: "1"
                        }
                        new: {
                            name: "Updated Policy"
                            triageExclusionId: ["0"]
                            packetAttr: []
                            confidence: []
                            response: []
                            customerId: "1"
                        }
                    )
                }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(
            res.errors[0].message.contains("access denied"),
            "Expected access denied error: {:?}",
            res.errors
        );
    }

    #[tokio::test]
    async fn test_triage_policy_user_with_multiple_customers() {
        let schema = TestSchema::new().await;
        create_account(&schema.store(), "testuser", Some(vec![0, 2]));

        // Create customers
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c0", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "1"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c2", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "2"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason"
                        description: "reason"
                        domain: ["example.com"]
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // Create policies for each customer
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Customer 0 Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "0"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Customer 1 Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "1"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "1"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Customer 2 Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "2"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "2"}"#);

        // User with customers [0, 2] should see policies for 0 and 2, but not 1
        let res = schema
            .execute_with_guard(
                r"{ triagePolicyList(first: 10) { totalCount nodes { name customerId } } }",
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "2");
        let nodes = json["triagePolicyList"]["nodes"].as_array().unwrap();
        let names: Vec<&str> = nodes.iter().map(|n| n["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"Customer 0 Policy"));
        assert!(names.contains(&"Customer 2 Policy"));
        assert!(!names.contains(&"Customer 1 Policy"));
    }

    #[tokio::test]
    async fn test_triage_policy_empty_customer_ids_sees_only_global() {
        let schema = TestSchema::new().await;
        create_account(&schema.store(), "testuser", Some(vec![]));

        // Create customer
        let res = schema
            .execute_as_system_admin(
                r#"mutation { insertCustomer(name: "c1", description: "", networks: []) }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertCustomer: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason"
                        description: "reason"
                        domain: ["example.com"]
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // Create global and customer-scoped policies
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Global Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriagePolicy(
                        name: "Customer Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "0"
                    )
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "1"}"#);

        // User with empty customer_ids should only see global policies
        let res = schema
            .execute_with_guard(
                r"{ triagePolicyList(first: 10) { totalCount nodes { name } } }",
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "1");
        assert_eq!(
            json["triagePolicyList"]["nodes"][0]["name"]
                .as_str()
                .unwrap(),
            "Global Policy"
        );
    }
}
