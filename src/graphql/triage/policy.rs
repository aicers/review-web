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
        let users_customers = users_customers(ctx)?;

        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_policy_map();
        let Some(inner) = map.get_by_id(i)? else {
            return Err("no such triage policy".into());
        };

        check_policy_access(users_customers.as_deref(), &inner)?;

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
    let users_customers = users_customers(ctx)?;
    let store = crate::graphql::get_store(ctx)?;
    let map = store.triage_policy_map();
    let (policies, has_previous, has_next) = crate::graphql::process_load_edges_filtered(
        &map,
        after,
        before,
        first,
        last,
        None,
        |policy: &database::TriagePolicy| {
            matches_customer(policy, customer_id)
                && can_access_policy(users_customers.as_deref(), policy)
        },
    );
    let policies = policies
        .into_iter()
        .map(|res| {
            let policy = res?;
            Ok((policy.unique_key(), policy.into()))
        })
        .collect::<anyhow::Result<Vec<PolicyEdge>>>()?;

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

/// Returns an error when the user cannot access the given policy.
fn check_policy_access(
    users_customers: Option<&[u32]>,
    policy: &database::TriagePolicy,
) -> Result<()> {
    if can_access_policy(users_customers, policy) {
        return Ok(());
    }
    Err("Forbidden".into())
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
        let users_customers = users_customers(ctx)?;
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
            if !is_member(users_customers.as_deref(), customer_id) {
                return Err("Forbidden".into());
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

        let mut parsed_ids = Vec::with_capacity(ids.len());
        let mut removed = Vec::<String>::with_capacity(ids.len());

        // Check access for all policies and capture names before removing any.
        for id in &ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let Some(policy) = map.get_by_id(i)? else {
                return Err("no such triage policy".into());
            };
            check_policy_access(users_customers.as_deref(), &policy)?;
            parsed_ids.push(i);
            removed.push(policy.name);
        }

        for (id, name) in parsed_ids.into_iter().zip(removed.iter()) {
            map.remove(id)?;
            info_with_username!(ctx, "Triage policy {name} has been deleted");
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
        check_policy_access(users_customers.as_deref(), &policy)?;

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
        if let Some(customer_id) = new.customer_id
            && !is_member(users_customers.as_deref(), customer_id)
        {
            return Err("Forbidden".into());
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
        role: Role,
        customer_ids: Option<Vec<u32>>,
    ) {
        let account = types::Account::new(
            username,
            "password",
            role,
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

    async fn insert_customers(schema: &TestSchema, names: &[&str]) {
        for (id, name) in names.iter().enumerate() {
            let res = schema
                .execute_as_system_admin(&format!(
                    r#"mutation {{ insertCustomer(name: "{name}", description: "", networks: []) }}"#
                ))
                .await;
            assert_eq!(
                res.data.to_string(),
                format!(r#"{{insertCustomer: "{id}"}}"#)
            );
        }
    }

    async fn insert_default_triage_exclusion_reason(schema: &TestSchema) {
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
    }

    async fn insert_customer_policy(
        schema: &TestSchema,
        expected_id: u32,
        name: &str,
        customer_id: u32,
    ) {
        let res = schema
            .execute_as_system_admin(&customer_policy_mutation(name, customer_id))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!(r#"{{insertTriagePolicy: "{expected_id}"}}"#)
        );
    }

    fn customer_policy_mutation(name: &str, customer_id: u32) -> String {
        format!(
            r#"mutation {{
                insertTriagePolicy(
                    name: "{name}"
                    triageExclusionId: ["0"]
                    packetAttr: []
                    confidence: []
                    response: []
                    customerId: "{customer_id}"
                )
            }}"#
        )
    }

    async fn insert_global_policy(schema: &TestSchema, expected_id: u32, name: &str) {
        let res = schema
            .execute_as_system_admin(&format!(
                r#"mutation {{
                    insertTriagePolicy(
                        name: "{name}"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                    )
                }}"#
            ))
            .await;
        assert_eq!(
            res.data.to_string(),
            format!(r#"{{insertTriagePolicy: "{expected_id}"}}"#)
        );
    }

    #[tokio::test]
    async fn triage_policy_customer_scoping_admin_allowed() {
        let schema = TestSchema::new().await;
        // Create admin account with no customer_ids (admin)
        create_account(&schema.store(), "testuser", Role::SystemAdministrator, None);

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

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
    async fn triage_policy_customer_scoping_allowed() {
        let schema = TestSchema::new().await;
        // Create scoped user with customer_ids = [0]
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0]),
        );

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

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
    async fn triage_policy_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;
        // Create scoped user with customer_ids = [0]
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0]),
        );

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Other Customer Policy", 1).await;

        // Scoped user should be denied access
        let res = schema
            .execute_with_guard(
                r#"{ triagePolicy(id: "0") { name } }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(
            res.errors[0].message.contains("Forbidden"),
            "Expected Forbidden error: {:?}",
            res.errors
        );
    }

    #[tokio::test]
    async fn triage_policy_insert_customer_scoping_admin_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;

        // Admin can insert policy for any customer
        insert_customer_policy(&schema, 0, "Admin Policy", 1).await;
    }

    #[tokio::test]
    async fn triage_policy_insert_customer_scoping_allowed() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0]),
        );

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;

        let res = schema
            .execute_with_guard(
                &customer_policy_mutation("Allowed Policy", 0),
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);
    }

    #[tokio::test]
    async fn triage_policy_insert_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0]),
        );

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;

        let res = schema
            .execute_with_guard(
                &customer_policy_mutation("Forbidden Policy", 1),
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(
            res.errors[0].message.contains("Forbidden"),
            "Expected Forbidden error: {:?}",
            res.errors
        );

        // Ensure policy was not created
        let res = schema
            .execute_as_system_admin(r"{ triagePolicyList(first: 10) { totalCount } }")
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "0");
    }

    #[tokio::test]
    async fn triage_policy_global_customer_scoping_allowed() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0]),
        );

        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Global Policy").await;

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
    async fn triage_policy_remove_customer_scoping_admin_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

        let res = schema
            .execute_as_system_admin(r#"mutation { removeTriagePolicies(ids: ["0"]) }"#)
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(
            res.data.to_string(),
            r#"{removeTriagePolicies: ["Customer Policy"]}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_remove_customer_scoping_allowed() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0]),
        );

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

        let res = schema
            .execute_with_guard(
                r#"mutation { removeTriagePolicies(ids: ["0"]) }"#,
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
            r#"{removeTriagePolicies: ["Customer Policy"]}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_remove_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0]),
        );

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Other Customer Policy", 1).await;

        // Scoped user should be denied from deleting
        let res = schema
            .execute_with_guard(
                r#"mutation { removeTriagePolicies(ids: ["0"]) }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(
            res.errors[0].message.contains("Forbidden"),
            "Expected Forbidden error: {:?}",
            res.errors
        );
    }

    #[tokio::test]
    async fn triage_policy_list_customer_scoping_admin_allowed() {
        let schema = TestSchema::new().await;
        create_account(&schema.store(), "testuser", Role::SystemAdministrator, None);

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Global Policy").await;
        insert_customer_policy(&schema, 1, "Customer 0 Policy", 0).await;
        insert_customer_policy(&schema, 2, "Customer 1 Policy", 1).await;

        // Admin should see all policies
        let res = schema
            .execute_as_system_admin(
                r"{ triagePolicyList(first: 10) { totalCount nodes { name customerId } } }",
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
    async fn triage_policy_list_customer_scoping_allowed() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0]),
        );

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Global Policy").await;
        insert_customer_policy(&schema, 1, "Customer 0 Policy", 0).await;
        insert_customer_policy(&schema, 2, "Customer 1 Policy", 1).await;

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
    async fn triage_policy_list_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![99]),
        );

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer 0 Policy", 0).await;

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
        assert_eq!(json["triagePolicyList"]["totalCount"], "0");
        assert_eq!(
            json["triagePolicyList"]["nodes"].as_array().unwrap().len(),
            0
        );
    }

    #[tokio::test]
    async fn triage_policy_list_multiple_customers_scoping_allowed() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0, 2]),
        );

        insert_customers(&schema, &["c0", "c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer 0 Policy", 0).await;
        insert_customer_policy(&schema, 1, "Customer 1 Policy", 1).await;
        insert_customer_policy(&schema, 2, "Customer 2 Policy", 2).await;

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
    async fn triage_policy_list_empty_scope_scoping_allowed() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![]),
        );

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Global Policy").await;
        insert_customer_policy(&schema, 1, "Customer Policy", 0).await;

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

    #[tokio::test]
    async fn triage_policy_update_customer_scoping_admin_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateTriagePolicy(
                        id: 0
                        old: {
                            name: "Customer Policy"
                            triageExclusionId: ["0"]
                            packetAttr: []
                            confidence: []
                            response: []
                            customerId: "0"
                        }
                        new: {
                            name: "Updated Policy"
                            triageExclusionId: ["0"]
                            packetAttr: []
                            confidence: []
                            response: []
                            customerId: "0"
                        }
                    )
                }"#,
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(res.data.to_string(), r#"{updateTriagePolicy: "0"}"#);
    }

    #[tokio::test]
    async fn triage_policy_update_customer_scoping_allowed() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0]),
        );

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

        let res = schema
            .execute_with_guard(
                r#"mutation {
                    updateTriagePolicy(
                        id: 0
                        old: {
                            name: "Customer Policy"
                            triageExclusionId: ["0"]
                            packetAttr: []
                            confidence: []
                            response: []
                            customerId: "0"
                        }
                        new: {
                            name: "Updated Policy"
                            triageExclusionId: ["0"]
                            packetAttr: []
                            confidence: []
                            response: []
                            customerId: "0"
                        }
                    )
                }"#,
                RoleGuard::Role(Role::SecurityAdministrator),
            )
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors: {:?}",
            res.errors
        );
        assert_eq!(res.data.to_string(), r#"{updateTriagePolicy: "0"}"#);
    }

    #[tokio::test]
    async fn triage_policy_update_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0]),
        );

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Other Customer Policy", 1).await;

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
            res.errors[0].message.contains("Forbidden"),
            "Expected Forbidden error: {:?}",
            res.errors
        );
    }

    #[tokio::test]
    async fn triage_policy_update_reassign_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;
        create_account(
            &schema.store(),
            "testuser",
            Role::SecurityAdministrator,
            Some(vec![0]),
        );

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer 0 Policy", 0).await;

        // Scoped user should not be able to move policy to customer 1
        let res = schema
            .execute_with_guard(
                r#"mutation {
                    updateTriagePolicy(
                        id: 0
                        old: {
                            name: "Customer 0 Policy"
                            triageExclusionId: ["0"]
                            packetAttr: []
                            confidence: []
                            response: []
                            customerId: "0"
                        }
                        new: {
                            name: "Moved Policy"
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
            res.errors[0].message.contains("Forbidden"),
            "Expected Forbidden error: {:?}",
            res.errors
        );

        // Ensure the policy was not updated
        let res = schema
            .execute_as_system_admin(r#"{ triagePolicy(id: "0") { name customerId } }"#)
            .await;
        assert!(
            res.errors.is_empty(),
            "Expected no errors when querying policy: {:?}",
            res.errors
        );
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicy: {name: "Customer 0 Policy", customerId: "0"}}"#
        );
    }
}
