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
                    res.as_ref().is_ok_and(|policy| {
                        matches_customer(policy, self.customer_id)
                            && can_access_policy(self.users_customers.as_deref(), policy)
                    })
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
        Ok(TriagePolicy {
            inner: ensure_accessible_policy(ctx, i)?,
        })
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

fn can_access_policy(users_customers: Option<&[u32]>, policy: &database::TriagePolicy) -> bool {
    match users_customers {
        None => true,
        Some(_) => match policy.customer_id {
            None => true,
            Some(policy_customer_id) => is_member(users_customers, policy_customer_id),
        },
    }
}

fn ensure_accessible_policy(ctx: &Context<'_>, policy_id: u32) -> Result<database::TriagePolicy> {
    let users_customers = users_customers(ctx)?;
    let store = crate::graphql::get_store(ctx)?;
    let map = store.triage_policy_map();
    ensure_accessible_policy_from_map(&map, users_customers.as_deref(), policy_id)
}

fn ensure_accessible_policy_from_map(
    map: &database::IndexedTable<'_, database::TriagePolicy>,
    users_customers: Option<&[u32]>,
    policy_id: u32,
) -> Result<database::TriagePolicy> {
    let Some(policy) = map.get_by_id(policy_id)? else {
        return Err("no such triage policy".into());
    };
    if can_access_policy(users_customers, &policy) {
        return Ok(policy);
    }
    Err("Forbidden".into())
}

fn ensure_mutation_customer_scope(
    users_customers: Option<&[u32]>,
    customer_id: Option<u32>,
) -> Result<()> {
    match (users_customers, customer_id) {
        (Some(_), None) => Err("Forbidden".into()),
        (_, Some(customer_id)) if !is_member(users_customers, customer_id) => {
            Err("Forbidden".into())
        }
        _ => Ok(()),
    }
}

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
        }
        ensure_mutation_customer_scope(users_customers.as_deref(), customer_id)?;
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

        for id in &ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            let policy = ensure_accessible_policy_from_map(&map, users_customers.as_deref(), i)?;
            ensure_mutation_customer_scope(users_customers.as_deref(), policy.customer_id)?;
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
        let policy_map = store.triage_policy_map();
        let policy = ensure_accessible_policy_from_map(&policy_map, users_customers.as_deref(), i)?;
        ensure_mutation_customer_scope(users_customers.as_deref(), policy.customer_id)?;

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
        ensure_mutation_customer_scope(users_customers.as_deref(), new.customer_id)?;

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
    use review_database::Role;
    use serde_json::Value;

    use crate::graphql::TestSchema;

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

    async fn execute_as_scoped_security_admin(
        schema: &TestSchema,
        query: &str,
        customer_ids: Vec<u32>,
    ) -> async_graphql::Response {
        schema
            .execute_as_scoped_user(query, Role::SecurityAdministrator, Some(customer_ids))
            .await
    }

    fn node_names(json: &Value) -> Vec<&str> {
        json["triagePolicyList"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| node["name"].as_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_reads_matching_policy() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"{ triagePolicy(id: "0") { name customerId } }"#,
            vec![0],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicy: {name: "Customer Policy", customerId: "0"}}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_cannot_read_other_customer_policy() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Other Customer Policy", 1).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"{ triagePolicy(id: "0") { name } }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_list_is_filtered_by_customer_scope() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Global Policy").await;
        insert_customer_policy(&schema, 1, "Customer 0 Policy", 0).await;
        insert_customer_policy(&schema, 2, "Customer 1 Policy", 1).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r"{ triagePolicyList(first: 10) { totalCount nodes { name customerId } } }",
            vec![0],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "2");
        let names = node_names(&json);
        assert!(names.contains(&"Global Policy"));
        assert!(names.contains(&"Customer 0 Policy"));
        assert!(!names.contains(&"Customer 1 Policy"));
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_cannot_create_global_policy() {
        let schema = TestSchema::new().await;

        insert_default_triage_exclusion_reason(&schema).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation {
                insertTriagePolicy(
                    name: "Forbidden Global Policy"
                    triageExclusionId: ["0"]
                    packetAttr: []
                    confidence: []
                    response: []
                )
            }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_cannot_create_other_customer_policy() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            &customer_policy_mutation("Forbidden Policy", 1),
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_can_delete_owned_policy() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation { removeTriagePolicies(ids: ["0"]) }"#,
            vec![0],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{removeTriagePolicies: ["Customer Policy"]}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_cannot_delete_other_customer_policy() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Other Customer Policy", 1).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation { removeTriagePolicies(ids: ["0"]) }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_cannot_move_policy_to_other_customer() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer 0 Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
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
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_cannot_promote_policy_to_global() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer 0 Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
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
                        name: "Promoted Global Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                    }
                )
            }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_customer_scoping_admin_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

        let res = schema
            .execute_as_system_admin(r#"{ triagePolicy(id: "0") { name customerId } }"#)
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicy: {name: "Customer Policy", customerId: "0"}}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_customer_scoping_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"{ triagePolicy(id: "0") { name customerId } }"#,
            vec![0],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicy: {name: "Customer Policy", customerId: "0"}}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Other Customer Policy", 1).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"{ triagePolicy(id: "0") { name } }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_customer_scoping_missing_policy() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(r#"{ triagePolicy(id: "99") { name } }"#)
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("no such triage policy"));
    }

    #[tokio::test]
    async fn triage_policy_insert_customer_scoping_admin_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;

        insert_customer_policy(&schema, 0, "Admin Policy", 1).await;
    }

    #[tokio::test]
    async fn triage_policy_insert_customer_scoping_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            &customer_policy_mutation("Allowed Policy", 0),
            vec![0],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{insertTriagePolicy: "0"}"#);
    }

    #[tokio::test]
    async fn triage_policy_insert_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            &customer_policy_mutation("Forbidden Policy", 1),
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));

        let res = schema
            .execute_as_system_admin(r"{ triagePolicyList(first: 10) { totalCount } }")
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "0");
    }

    #[tokio::test]
    async fn triage_policy_insert_global_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;

        insert_default_triage_exclusion_reason(&schema).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation {
                insertTriagePolicy(
                    name: "Forbidden Global Policy"
                    triageExclusionId: ["0"]
                    packetAttr: []
                    confidence: []
                    response: []
                )
            }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));

        let res = schema
            .execute_as_system_admin(r"{ triagePolicyList(first: 10) { totalCount } }")
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "0");
    }

    #[tokio::test]
    async fn triage_policy_global_customer_scoping_allowed() {
        let schema = TestSchema::new().await;

        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Global Policy").await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"{ triagePolicy(id: "0") { name customerId } }"#,
            vec![0],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
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
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{removeTriagePolicies: ["Customer Policy"]}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_remove_customer_scoping_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation { removeTriagePolicies(ids: ["0"]) }"#,
            vec![0],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{removeTriagePolicies: ["Customer Policy"]}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_remove_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Other Customer Policy", 1).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation { removeTriagePolicies(ids: ["0"]) }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_remove_customer_scoping_missing_policy() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(r#"mutation { removeTriagePolicies(ids: ["99"]) }"#)
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("no such triage policy"));
    }

    #[tokio::test]
    async fn triage_policy_list_customer_scoping_admin_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Global Policy").await;
        insert_customer_policy(&schema, 1, "Customer 0 Policy", 0).await;
        insert_customer_policy(&schema, 2, "Customer 1 Policy", 1).await;

        let res = schema
            .execute_as_system_admin(
                r"{ triagePolicyList(first: 10) { totalCount nodes { name customerId } } }",
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "3");
    }

    #[tokio::test]
    async fn triage_policy_list_customer_scoping_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Global Policy").await;
        insert_customer_policy(&schema, 1, "Customer 0 Policy", 0).await;
        insert_customer_policy(&schema, 2, "Customer 1 Policy", 1).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r"{ triagePolicyList(first: 10) { totalCount nodes { name customerId } } }",
            vec![0],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "2");
        let names = node_names(&json);
        assert!(names.contains(&"Global Policy"));
        assert!(names.contains(&"Customer 0 Policy"));
        assert!(!names.contains(&"Customer 1 Policy"));
    }

    #[tokio::test]
    async fn triage_policy_list_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer 0 Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r"{ triagePolicyList(first: 10) { totalCount nodes { name customerId } } }",
            vec![99],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
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

        insert_customers(&schema, &["c0", "c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer 0 Policy", 0).await;
        insert_customer_policy(&schema, 1, "Customer 1 Policy", 1).await;
        insert_customer_policy(&schema, 2, "Customer 2 Policy", 2).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r"{ triagePolicyList(first: 10) { totalCount nodes { name customerId } } }",
            vec![0, 2],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "2");
        let names = node_names(&json);
        assert!(names.contains(&"Customer 0 Policy"));
        assert!(names.contains(&"Customer 2 Policy"));
        assert!(!names.contains(&"Customer 1 Policy"));
    }

    #[tokio::test]
    async fn triage_policy_list_empty_scope_scoping_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Global Policy").await;
        insert_customer_policy(&schema, 1, "Customer Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r"{ triagePolicyList(first: 10) { totalCount nodes { name } } }",
            vec![],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
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
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{updateTriagePolicy: "0"}"#);
    }

    #[tokio::test]
    async fn triage_policy_update_customer_scoping_allowed() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
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
            vec![0],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{updateTriagePolicy: "0"}"#);
    }

    #[tokio::test]
    async fn triage_policy_update_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Other Customer Policy", 1).await;

        let res = execute_as_scoped_security_admin(
            &schema,
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
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_update_customer_scoping_missing_policy() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateTriagePolicy(
                        id: 99
                        old: {
                            name: "Missing Policy"
                            triageExclusionId: []
                            packetAttr: []
                            confidence: []
                            response: []
                        }
                        new: {
                            name: "Updated Policy"
                            triageExclusionId: []
                            packetAttr: []
                            confidence: []
                            response: []
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("no such triage policy"));
    }

    #[tokio::test]
    async fn triage_policy_update_reassign_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer 0 Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
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
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));

        let res = schema
            .execute_as_system_admin(r#"{ triagePolicy(id: "0") { name customerId } }"#)
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicy: {name: "Customer 0 Policy", customerId: "0"}}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_update_to_global_customer_scoping_forbidden() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Customer 0 Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
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
                        name: "Promoted Global Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                    }
                )
            }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));

        let res = schema
            .execute_as_system_admin(r#"{ triagePolicy(id: "0") { name customerId } }"#)
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicy: {name: "Customer 0 Policy", customerId: "0"}}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_cannot_delete_shared_policy() {
        let schema = TestSchema::new().await;

        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Shared Policy").await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation { removeTriagePolicies(ids: ["0"]) }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));

        // Verify the policy still exists.
        let res = schema
            .execute_as_system_admin(r#"{ triagePolicy(id: "0") { name } }"#)
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicy: {name: "Shared Policy"}}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_cannot_update_shared_policy() {
        let schema = TestSchema::new().await;

        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Shared Policy").await;

        // Attempt to update a shared policy while keeping it shared.
        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation {
                updateTriagePolicy(
                    id: 0
                    old: {
                        name: "Shared Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                    }
                    new: {
                        name: "Renamed Shared"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                    }
                )
            }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_cannot_convert_shared_to_customer_owned() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Shared Policy").await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation {
                updateTriagePolicy(
                    id: 0
                    old: {
                        name: "Shared Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                    }
                    new: {
                        name: "Now Customer Owned"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "0"
                    }
                )
            }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_cannot_move_out_of_scope_into_scope() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Out of Scope Policy", 1).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation {
                updateTriagePolicy(
                    id: 0
                    old: {
                        name: "Out of Scope Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "1"
                    }
                    new: {
                        name: "Stolen Policy"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "0"
                    }
                )
            }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));
    }

    #[tokio::test]
    async fn triage_policy_scoped_user_can_reassign_between_in_scope_customers() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Policy A", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation {
                updateTriagePolicy(
                    id: 0
                    old: {
                        name: "Policy A"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "0"
                    }
                    new: {
                        name: "Policy A"
                        triageExclusionId: ["0"]
                        packetAttr: []
                        confidence: []
                        response: []
                        customerId: "1"
                    }
                )
            }"#,
            vec![0, 1],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{updateTriagePolicy: "0"}"#);
    }

    #[tokio::test]
    async fn triage_policy_remove_mixed_permitted_and_forbidden_fails_atomically() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "In Scope Policy", 0).await;
        insert_customer_policy(&schema, 1, "Out of Scope Policy", 1).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation { removeTriagePolicies(ids: ["0", "1"]) }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));

        // Verify neither policy was deleted.
        let res = schema
            .execute_as_system_admin(
                r"{ triagePolicyList(first: 10) { totalCount nodes { name } } }",
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "2");
    }

    #[tokio::test]
    async fn triage_policy_remove_mixed_permitted_and_shared_fails_atomically() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Shared Policy").await;
        insert_customer_policy(&schema, 1, "In Scope Policy", 0).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"mutation { removeTriagePolicies(ids: ["1", "0"]) }"#,
            vec![0],
        )
        .await;
        assert_eq!(res.errors.len(), 1);
        assert!(res.errors[0].message.contains("Forbidden"));

        // Verify neither policy was deleted.
        let res = schema
            .execute_as_system_admin(
                r"{ triagePolicyList(first: 10) { totalCount nodes { name } } }",
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "2");
    }

    #[tokio::test]
    async fn triage_policy_list_with_customer_id_filter_includes_shared() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Shared Policy").await;
        insert_customer_policy(&schema, 1, "Customer 0 Policy", 0).await;
        insert_customer_policy(&schema, 2, "Customer 1 Policy", 1).await;

        let res = execute_as_scoped_security_admin(
            &schema,
            r#"{ triagePolicyList(first: 10, customerId: "0") { totalCount nodes { name } } }"#,
            vec![0],
        )
        .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triagePolicyList"]["totalCount"], "2");
        let names = node_names(&json);
        assert!(names.contains(&"Shared Policy"));
        assert!(names.contains(&"Customer 0 Policy"));
        assert!(!names.contains(&"Customer 1 Policy"));
    }

    #[tokio::test]
    async fn triage_policy_admin_crud_shared_policy() {
        let schema = TestSchema::new().await;

        insert_default_triage_exclusion_reason(&schema).await;
        insert_global_policy(&schema, 0, "Shared Policy").await;

        // Admin can read shared policy.
        let res = schema
            .execute_as_system_admin(r#"{ triagePolicy(id: "0") { name customerId } }"#)
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{triagePolicy: {name: "Shared Policy", customerId: null}}"#
        );

        // Admin can update shared policy.
        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateTriagePolicy(
                        id: 0
                        old: {
                            name: "Shared Policy"
                            triageExclusionId: ["0"]
                            packetAttr: []
                            confidence: []
                            response: []
                        }
                        new: {
                            name: "Updated Shared"
                            triageExclusionId: ["0"]
                            packetAttr: []
                            confidence: []
                            response: []
                        }
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{updateTriagePolicy: "0"}"#);

        // Admin can delete shared policy.
        let res = schema
            .execute_as_system_admin(r#"mutation { removeTriagePolicies(ids: ["0"]) }"#)
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{removeTriagePolicies: ["Updated Shared"]}"#
        );
    }

    #[tokio::test]
    async fn triage_policy_admin_can_reassign_customers() {
        let schema = TestSchema::new().await;

        insert_customers(&schema, &["c1", "c2"]).await;
        insert_default_triage_exclusion_reason(&schema).await;
        insert_customer_policy(&schema, 0, "Policy", 0).await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    updateTriagePolicy(
                        id: 0
                        old: {
                            name: "Policy"
                            triageExclusionId: ["0"]
                            packetAttr: []
                            confidence: []
                            response: []
                            customerId: "0"
                        }
                        new: {
                            name: "Policy"
                            triageExclusionId: ["0"]
                            packetAttr: []
                            confidence: []
                            response: []
                            customerId: "1"
                        }
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "unexpected errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{updateTriagePolicy: "0"}"#);
    }
}
