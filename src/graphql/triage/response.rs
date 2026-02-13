use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, InputObject, Object, Result, StringNumber,
    connection::{Connection, Edge, EmptyFields},
    types::ID,
};
use chrono::{DateTime, Utc};
use itertools::Itertools;
use review_database::{Indexable, UniqueKey};
use tracing::info;

use super::{Role, RoleGuard};
use crate::graphql::customer_access::{
    derive_customer_id_from_hostname, hostname_customer_id_map, is_member, sensor_from_key,
    users_customers,
};
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
    async fn total_count(&self, ctx: &Context<'_>) -> Result<StringNumber<usize>> {
        use review_database::{Iterable, event::Direction};

        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_response_map();
        let users_cids = users_customers(ctx)?;

        let count = if users_cids.is_none() {
            // Admin: count all
            map.iter(Direction::Forward, None).count()
        } else {
            let hostname_map = hostname_customer_id_map(&store)?;
            // Scoped user: count only accessible responses
            map.iter(Direction::Forward, None)
                .filter_map(std::result::Result::ok)
                .filter(|tr| {
                    let key_bytes = tr.key();
                    let Ok(sensor) = sensor_from_key(&key_bytes) else {
                        return false;
                    };
                    match hostname_map.get(&sensor).copied() {
                        Some(c) => is_member(users_cids.as_deref(), c),
                        None => false,
                    }
                })
                .count()
        };
        Ok(StringNumber(count))
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

/// Checks customer access for a triage response identified by its sensor
/// hostname. Returns `Ok(())` if:
/// - The user is an admin (`users_customers` is `None`), or
/// - The derived customer from the sensor hostname is in the user's
///   accessible customers.
///
/// # Errors
///
/// Returns `Forbidden` if the user does not have access, or if the sensor
/// hostname cannot be resolved to a customer.
fn check_sensor_access(ctx: &Context<'_>, sensor: &str) -> Result<()> {
    let users_cids = users_customers(ctx)?;
    if users_cids.is_none() {
        return Ok(()); // Admin bypass
    }
    let store = crate::graphql::get_store(ctx)?;
    let derived = derive_customer_id_from_hostname(&store, sensor)?;
    match derived {
        Some(cid) if is_member(users_cids.as_deref(), cid) => Ok(()),
        Some(_) | None => Err("Forbidden".into()),
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

    /// Looks up a triage response by the given sensor and time.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn triage_response(
        &self,
        ctx: &Context<'_>,
        sensor: String,
        time: DateTime<Utc>,
    ) -> Result<Option<TriageResponse>> {
        check_sensor_access(ctx, &sensor)?;

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
    let users_cids = users_customers(ctx)?;
    let store = crate::graphql::get_store(ctx)?;
    let table = store.triage_response_map();

    if users_cids.is_none() {
        // Admin: no filtering needed
        crate::graphql::load_edges(&table, after, before, first, last, TriageResponseTotalCount)
    } else {
        let hostname_map = hostname_customer_id_map(&store)?;
        // Scoped user: filter by customer access
        let predicate = |tr: &review_database::TriageResponse| {
            let key_bytes = tr.key();
            let Ok(sensor) = sensor_from_key(&key_bytes) else {
                return false;
            };
            hostname_map
                .get(&sensor)
                .copied()
                .is_some_and(|c| is_member(users_cids.as_deref(), c))
        };

        let (nodes, has_previous, has_next) = crate::graphql::process_load_edges_filtered(
            &table, after, before, first, last, None, predicate,
        );

        let mut connection =
            Connection::with_additional_fields(has_previous, has_next, TriageResponseTotalCount);
        let edges = nodes
            .into_iter()
            .map(|node| -> Result<_> {
                let node = node.map_err(|e| {
                    tracing::warn!("Failed to load from DB: {}", e);
                    async_graphql::Error::new("database error")
                })?;
                let key: Vec<u8> = node.unique_key().to_vec();
                Ok(Edge::new(OpaqueCursor(key), node.into()))
            })
            .collect::<Result<Vec<_>>>()?;
        connection.edges.extend(edges);
        Ok(connection)
    }
}

#[Object]
impl super::TriageResponseMutation {
    /// Inserts a new triage response, returning the ID of the new response.
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
        check_sensor_access(ctx, &sensor)?;

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
        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_response_map();

        let mut removed = Vec::<String>::with_capacity(ids.len());
        for id in ids {
            let i = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;

            // Check customer access before removing
            if users_cids.is_some() {
                let Some(tr) = map.get_by_id(i)? else {
                    return Err("no such triage response".into());
                };
                let key_bytes = tr.key().into_owned();
                let sensor = sensor_from_key(&key_bytes)?;
                let derived = derive_customer_id_from_hostname(&store, &sensor)?;
                match derived {
                    Some(cid) if is_member(users_cids.as_deref(), cid) => {}
                    _ => return Err("Forbidden".into()),
                }
            }

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

        // Check customer access from the key in the old input
        let sensor = sensor_from_key(&old.key)?;
        check_sensor_access(ctx, &sensor)?;

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

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_triage_response_scoped_list_filtering() {
        let schema = TestSchema::new().await;
        let cid_a = schema.setup_customer_and_node("cust-a", "sensor-a").await;
        let _cid_b = schema.setup_customer_and_node("cust-b", "sensor-b").await;
        let cid_a_num: u32 = cid_a.parse().unwrap();

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageResponse(
                        sensor: "sensor-a"
                        time: "2024-01-01T00:00:00Z"
                        tagIds: []
                        remarks: "a"
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "insert a: {:?}", res.errors);

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageResponse(
                        sensor: "sensor-b"
                        time: "2024-01-01T00:00:00Z"
                        tagIds: []
                        remarks: "b"
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "insert b: {:?}", res.errors);

        let res = schema
            .execute_as_system_admin(r"{triageResponseList{totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{triageResponseList: {totalCount: "2"}}"#
        );

        let res = schema
            .execute_as_security_admin_with_customer_ids(
                r"{triageResponseList{totalCount}}",
                vec![cid_a_num],
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            r#"{triageResponseList: {totalCount: "1"}}"#
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_triage_response_scoped_list_pagination_args() {
        let schema = TestSchema::new().await;
        let cid_a1 = schema.setup_customer_and_node("cust-a1", "sensor-a1").await;
        let cid_a2 = schema.setup_customer_and_node("cust-a2", "sensor-a2").await;
        let cid_a3 = schema.setup_customer_and_node("cust-a3", "sensor-a3").await;
        let _cid_b = schema.setup_customer_and_node("cust-b", "sensor-b1").await;
        let cid_a1_num: u32 = cid_a1.parse().unwrap();
        let cid_a2_num: u32 = cid_a2.parse().unwrap();
        let cid_a3_num: u32 = cid_a3.parse().unwrap();
        let scoped_customer_ids = vec![cid_a1_num, cid_a2_num, cid_a3_num];

        for (sensor, remarks) in [
            ("sensor-a1", "a1"),
            ("sensor-a2", "a2"),
            ("sensor-a3", "a3"),
            ("sensor-b1", "b1"),
        ] {
            let query = format!(
                r#"mutation {{
                    insertTriageResponse(
                        sensor: "{sensor}"
                        time: "2024-01-01T00:00:00Z"
                        tagIds: []
                        remarks: "{remarks}"
                    )
                }}"#,
            );
            let res = schema.execute_as_system_admin(&query).await;
            assert!(res.errors.is_empty(), "insert {sensor}: {:?}", res.errors);
        }

        let res = schema
            .execute_as_security_admin_with_customer_ids(
                r"{
                    triageResponseList(first: 10) {
                        totalCount
                        edges { cursor node { remarks } }
                    }
                }",
                scoped_customer_ids.clone(),
            )
            .await;
        assert!(res.errors.is_empty(), "full list errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triageResponseList"]["totalCount"], "3");
        let edges = json["triageResponseList"]["edges"].as_array().unwrap();
        assert_eq!(edges.len(), 3);
        let visible_remarks: Vec<String> = edges
            .iter()
            .map(|edge| edge["node"]["remarks"].as_str().unwrap().to_string())
            .collect();

        let res = schema
            .execute_as_security_admin_with_customer_ids(
                r"{
                    triageResponseList(first: 1) {
                        edges { cursor node { remarks } }
                        pageInfo { endCursor hasNextPage }
                    }
                }",
                scoped_customer_ids.clone(),
            )
            .await;
        assert!(res.errors.is_empty(), "first errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        let first_edges = json["triageResponseList"]["edges"].as_array().unwrap();
        assert_eq!(first_edges.len(), 1);
        assert_eq!(
            first_edges[0]["node"]["remarks"].as_str().unwrap(),
            visible_remarks[0]
        );
        assert_eq!(json["triageResponseList"]["pageInfo"]["hasNextPage"], true);
        let after_cursor = json["triageResponseList"]["pageInfo"]["endCursor"]
            .as_str()
            .unwrap()
            .to_string();

        let query = format!(
            r#"{{
                triageResponseList(after: "{after_cursor}") {{
                    edges {{ node {{ remarks }} }}
                }}
            }}"#,
        );
        let res = schema
            .execute_as_security_admin_with_customer_ids(&query, scoped_customer_ids.clone())
            .await;
        assert!(res.errors.is_empty(), "after errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        let after_remarks: Vec<String> = json["triageResponseList"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["node"]["remarks"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(after_remarks, visible_remarks[1..].to_vec());

        let res = schema
            .execute_as_security_admin_with_customer_ids(
                r"{
                    triageResponseList(last: 1) {
                        edges { cursor node { remarks } }
                        pageInfo { startCursor hasPreviousPage }
                    }
                }",
                scoped_customer_ids.clone(),
            )
            .await;
        assert!(res.errors.is_empty(), "last errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        let last_edges = json["triageResponseList"]["edges"].as_array().unwrap();
        assert_eq!(last_edges.len(), 1);
        assert_eq!(
            last_edges[0]["node"]["remarks"].as_str().unwrap(),
            visible_remarks.last().unwrap()
        );
        assert_eq!(
            json["triageResponseList"]["pageInfo"]["hasPreviousPage"],
            true
        );
        let before_cursor = json["triageResponseList"]["pageInfo"]["startCursor"]
            .as_str()
            .unwrap()
            .to_string();

        let query = format!(
            r#"{{
                triageResponseList(before: "{before_cursor}") {{
                    edges {{ node {{ remarks }} }}
                }}
            }}"#,
        );
        let res = schema
            .execute_as_security_admin_with_customer_ids(&query, scoped_customer_ids)
            .await;
        assert!(res.errors.is_empty(), "before errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        let before_remarks: Vec<String> = json["triageResponseList"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .map(|edge| edge["node"]["remarks"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            before_remarks,
            visible_remarks[..visible_remarks.len() - 1].to_vec()
        );
    }

    #[tokio::test]
    async fn test_triage_response_scoped_query_allowed() {
        let schema = TestSchema::new().await;
        let cid = schema.setup_customer_and_node("cust-a", "sensor-a").await;
        let cid_num: u32 = cid.parse().unwrap();

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageResponse(
                        sensor: "sensor-a"
                        time: "2024-01-01T00:00:00Z"
                        tagIds: [1]
                        remarks: "visible"
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "insert response: {:?}", res.errors);

        let res = schema
            .execute_as_security_admin_with_customer_ids(
                r#"{ triageResponse(sensor: "sensor-a", time: "2024-01-01T00:00:00Z") { id remarks } }"#,
                vec![cid_num],
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triageResponse"]["id"], "0");
        assert_eq!(json["triageResponse"]["remarks"], "visible");
    }

    #[tokio::test]
    async fn test_triage_response_scoped_query_forbidden() {
        let schema = TestSchema::new().await;
        let _cid = schema.setup_customer_and_node("cust-a", "sensor-a").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageResponse(
                        sensor: "sensor-a"
                        time: "2024-01-01T00:00:00Z"
                        tagIds: []
                        remarks: "x"
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty());

        let res = schema
            .execute_as_security_admin_with_customer_ids(
                r#"{ triageResponse(sensor: "sensor-a", time: "2024-01-01T00:00:00Z") { id } }"#,
                vec![999],
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn test_triage_response_scoped_insert_allowed() {
        let schema = TestSchema::new().await;
        let cid = schema.setup_customer_and_node("cust-a", "sensor-a").await;
        let cid_num: u32 = cid.parse().unwrap();

        let res = schema
            .execute_as_security_admin_with_customer_ids(
                r#"mutation {
                    insertTriageResponse(
                        sensor: "sensor-a"
                        time: "2024-01-01T00:00:00Z"
                        tagIds: []
                        remarks: "ok"
                    )
                }"#,
                vec![cid_num],
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
    }

    #[tokio::test]
    async fn test_triage_response_scoped_insert_forbidden() {
        let schema = TestSchema::new().await;
        let _cid = schema.setup_customer_and_node("cust-a", "sensor-a").await;

        let res = schema
            .execute_as_security_admin_with_customer_ids(
                r#"mutation {
                    insertTriageResponse(
                        sensor: "sensor-a"
                        time: "2024-01-01T00:00:00Z"
                        tagIds: []
                        remarks: "nope"
                    )
                }"#,
                vec![999],
            )
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn test_triage_response_scoped_remove_allowed() {
        let schema = TestSchema::new().await;
        let cid = schema.setup_customer_and_node("cust-a", "sensor-a").await;
        let cid_num: u32 = cid.parse().unwrap();

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageResponse(
                        sensor: "sensor-a"
                        time: "2024-01-01T00:00:00Z"
                        tagIds: []
                        remarks: "x"
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "insert response: {:?}", res.errors);
        let id = res.data.to_string().split('"').nth(1).unwrap().to_string();

        let query = format!(r"mutation {{ removeTriageResponses(ids: [{id}]) }}");
        let res = schema
            .execute_as_security_admin_with_customer_ids(&query, vec![cid_num])
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            format!(r#"{{removeTriageResponses: ["{id}"]}}"#)
        );
    }

    #[tokio::test]
    async fn test_triage_response_scoped_remove_forbidden() {
        let schema = TestSchema::new().await;
        let _cid = schema.setup_customer_and_node("cust-a", "sensor-a").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageResponse(
                        sensor: "sensor-a"
                        time: "2024-01-01T00:00:00Z"
                        tagIds: []
                        remarks: "x"
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty());
        let id = res.data.to_string().split('"').nth(1).unwrap().to_string();

        let query = format!(r"mutation {{ removeTriageResponses(ids: [{id}]) }}");
        let res = schema
            .execute_as_security_admin_with_customer_ids(&query, vec![999])
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn test_triage_response_scoped_update_allowed() {
        let schema = TestSchema::new().await;
        let cid = schema.setup_customer_and_node("cust-a", "sensor1").await;
        let cid_num: u32 = cid.parse().unwrap();

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageResponse(
                        sensor: "sensor1"
                        time: "2023-02-14 14:54:46.083902898 +00:00"
                        tagIds: [1, 2, 3]
                        remarks: "before"
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "insert response: {:?}", res.errors);
        let id = res.data.to_string().split('"').nth(1).unwrap().to_string();

        let query = format!(
            r#"mutation {{
                updateTriageResponse(
                    id: "{id}"
                    old: {{
                        key: [115, 101, 110, 115, 111, 114, 49, 23, 67, 184, 160, 145, 75, 221, 178]
                        tagIds: [1, 2, 3]
                        remarks: "before"
                    }}
                    new: {{
                        key: [115, 101, 110, 115, 111, 114, 49, 23, 67, 184, 160, 145, 75, 221, 178]
                        tagIds: [2, 3]
                        remarks: "after"
                    }}
                )
            }}"#,
        );
        let res = schema
            .execute_as_security_admin_with_customer_ids(&query, vec![cid_num])
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        assert_eq!(
            res.data.to_string(),
            format!(r#"{{updateTriageResponse: "{id}"}}"#)
        );

        let res = schema
            .execute_as_security_admin_with_customer_ids(
                r#"{ triageResponse(sensor: "sensor1", time: "2023-02-14 14:54:46.083902898 +00:00") { remarks tagIds } }"#,
                vec![cid_num],
            )
            .await;
        assert!(res.errors.is_empty(), "query errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["triageResponse"]["remarks"], "after");
        assert_eq!(json["triageResponse"]["tagIds"][0], "2");
        assert_eq!(json["triageResponse"]["tagIds"][1], "3");
    }

    #[tokio::test]
    async fn test_triage_response_scoped_update_forbidden() {
        let schema = TestSchema::new().await;
        let _cid = schema.setup_customer_and_node("cust-a", "sensor1").await;

        let res = schema
            .execute_as_system_admin(
                r#"mutation {
                    insertTriageResponse(
                        sensor: "sensor1"
                        time: "2023-02-14 14:54:46.083902898 +00:00"
                        tagIds: [1, 2, 3]
                        remarks: "before"
                    )
                }"#,
            )
            .await;
        assert!(res.errors.is_empty(), "insert response: {:?}", res.errors);
        let id = res.data.to_string().split('"').nth(1).unwrap().to_string();

        let query = format!(
            r#"mutation {{
                updateTriageResponse(
                    id: "{id}"
                    old: {{
                        key: [115, 101, 110, 115, 111, 114, 49, 23, 67, 184, 160, 145, 75, 221, 178]
                        tagIds: [1, 2, 3]
                        remarks: "before"
                    }}
                    new: {{
                        key: [115, 101, 110, 115, 111, 114, 49, 23, 67, 184, 160, 145, 75, 221, 178]
                        tagIds: [2, 3]
                        remarks: "after"
                    }}
                )
            }}"#,
        );
        let res = schema
            .execute_as_security_admin_with_customer_ids(&query, vec![999])
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn test_triage_response() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(r"{triageResponseList{totalCount}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{triageResponseList: {totalCount: "0"}}"#
        );

        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    insertTriageResponse(
                        sensor: "sensor1"
                        time: "2023-02-14 14:54:46.083902898 +00:00"
                        tagIds: [1, 2, 3]
                        remarks: "Hello World"
                    )
                }
                "#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTriageResponse: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    updateTriageResponse(
                        id: "0"
                        old: {
                            key: [
                                115,
                                101,
                                110,
                                115,
                                111,
                                114,
                                49,
                                23,
                                67,
                                184,
                                160,
                                145,
                                75,
                                221,
                                178
                            ]
                            tagIds:[1, 2, 3]
                            remarks:"Hello World"
                        }
                        new: {
                            key: [
                                115,
                                101,
                                110,
                                115,
                                111,
                                114,
                                49,
                                23,
                                67,
                                184,
                                160,
                                145,
                                75,
                                221,
                                178
                            ]
                            tagIds:[2, 3]
                        }
                    )
                }
                "#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateTriageResponse: "0"}"#);

        let res = schema
            .execute_as_system_admin(
                r"
                mutation {
                    removeTriageResponses(ids: [0])
                }
                ",
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{removeTriageResponses: ["0"]}"#);
    }
}
