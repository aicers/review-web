use std::collections::HashSet;

use async_graphql::{Context, ID, Object, Result};
use review_database::{Indexable, Iterable, Store, event::Direction};

use super::{Role, Tag};
use crate::graphql::RoleGuard;
use crate::graphql::customer_access::{
    hostname_customer_id_map, is_member, sensor_from_key, users_customers,
};

/// Collects the set of event-tag IDs referenced by `TriageResponse`s that
/// the current user is allowed to see.
///
/// Returns `Ok(None)` for administrators (no filtering needed), or
/// `Ok(Some(HashSet))` for scoped users.
fn accessible_tag_ids(store: &Store, users_cids: Option<&[u32]>) -> Result<Option<HashSet<u32>>> {
    if users_cids.is_none() {
        return Ok(None); // Admin: all tags are accessible
    }

    let hostname_map = hostname_customer_id_map(store)?;
    let map = store.triage_response_map();
    let mut tag_ids = HashSet::new();

    for entry in map.iter(Direction::Forward, None) {
        let tr = entry.map_err(|e| {
            async_graphql::Error::new(format!("failed to iterate triage responses: {e}"))
        })?;
        let key_bytes = tr.key();
        let Ok(sensor) = sensor_from_key(&key_bytes) else {
            continue;
        };
        match hostname_map.get(&sensor).copied() {
            Some(c) if is_member(users_cids, c) => {
                tag_ids.extend(tr.tag_ids().iter().copied());
            }
            _ => {}
        }
    }

    Ok(Some(tag_ids))
}

/// Checks that the user has access to **all** `TriageResponse`s that
/// reference the given `tag_id`.
///
/// Returns `Ok(())` for administrators or when every referencing response
/// belongs to an accessible customer. Returns `Err("Forbidden")` if any
/// referencing response belongs to an inaccessible customer.
fn check_tag_access(store: &Store, users_cids: Option<&[u32]>, tag_id: u32) -> Result<()> {
    if users_cids.is_none() {
        return Ok(()); // Admin bypass
    }

    let hostname_map = hostname_customer_id_map(store)?;
    let map = store.triage_response_map();

    for entry in map.iter(Direction::Forward, None) {
        let tr = entry.map_err(|e| {
            async_graphql::Error::new(format!("failed to iterate triage responses: {e}"))
        })?;
        if !tr.tag_ids().contains(&tag_id) {
            continue;
        }
        let key_bytes = tr.key();
        let Ok(sensor) = sensor_from_key(&key_bytes) else {
            return Err("Forbidden".into());
        };
        match hostname_map.get(&sensor).copied() {
            Some(c) if is_member(users_cids, c) => {}
            _ => return Err("Forbidden".into()),
        }
    }

    Ok(())
}

#[derive(Default)]
pub(in crate::graphql) struct EventTagQuery;

#[Object]
impl EventTagQuery {
    /// A list of event tags.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn event_tag_list(&self, ctx: &Context<'_>) -> Result<Vec<Tag>> {
        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let allowed = accessible_tag_ids(&store, users_cids.as_deref())?;
        let set = store.event_tag_set()?;

        Ok(set
            .tags()
            .filter(|tag| match &allowed {
                None => true, // Admin: all tags visible
                Some(ids) => ids.contains(&tag.id),
            })
            .map(|tag| Tag {
                id: tag.id,
                name: tag.name.clone(),
            })
            .collect())
    }
}

#[derive(Default)]
pub(in crate::graphql) struct EventTagMutation;

#[Object]
impl EventTagMutation {
    /// Inserts a new event tag, returning the ID of the new tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn insert_event_tag(&self, ctx: &Context<'_>, name: String) -> Result<ID> {
        let store = crate::graphql::get_store(ctx)?;
        let mut set = store.event_tag_set()?;
        let id = set.insert(&name)?;
        Ok(ID(id.to_string()))
    }

    /// Removes an event tag for the given ID, returning the name of the removed
    /// tag.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn remove_event_tag(&self, ctx: &Context<'_>, id: ID) -> Result<Option<String>> {
        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let id_num = id.0.parse::<u32>()?;
        check_tag_access(&store, users_cids.as_deref(), id_num)?;

        let mut set = store.event_tag_set()?;
        let triage_response_map = store.triage_response_map();
        let name = set.remove_event_tag(id_num, &triage_response_map)?;
        Ok(Some(name))
    }

    /// Updates the name of an event tag for the given ID.
    ///
    /// It returns `true` if the name was updated, `false` if the tag was
    /// different or not found.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))")]
    async fn update_event_tag(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: String,
        new: String,
    ) -> Result<bool> {
        let users_cids = users_customers(ctx)?;
        let store = crate::graphql::get_store(ctx)?;
        let id_num = id.0.parse::<u32>()?;
        check_tag_access(&store, users_cids.as_deref(), id_num)?;

        let mut set = store.event_tag_set()?;
        Ok(set.update(id_num, &old, &new)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_event_tag_list_scoped() {
        let schema = TestSchema::new().await;
        let cid_a = schema.setup_customer_and_node("cust-a", "sensor-a").await;
        let _cid_b = schema.setup_customer_and_node("cust-b", "sensor-b").await;
        let cid_a_num: u32 = cid_a.parse().unwrap();

        let res = schema
            .execute_as_system_admin(r#"mutation { insertEventTag(name: "tag-alpha") }"#)
            .await;
        assert!(res.errors.is_empty(), "insert tag-alpha: {:?}", res.errors);
        let tag_alpha_id: u32 = res
            .data
            .to_string()
            .split('"')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();

        let res = schema
            .execute_as_system_admin(r#"mutation { insertEventTag(name: "tag-beta") }"#)
            .await;
        assert!(res.errors.is_empty(), "insert tag-beta: {:?}", res.errors);
        let tag_beta_id: u32 = res
            .data
            .to_string()
            .split('"')
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();

        let query_a = format!(
            r#"mutation {{
                insertTriageResponse(
                    sensor: "sensor-a"
                    time: "2024-01-01T00:00:00Z"
                    tagIds: [{tag_alpha_id}]
                    remarks: "a"
                )
            }}"#,
        );
        let res = schema.execute_as_system_admin(&query_a).await;
        assert!(res.errors.is_empty(), "insert resp a: {:?}", res.errors);

        let query_b = format!(
            r#"mutation {{
                insertTriageResponse(
                    sensor: "sensor-b"
                    time: "2024-01-01T00:00:00Z"
                    tagIds: [{tag_beta_id}]
                    remarks: "b"
                )
            }}"#,
        );
        let res = schema.execute_as_system_admin(&query_b).await;
        assert!(res.errors.is_empty(), "insert resp b: {:?}", res.errors);

        let res = schema
            .execute_as_system_admin(r"{ eventTagList { name } }")
            .await;
        assert!(res.errors.is_empty());
        let json = res.data.into_json().unwrap();
        let names: Vec<&str> = json["eventTagList"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"tag-alpha"));
        assert!(names.contains(&"tag-beta"));

        let res = schema
            .execute_as_security_admin_with_customer_ids(
                r"{ eventTagList { name } }",
                vec![cid_a_num],
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        let names: Vec<&str> = json["eventTagList"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"tag-alpha"));
        assert!(!names.contains(&"tag-beta"));
    }

    #[tokio::test]
    async fn test_event_tag_list_scoped_shared_tag_visible_with_reachable_policy() {
        let schema = TestSchema::new().await;
        let cid_a = schema.setup_customer_and_node("cust-a", "sensor-a").await;
        let _cid_b = schema.setup_customer_and_node("cust-b", "sensor-b").await;
        let cid_a_num: u32 = cid_a.parse().unwrap();

        let res = schema
            .execute_as_system_admin(r#"mutation { insertEventTag(name: "shared-tag") }"#)
            .await;
        assert!(res.errors.is_empty(), "insert shared-tag: {:?}", res.errors);
        let tag_id = res.data.to_string().split('"').nth(1).unwrap().to_string();

        for sensor in ["sensor-a", "sensor-b"] {
            let query = format!(
                r#"mutation {{
                    insertTriageResponse(
                        sensor: "{sensor}"
                        time: "2024-01-01T00:00:00Z"
                        tagIds: [{tag_id}]
                        remarks: "x"
                    )
                }}"#,
            );
            let res = schema.execute_as_system_admin(&query).await;
            assert!(
                res.errors.is_empty(),
                "insert triage response for {sensor}: {:?}",
                res.errors
            );
        }

        let res = schema
            .execute_as_security_admin_with_customer_ids(
                r"{ eventTagList { name } }",
                vec![cid_a_num],
            )
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);

        let json = res.data.into_json().unwrap();
        let names: Vec<&str> = json["eventTagList"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();

        // Current list policy is reachable-based: visible if at least one
        // accessible triage response references the tag.
        assert!(names.contains(&"shared-tag"));
    }

    #[tokio::test]
    async fn test_event_tag_insert() {
        let schema = TestSchema::new().await;

        let res = schema
            .execute_as_system_admin(r#"mutation { insertEventTag(name: "new-tag") }"#)
            .await;
        assert!(res.errors.is_empty(), "insert errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{insertEventTag: "0"}"#);

        let res = schema
            .execute_as_system_admin(r"{ eventTagList { id name } }")
            .await;
        assert!(res.errors.is_empty(), "list errors: {:?}", res.errors);
        let json = res.data.into_json().unwrap();
        assert_eq!(json["eventTagList"][0]["id"], "0");
        assert_eq!(json["eventTagList"][0]["name"], "new-tag");
    }

    #[tokio::test]
    async fn test_event_tag_remove_scoped_allowed() {
        let schema = TestSchema::new().await;
        let cid_a = schema.setup_customer_and_node("cust-a", "sensor-a").await;
        let cid_a_num: u32 = cid_a.parse().unwrap();

        let res = schema
            .execute_as_system_admin(r#"mutation { insertEventTag(name: "only-a") }"#)
            .await;
        assert!(res.errors.is_empty());
        let tag_id = res.data.to_string().split('"').nth(1).unwrap().to_string();

        let query = format!(
            r#"mutation {{
                insertTriageResponse(
                    sensor: "sensor-a"
                    time: "2024-01-01T00:00:00Z"
                    tagIds: [{tag_id}]
                    remarks: "x"
                )
            }}"#,
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty());

        let query = format!(r#"mutation {{ removeEventTag(id: "{tag_id}") }}"#);
        let res = schema
            .execute_as_security_admin_with_customer_ids(&query, vec![cid_a_num])
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r#"{removeEventTag: "only-a"}"#);
    }

    #[tokio::test]
    async fn test_event_tag_remove_scoped_forbidden() {
        let schema = TestSchema::new().await;
        let _cid_a = schema.setup_customer_and_node("cust-a", "sensor-a").await;
        let cid_b = schema.setup_customer_and_node("cust-b", "sensor-b").await;
        let cid_b_num: u32 = cid_b.parse().unwrap();

        let res = schema
            .execute_as_system_admin(r#"mutation { insertEventTag(name: "only-a") }"#)
            .await;
        assert!(res.errors.is_empty());
        let tag_id = res.data.to_string().split('"').nth(1).unwrap().to_string();

        let query = format!(
            r#"mutation {{
                insertTriageResponse(
                    sensor: "sensor-a"
                    time: "2024-01-01T00:00:00Z"
                    tagIds: [{tag_id}]
                    remarks: "x"
                )
            }}"#,
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty());

        let query = format!(r#"mutation {{ removeEventTag(id: "{tag_id}") }}"#);
        let res = schema
            .execute_as_security_admin_with_customer_ids(&query, vec![cid_b_num])
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn test_event_tag_update_scoped_allowed() {
        let schema = TestSchema::new().await;
        let cid_a = schema.setup_customer_and_node("cust-a", "sensor-a").await;
        let cid_a_num: u32 = cid_a.parse().unwrap();

        let res = schema
            .execute_as_system_admin(r#"mutation { insertEventTag(name: "rename-me") }"#)
            .await;
        assert!(res.errors.is_empty());
        let tag_id = res.data.to_string().split('"').nth(1).unwrap().to_string();

        let query = format!(
            r#"mutation {{
                insertTriageResponse(
                    sensor: "sensor-a"
                    time: "2024-01-01T00:00:00Z"
                    tagIds: [{tag_id}]
                    remarks: "x"
                )
            }}"#,
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty());

        let query = format!(
            r#"mutation {{ updateEventTag(id: "{tag_id}", old: "rename-me", new: "renamed") }}"#
        );
        let res = schema
            .execute_as_security_admin_with_customer_ids(&query, vec![cid_a_num])
            .await;
        assert!(res.errors.is_empty(), "errors: {:?}", res.errors);
        assert_eq!(res.data.to_string(), r"{updateEventTag: true}");
    }

    #[tokio::test]
    async fn test_event_tag_update_scoped_forbidden() {
        let schema = TestSchema::new().await;
        let _cid_a = schema.setup_customer_and_node("cust-a", "sensor-a").await;
        let cid_b = schema.setup_customer_and_node("cust-b", "sensor-b").await;
        let cid_b_num: u32 = cid_b.parse().unwrap();

        let res = schema
            .execute_as_system_admin(r#"mutation { insertEventTag(name: "rename-me") }"#)
            .await;
        assert!(res.errors.is_empty());
        let tag_id = res.data.to_string().split('"').nth(1).unwrap().to_string();

        let query = format!(
            r#"mutation {{
                insertTriageResponse(
                    sensor: "sensor-a"
                    time: "2024-01-01T00:00:00Z"
                    tagIds: [{tag_id}]
                    remarks: "x"
                )
            }}"#,
        );
        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty());

        let query = format!(
            r#"mutation {{ updateEventTag(id: "{tag_id}", old: "rename-me", new: "renamed") }}"#
        );
        let res = schema
            .execute_as_security_admin_with_customer_ids(&query, vec![cid_b_num])
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }

    #[tokio::test]
    async fn test_event_tag_update_scoped_forbidden_with_shared_tag() {
        let schema = TestSchema::new().await;
        let cid_a = schema.setup_customer_and_node("cust-a", "sensor-a").await;
        let _cid_b = schema.setup_customer_and_node("cust-b", "sensor-b").await;
        let cid_a_num: u32 = cid_a.parse().unwrap();

        let res = schema
            .execute_as_system_admin(r#"mutation { insertEventTag(name: "shared-tag") }"#)
            .await;
        assert!(res.errors.is_empty(), "insert shared-tag: {:?}", res.errors);
        let tag_id = res.data.to_string().split('"').nth(1).unwrap().to_string();

        for sensor in ["sensor-a", "sensor-b"] {
            let query = format!(
                r#"mutation {{
                    insertTriageResponse(
                        sensor: "{sensor}"
                        time: "2024-01-01T00:00:00Z"
                        tagIds: [{tag_id}]
                        remarks: "x"
                    )
                }}"#,
            );
            let res = schema.execute_as_system_admin(&query).await;
            assert!(
                res.errors.is_empty(),
                "insert triage response for {sensor}: {:?}",
                res.errors
            );
        }

        let query = format!(
            r#"mutation {{ updateEventTag(id: "{tag_id}", old: "shared-tag", new: "renamed") }}"#
        );
        let res = schema
            .execute_as_security_admin_with_customer_ids(&query, vec![cid_a_num])
            .await;
        assert_eq!(res.errors.len(), 1);
        assert_eq!(res.errors[0].message, "Forbidden");
    }
}
