use async_graphql::{Context, ID, Object, Result};

use super::{Role, Tag};
use crate::graphql::RoleGuard;

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
        let store = crate::graphql::get_store(ctx)?;
        let set = store.event_tag_set()?;
        Ok(set
            .tags()
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
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn insert_event_tag(&self, ctx: &Context<'_>, name: String) -> Result<ID> {
        let store = crate::graphql::get_store(ctx)?;
        let mut set = store.event_tag_set()?;
        let id = set.insert(&name)?;
        Ok(ID(id.to_string()))
    }

    /// Removes an event tag for the given ID.
    ///
    /// This operation is restricted to system administrators.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn remove_event_tag(&self, ctx: &Context<'_>, id: ID) -> Result<Option<String>> {
        let store = crate::graphql::get_store(ctx)?;
        let id_num = id.0.parse::<u32>()?;

        let mut set = store.event_tag_set()?;
        let triage_response_map = store.triage_response_map();
        let name = set.remove_event_tag(id_num, &triage_response_map)?;
        Ok(Some(name))
    }

    /// Updates the name of an event tag for the given ID.
    ///
    /// It returns `true` if the name was updated, `false` if the tag was
    /// different or not found.
    ///
    /// This operation is restricted to system administrators.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn update_event_tag(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: String,
        new: String,
    ) -> Result<bool> {
        let store = crate::graphql::get_store(ctx)?;
        let id_num = id.0.parse::<u32>()?;

        let mut set = store.event_tag_set()?;
        Ok(set.update(id_num, &old, &new)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::{Role, RoleGuard, TestSchema};

    async fn insert_tag(schema: &TestSchema, name: &str) -> String {
        let query = format!(r#"mutation {{ insertEventTag(name: "{name}") }}"#);
        let res = schema.execute_as_system_admin(&query).await;
        assert!(res.errors.is_empty(), "insert errors: {:?}", res.errors);
        res.data.into_json().unwrap()["insertEventTag"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn event_tag_list_is_global() {
        let schema = TestSchema::new().await;

        insert_tag(&schema, "global-a").await;
        insert_tag(&schema, "global-b").await;

        let res = schema
            .execute_as_scoped_user(
                r"{ eventTagList { name } }",
                Role::SecurityAdministrator,
                Some(vec![999]),
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

        assert!(names.contains(&"global-a"));
        assert!(names.contains(&"global-b"));
    }

    #[tokio::test]
    async fn event_tag_list_allowed_for_all_roles() {
        let schema = TestSchema::new().await;
        insert_tag(&schema, "global-read").await;

        for role in [
            Role::SystemAdministrator,
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ] {
            let res = schema
                .execute_with_guard(r"{ eventTagList { name } }", RoleGuard::Role(role))
                .await;
            assert!(res.errors.is_empty(), "list errors: {:?}", res.errors);
        }
    }

    #[tokio::test]
    async fn insert_event_tag_allowed_for_all_roles() {
        let schema = TestSchema::new().await;

        let roles = [
            Role::SystemAdministrator,
            Role::SecurityAdministrator,
            Role::SecurityManager,
            Role::SecurityMonitor,
        ];

        for (idx, role) in roles.into_iter().enumerate() {
            let query = format!(r#"mutation {{ insertEventTag(name: "tag-{idx}") }}"#);
            let res = schema
                .execute_with_guard(&query, RoleGuard::Role(role))
                .await;
            assert!(res.errors.is_empty(), "insert errors: {:?}", res.errors);
        }
    }

    #[tokio::test]
    async fn update_event_tag_allowed_for_system_admin_only() {
        let schema = TestSchema::new().await;
        let tag_id = insert_tag(&schema, "rename-me").await;

        let query = format!(
            r#"mutation {{ updateEventTag(id: "{tag_id}", old: "rename-me", new: "renamed") }}"#
        );

        let res = schema.execute_as_system_admin(&query).await;
        assert!(
            res.errors.is_empty(),
            "admin update errors: {:?}",
            res.errors
        );
        assert_eq!(res.data.to_string(), r"{updateEventTag: true}");

        for (role, suffix) in [
            (Role::SecurityAdministrator, "admin"),
            (Role::SecurityManager, "manager"),
            (Role::SecurityMonitor, "monitor"),
        ] {
            let old_name = format!("rename-me-{suffix}");
            let tag_id = insert_tag(&schema, &old_name).await;
            let query = format!(
                r#"mutation {{ updateEventTag(id: "{tag_id}", old: "{old_name}", new: "renamed") }}"#
            );
            let res = schema
                .execute_with_guard(&query, RoleGuard::Role(role))
                .await;
            assert_eq!(res.errors.len(), 1);
            assert!(res.errors[0].message.contains("Forbidden"));
        }
    }

    #[tokio::test]
    async fn remove_event_tag_allowed_for_system_admin_only() {
        let schema = TestSchema::new().await;

        let tag_id = insert_tag(&schema, "remove-me").await;
        let query = format!(r#"mutation {{ removeEventTag(id: "{tag_id}") }}"#);

        let res = schema.execute_as_system_admin(&query).await;
        assert!(
            res.errors.is_empty(),
            "admin remove errors: {:?}",
            res.errors
        );
        assert_eq!(res.data.to_string(), r#"{removeEventTag: "remove-me"}"#);

        for (role, name) in [
            (Role::SecurityAdministrator, "remove-me-admin"),
            (Role::SecurityManager, "remove-me-manager"),
            (Role::SecurityMonitor, "remove-me-monitor"),
        ] {
            let tag_id = insert_tag(&schema, name).await;
            let query = format!(r#"mutation {{ removeEventTag(id: "{tag_id}") }}"#);
            let res = schema
                .execute_with_guard(&query, RoleGuard::Role(role))
                .await;
            assert_eq!(res.errors.len(), 1);
            assert!(res.errors[0].message.contains("Forbidden"));
        }
    }
}
