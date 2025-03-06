use async_graphql::connection::OpaqueCursor;
use async_graphql::{
    Context, InputObject, Object, Result, SimpleObject,
    connection::{Connection, EmptyFields},
};

use super::{AgentManager, BoxedAgentManager, Role, RoleGuard};
use crate::graphql::query_with_constraints;

#[derive(Default)]
pub(super) struct TrustedDomainQuery;

#[Object]
impl TrustedDomainQuery {
    /// A list of trusted domains.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn trusted_domain_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<OpaqueCursor<Vec<u8>>, TrustedDomain, EmptyFields, EmptyFields>> {
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move { load(ctx, after, before, first, last).await },
        )
        .await
    }
}

#[derive(Default)]
pub(super) struct TrustedDomainMutation;

#[Object]
impl TrustedDomainMutation {
    /// Inserts a new trusted domain, returning the last remarks if it was set.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_trusted_domain(
        &self,
        ctx: &Context<'_>,
        name: String,
        remarks: String,
    ) -> Result<String> {
        let name = {
            let store = crate::graphql::get_store(ctx).await?;
            let map = store.trusted_domain_map();
            let entry = review_database::TrustedDomain { name, remarks };
            map.put(&entry)?;
            entry.name
        };

        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        agent_manager.broadcast_trusted_domains().await?;
        Ok(name)
    }

    /// Updates a trusted domain, returning the new value.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_trusted_domain(
        &self,
        ctx: &Context<'_>,
        old: TrustedDomainInput,
        new: TrustedDomainInput,
    ) -> Result<String> {
        let name = {
            let store = crate::graphql::get_store(ctx).await?;
            let map = store.trusted_domain_map();
            let old = review_database::TrustedDomain::from(old);
            let new = review_database::TrustedDomain::from(new);
            map.update(&old, &new)?;
            new.name
        };

        let agent_manager = ctx.data::<BoxedAgentManager>()?;
        agent_manager.broadcast_trusted_domains().await?;
        Ok(name)
    }

    /// Removes multiple trusted domains, returning the old values if they existed.
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn remove_trusted_domains(
        &self,
        ctx: &Context<'_>,
        names: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.trusted_domain_map();

        let removed: Vec<String> = names
            .iter()
            .filter_map(|name| map.remove(name).ok().map(|()| name.clone()))
            .collect();

        let agent_manager = ctx.data::<Box<dyn AgentManager>>()?;
        agent_manager.broadcast_trusted_domains().await?;

        Ok(removed)
    }
}

#[derive(SimpleObject)]
pub(super) struct TrustedDomain {
    name: String,
    remarks: String,
}

impl From<review_database::TrustedDomain> for TrustedDomain {
    fn from(input: review_database::TrustedDomain) -> Self {
        Self {
            name: input.name,
            remarks: input.remarks,
        }
    }
}

#[derive(InputObject)]
pub(super) struct TrustedDomainInput {
    name: String,
    remarks: String,
}

impl From<TrustedDomainInput> for review_database::TrustedDomain {
    fn from(input: TrustedDomainInput) -> Self {
        Self {
            name: input.name,
            remarks: input.remarks,
        }
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<OpaqueCursor<Vec<u8>>>,
    before: Option<OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, TrustedDomain, EmptyFields, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.trusted_domain_map();
    super::load_edges(&map, after, before, first, last, EmptyFields)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::graphql::{BoxedAgentManager, MockAgentManager, TestSchema};

    #[tokio::test]
    async fn trusted_domain_list() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(r"{trustedDomainList{edges{node{name}}}}")
            .await;
        assert_eq!(res.data.to_string(), r"{trustedDomainList: {edges: []}}");

        let res = schema
            .execute(r#"mutation{insertTrustedDomain(name:"example1.com",remarks:"test")}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTrustedDomain: "example1.com"}"#
        );
        let res = schema
            .execute(r#"mutation{insertTrustedDomain(name:"example2.org",remarks:"test")}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTrustedDomain: "example2.org"}"#
        );
        let res = schema
            .execute(r#"mutation{insertTrustedDomain(name:"example3.org",remarks:"test")}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTrustedDomain: "example3.org"}"#
        );

        let res = schema
            .execute(r"{trustedDomainList{edges{node{name}}}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{trustedDomainList: {edges: [{node: {name: "example1.com"}}, {node: {name: "example2.org"}}, {node: {name: "example3.org"}}]}}"#
        );

        let res = schema
            .execute(r#"mutation{removeTrustedDomains(names:["example1.com", "example2.org"])}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{removeTrustedDomains: ["example1.com", "example2.org"]}"#
        );

        let res = schema
            .execute(r"{trustedDomainList{edges{node{name}}}}")
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{trustedDomainList: {edges: [{node: {name: "example3.org"}}]}}"#
        );
    }

    #[tokio::test]
    async fn update_trusted_domain() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let test_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let schema = TestSchema::new_with_params(agent_manager, Some(test_addr), "testuser").await;
        let insert_query = r#"
              mutation {
                insertTrustedDomain(
                    name: "test.com"
                    remarks: "origin_remarks"
                )
              }
              "#;
        let update_query = r#"
              mutation {
                updateTrustedDomain(
                    old: {
                        name: "test.com"
                        remarks: "origin_remarks"
                    }
                    new: {
                        name: "test2.com"
                        remarks: "updated_remarks"
                    }
                )
              }
              "#;

        let res = schema.execute(update_query).await;
        assert_eq!(
            res.errors.first().unwrap().message,
            "no such entry".to_string()
        );

        let res = schema.execute(insert_query).await;
        assert_eq!(res.data.to_string(), r#"{insertTrustedDomain: "test.com"}"#);

        let res = schema.execute(update_query).await;
        assert_eq!(
            res.data.to_string(),
            r#"{updateTrustedDomain: "test2.com"}"#
        );
    }
}
