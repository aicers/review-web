use async_graphql::{
    connection::{Connection, EmptyFields},
    Context, Object, Result, SimpleObject,
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
    ) -> Result<Connection<String, TrustedDomain, EmptyFields, EmptyFields>> {
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

    /// Removes a trusted domain, returning the old value if it existed.
    #[graphql(
        guard = "RoleGuard::new(Role::SystemAdministrator).or(RoleGuard::new(Role::SecurityAdministrator))"
    )]
    async fn remove_trusted_domain(&self, ctx: &Context<'_>, name: String) -> Result<String> {
        {
            let store = crate::graphql::get_store(ctx).await?;
            let map = store.trusted_domain_map();
            map.remove(&name)?;
        }

        let agent_manager = ctx.data::<Box<dyn AgentManager>>()?;
        agent_manager.broadcast_trusted_domains().await?;
        Ok(name)
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

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, TrustedDomain, EmptyFields, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.trusted_domain_map();
    super::load_edges(&map, after, before, first, last, EmptyFields)
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn trusted_domain_list() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(r#"{trustedDomainList{edges{node{name}}}}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{trustedDomainList: {edges: []}}"#);

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
            .execute(r#"{trustedDomainList{edges{node{name}}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{trustedDomainList: {edges: [{node: {name: "example1.com"}}, {node: {name: "example2.org"}}]}}"#
        );

        let res = schema
            .execute(r#"mutation{removeTrustedDomain(name:"example1.com")}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{removeTrustedDomain: "example1.com"}"#
        );

        let res = schema
            .execute(r#"{trustedDomainList{edges{node{name}}}}"#)
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{trustedDomainList: {edges: [{node: {name: "example2.org"}}]}}"#
        );
    }
}
