use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, InputObject, Object, Result, SimpleObject,
};
use regex::Regex;

use super::{AgentManager, BoxedAgentManager, Role, RoleGuard};

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
        query(
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

    /// Update a trusted domain, returning the new value if it passes domain validation.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_trusted_domain(
        &self,
        ctx: &Context<'_>,
        old: TrustedDomainInput,
        new: TrustedDomainInput,
    ) -> Result<String> {
        if !is_valid_domain(&new.name) {
            return Err(TrustedDomainError::InvalidDomainName(String::from(&new.name)).into());
        }

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
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, TrustedDomain, EmptyFields, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.trusted_domain_map();
    super::load_edges(&map, after, before, first, last, EmptyFields)
}

fn is_valid_domain(domain: &str) -> bool {
    let domain_regex =
        Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$").unwrap();
    domain_regex.is_match(domain)
}

#[derive(Debug, thiserror::Error)]
#[allow(clippy::module_name_repetitions)]
pub enum TrustedDomainError {
    #[error("Invalid domain name: {0}")]
    InvalidDomainName(String),
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::graphql::trusted_domain::is_valid_domain;
    use crate::graphql::{BoxedAgentManager, MockAgentManager, TestSchema};

    #[tokio::test]
    async fn trusted_domain_list() {
        let schema = TestSchema::new().await;
        let res = schema
            .execute(r#"{trustedDomainList{edges{node{name}}}}"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{trustedDomainList: {edges: []}}"#);
    }

    #[tokio::test]
    async fn update_trusted_domain() {
        let agent_manager: BoxedAgentManager = Box::new(MockAgentManager {});
        let test_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let schema = TestSchema::new_with(agent_manager, Some(test_addr)).await;
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

        let update_error_query = r#"
              mutation {
                updateTrustedDomain(
                    old: {
                        name: "test2.com"
                        remarks: "origin_remarks"
                    }
                    new: {
                        name: "test"
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

        let res = schema.execute(update_error_query).await;
        assert_eq!(
            res.errors.first().unwrap().message,
            "Invalid domain name: test".to_string()
        );
    }

    #[test]
    fn valid_domain() {
        let test_domains = vec![
            "ex.com",
            "test.domain.co.kr",
            "test.or.org",
            "test-1.sample",
            "error",
        ];

        let res: Vec<_> = test_domains.iter().map(|&x| is_valid_domain(x)).collect();
        let expect = vec![true, true, true, true, false];
        assert_eq!(res, expect);
    }
}
