use async_graphql::{Context, ID, InputObject, Object, Result, Union};
use review_database as database;
use review_database::Iterable;
use review_database::event::Direction;
use tracing::info;

use super::super::customer::{HostNetworkGroup, HostNetworkGroupInput};
use super::{Role, RoleGuard};
use crate::info_with_username;

#[derive(Union)]
pub(super) enum ExclusionReason {
    IpAddress(IpAddressTriageExclusion),
    Domain(DomainTriageExclusion),
    Hostname(HostnameTriageExclusion),
    Uri(UriTriageExclusion),
}

impl From<&database::ExclusionReason> for ExclusionReason {
    fn from(value: &database::ExclusionReason) -> Self {
        match value {
            database::ExclusionReason::IpAddress(g) => IpAddressTriageExclusion(g.clone()).into(),
            database::ExclusionReason::Domain(d) => DomainTriageExclusion(d.clone()).into(),
            database::ExclusionReason::Hostname(h) => HostnameTriageExclusion(h.clone()).into(),
            database::ExclusionReason::Uri(u) => UriTriageExclusion(u.clone()).into(),
        }
    }
}

pub(super) struct IpAddressTriageExclusion(database::HostNetworkGroup);

#[Object]
impl IpAddressTriageExclusion {
    async fn ip_address(&self) -> HostNetworkGroup<'_> {
        (&self.0).into()
    }
}

pub(super) struct DomainTriageExclusion(Vec<String>);

#[Object]
impl DomainTriageExclusion {
    async fn domain(&self) -> &[String] {
        &self.0
    }
}

pub(super) struct UriTriageExclusion(Vec<String>);

#[Object]
impl UriTriageExclusion {
    async fn uri(&self) -> &[String] {
        &self.0
    }
}

pub(super) struct HostnameTriageExclusion(Vec<String>);

#[Object]
impl HostnameTriageExclusion {
    async fn hostname(&self) -> &[String] {
        &self.0
    }
}

pub(super) struct TriageExclusionReason {
    inner: database::TriageExclusionReason,
}

impl From<database::TriageExclusionReason> for TriageExclusionReason {
    fn from(inner: database::TriageExclusionReason) -> Self {
        Self { inner }
    }
}

#[Object]
impl TriageExclusionReason {
    async fn id(&self) -> ID {
        ID::from(self.inner.id.to_string())
    }

    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn description(&self) -> &str {
        &self.inner.description
    }

    async fn exclusion_reason(&self) -> ExclusionReason {
        (&self.inner.exclusion_reason).into()
    }
}

#[derive(Clone, InputObject)]
pub(super) struct ExclusionReasonInput {
    ip_address: Option<HostNetworkGroupInput>,
    domain: Option<Vec<String>>,
    hostname: Option<Vec<String>>,
    uri: Option<Vec<String>>,
}

impl TryFrom<ExclusionReasonInput> for database::ExclusionReason {
    type Error = anyhow::Error;

    fn try_from(value: ExclusionReasonInput) -> Result<Self, Self::Error> {
        if let Some(ip_address) = value.ip_address {
            Ok(database::ExclusionReason::IpAddress(ip_address.try_into()?))
        } else if let Some(domain) = value.domain {
            Ok(database::ExclusionReason::Domain(domain))
        } else if let Some(hostname) = value.hostname {
            Ok(database::ExclusionReason::Hostname(hostname))
        } else if let Some(uri) = value.uri {
            Ok(database::ExclusionReason::Uri(uri))
        } else {
            Err(anyhow::anyhow!("invalid input"))
        }
    }
}

#[derive(Clone, InputObject)]
pub(super) struct TriageExclusionReasonInput {
    pub name: String,
    pub description: String,
    #[graphql(flatten)]
    pub exclusion_reason: ExclusionReasonInput,
}

impl TryFrom<TriageExclusionReasonInput> for database::TriageExclusionReason {
    type Error = anyhow::Error;

    fn try_from(value: TriageExclusionReasonInput) -> Result<Self, Self::Error> {
        let exclusion_reason: database::ExclusionReason = value.exclusion_reason.try_into()?;
        Ok(Self {
            id: u32::MAX,
            name: value.name,
            description: value.description,
            exclusion_reason,
        })
    }
}

impl TryFrom<TriageExclusionReasonInput> for database::TriageExclusionReasonUpdate {
    type Error = anyhow::Error;

    fn try_from(value: TriageExclusionReasonInput) -> Result<Self, Self::Error> {
        let exclusion_reason: database::ExclusionReason = value.exclusion_reason.try_into()?;
        Ok(Self {
            name: value.name,
            description: value.description,
            exclusion_reason,
        })
    }
}

#[derive(Default)]
pub(crate) struct TriageExclusionReasonQuery;

#[Object]
impl TriageExclusionReasonQuery {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn triage_exclusion_reasons(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Vec<TriageExclusionReason>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_exclusion_reason_map();
        let mut reasons = Vec::new();
        for entry in map.iter(Direction::Forward, None) {
            let reason = entry?;
            reasons.push(reason.into());
        }
        Ok(reasons)
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn triage_exclusion_reason(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<TriageExclusionReason> {
        let id = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_exclusion_reason_map();
        let Some(reason) = map.get_by_id(id)? else {
            return Err("no such triage exclusion reason".into());
        };
        Ok(reason.into())
    }
}

#[derive(Default)]
pub(crate) struct TriageExclusionReasonMutation;

#[Object]
impl TriageExclusionReasonMutation {
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_triage_exclusion_reason(
        &self,
        ctx: &Context<'_>,
        input: TriageExclusionReasonInput,
    ) -> Result<ID> {
        let reason: database::TriageExclusionReason = input.try_into()?;
        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_exclusion_reason_map();
        let id = map.put(reason)?;
        info_with_username!(ctx, "Triage exclusion reason has been registered: {}", id);
        Ok(ID::from(id.to_string()))
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_triage_exclusion_reason(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: TriageExclusionReasonInput,
        new: TriageExclusionReasonInput,
    ) -> Result<ID> {
        let id = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
        let old_update: database::TriageExclusionReasonUpdate = old.try_into()?;
        let new_update: database::TriageExclusionReasonUpdate = new.try_into()?;

        let store = crate::graphql::get_store(ctx)?;
        let mut map = store.triage_exclusion_reason_map();
        map.update(id, &old_update, &new_update)?;
        info_with_username!(ctx, "Triage exclusion reason {id} has been updated");
        Ok(ID::from(id.to_string()))
    }

    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_triage_exclusion_reasons(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] ids: Vec<ID>,
    ) -> Result<Vec<ID>> {
        let store = crate::graphql::get_store(ctx)?;
        let map = store.triage_exclusion_reason_map();

        let mut removed = Vec::with_capacity(ids.len());
        for id in ids {
            let id_u32 = id.as_str().parse::<u32>().map_err(|_| "invalid ID")?;
            map.remove(id_u32)?;
            removed.push(ID::from(id_u32.to_string()));
            info_with_username!(ctx, "Triage exclusion reason {id_u32} has been deleted");
        }

        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_triage_exclusion_reason_crud() {
        let schema = TestSchema::new().await;

        // Insert
        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    insertTriageExclusionReason(input: {
                        name: "Reason 1"
                        description: "first reason"
                        ipAddress: {
                            hosts: ["1.1.1.1"]
                            networks: []
                            ranges: []
                        }
                    })
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{insertTriageExclusionReason: "0"}"#
        );

        // Query list (should include inserted values)
        let res = schema
            .execute_as_system_admin(
                r"
                {
                    triageExclusionReasons {
                        id
                        name
                        description
                        exclusionReason {
                            ... on IpAddressTriageExclusion {
                                ipAddress { hosts }
                            }
                        }
                    }
                }",
            )
            .await;
        assert!(res.errors.is_empty(), "Query errors: {:?}", res.errors);
        let payload = res.data.into_json().unwrap();
        let items = payload["triageExclusionReasons"]
            .as_array()
            .expect("triageExclusionReasons should be an array");
        assert_eq!(items.len(), 1, "Expected one exclusion reason: {items:?}");
        let item = &items[0];
        assert_eq!(item["id"], "0");
        assert_eq!(item["name"], "Reason 1");
        assert_eq!(item["description"], "first reason");
        assert_eq!(
            item["exclusionReason"]["ipAddress"]["hosts"]
                .as_array()
                .unwrap()
                .first()
                .unwrap(),
            "1.1.1.1"
        );

        // Update (change type to domain)
        let res = schema
            .execute_as_system_admin(
                r#"
                mutation {
                    updateTriageExclusionReason(
                        id: "0"
                        old: {
                            name: "Reason 1"
                            description: "first reason"
                            ipAddress: {
                                hosts: ["1.1.1.1"]
                                networks: []
                                ranges: []
                            }
                        }
                        new: {
                            name: "Reason 1 updated"
                            description: "domain reason"
                            domain: ["example.com"]
                        }
                    )
                }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{updateTriageExclusionReason: "0"}"#
        );

        // Remove
        let res = schema
            .execute_as_system_admin(r#"mutation { removeTriageExclusionReasons(ids: ["0"]) }"#)
            .await;
        assert!(
            res.data.to_string().contains(r#"["0"]"#),
            "Unexpected removeTriageExclusionReasons payload: {}",
            res.data
        );
    }
}
