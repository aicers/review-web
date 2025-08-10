use async_graphql::{Context, Enum, ID, Object, Result, SimpleObject};
use review_database::{self as database, TidbRuleKind as DbTidbRuleKind};

use super::{Role, RoleGuard, triage::ThreatCategory};

#[derive(Default)]
pub(super) struct TidbQuery;

#[Object]
impl TidbQuery {
    /// Look up an Tidb by the given database name.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn tidb(&self, ctx: &Context<'_>, name: String) -> Result<Tidb> {
        let store = super::get_store(ctx).await?;
        let table = store.tidb_map();
        let Some(tidb) = table.get(&name)? else {
            return Err("no such tidb".into());
        };
        Ok(tidb.into())
    }

    /// A list of ti databases
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn tidb_list(&self, ctx: &Context<'_>) -> Result<Vec<Tidb>> {
        let store = super::get_store(ctx).await?;
        let table = store.tidb_map();

        Ok(table.get_list()?.into_iter().map(Into::into).collect())
    }

    /// A query for detail information of a rule
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn tidb_rule(
        &self,
        ctx: &Context<'_>,
        name: String,
        rule_id: String,
    ) -> Result<Option<TidbRule>> {
        let rule_id = rule_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid rule ID")?;
        let store = super::get_store(ctx).await?;
        let table = store.tidb_map();
        let Some(tidb) = table.get(&name)? else {
            return Err("no such tidb".into());
        };
        tidb.patterns
            .into_iter()
            .find(|rule| rule.rule_id == rule_id)
            .map_or(Ok(None), |rule| Ok(Some(rule.into())))
    }
}

#[derive(Default)]
pub(super) struct TidbMutation;

#[Object]
impl TidbMutation {
    /// Inserts a new Tidb, overwriting any existing database with same name
    /// `dbfile` should be encoded string of `Tidb` instance that is serialized
    /// with `bincode::DefaultOptions::new().serialize`.
    /// Returns name and version.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_tidb(&self, ctx: &Context<'_>, dbfile: String) -> Result<TidbOutput> {
        let tidb = database::Tidb::new(&dbfile)?;
        let output = TidbOutput {
            name: tidb.name.clone(),
            version: tidb.version.clone(),
        };

        let store = super::get_store(ctx).await?;
        let table = store.tidb_map();
        table.insert(tidb)?;

        Ok(output)
    }

    /// Removes Tidb, returning the name and version of database that removed
    ///
    /// On error, some Tidbs may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_tidb(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] names: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = super::get_store(ctx).await?;
        let table = store.tidb_map();
        let mut removed = Vec::with_capacity(names.len());
        for name in names {
            match table.remove(&name) {
                Ok(()) => removed.push(name),
                Err(e) => return Err(format!("{e:?}").into()),
            }
        }
        Ok(removed)
    }

    /// Updates the given Tidb, returning the Tidb ID that was updated.
    /// `new` should be encoded string of `Tidb` instance that is serialized
    /// with `bincode::DefaultOptions::new().serialize`.
    ///
    /// Will return error if old and new tidb name is different
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_tidb(
        &self,
        ctx: &Context<'_>,
        name: String,
        new: String,
    ) -> Result<TidbOutput> {
        let tidb = database::Tidb::new(&new)?;
        let output = TidbOutput {
            name: tidb.name.clone(),
            version: tidb.version.clone(),
        };
        let store = super::get_store(ctx).await?;
        let table = store.tidb_map();

        table.update(&name, tidb)?;
        Ok(output)
    }
}

struct Tidb {
    inner: database::Tidb,
}

#[Object]
impl Tidb {
    /// The database ID of the Tidb.
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    /// The name of the Tidb.
    async fn name(&self) -> &str {
        &self.inner.name
    }

    /// The description of the Tidb.
    async fn description(&self) -> Option<&str> {
        self.inner.description.as_deref()
    }

    /// The kind of the Tidb.
    async fn kind(&self) -> TidbKind {
        self.inner.kind.into()
    }

    /// The MITRE category of the Tidb.
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// The version of the Tidb.
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// The patterns in Tidb.
    async fn patterns(&self) -> String {
        self.inner.patterns()
    }
}

impl From<database::Tidb> for Tidb {
    fn from(inner: database::Tidb) -> Self {
        Self { inner }
    }
}

#[derive(Copy, Clone, Enum, Eq, PartialEq)]
#[graphql(remote = "database::TidbKind")]
enum TidbKind {
    Ip,
    Url,
    Token,
    Regex,
}

#[derive(Copy, Clone, Enum, Eq, PartialEq)]
enum TidbRuleKind {
    Os,
    AgentSoftware,
}

struct TidbRule {
    inner: database::TidbRule,
}

#[Object]
impl TidbRule {
    async fn rule_id(&self) -> ID {
        ID(self.inner.rule_id.to_string())
    }

    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn description(&self) -> &Option<String> {
        &self.inner.description
    }

    async fn references(&self) -> &Option<Vec<String>> {
        &self.inner.references
    }

    async fn samples(&self) -> &Option<Vec<String>> {
        &self.inner.samples
    }

    async fn signatures(&self) -> &Option<Vec<String>> {
        &self.inner.signatures
    }

    async fn confidence(&self) -> Option<f32> {
        self.inner.confidence
    }

    async fn kind(&self) -> Option<TidbRuleKind> {
        self.inner.kind.map(|k| match k {
            DbTidbRuleKind::Os => TidbRuleKind::Os,
            DbTidbRuleKind::AgentSoftware => TidbRuleKind::AgentSoftware,
        })
    }
}

impl From<database::TidbRule> for TidbRule {
    fn from(inner: database::TidbRule) -> Self {
        Self { inner }
    }
}

#[derive(SimpleObject)]
#[allow(clippy::module_name_repetitions)]
pub struct TidbOutput {
    name: String,
    version: String,
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn isud_tidb() {
        let schema = TestSchema::new().await;

        let query_tidblist = r"{tidbList{name,version,category}}";
        let res = schema.execute(query_tidblist).await;
        assert_eq!(res.data.to_string(), r"{tidbList: []}");
    }
}
