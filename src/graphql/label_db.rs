use async_graphql::{Context, Enum, ID, Object, Result, SimpleObject};
use review_database::{self as database, LabelDbRuleKind as DbLabelDbRuleKind};
use tracing::info;

use super::{Role, RoleGuard, triage::ThreatCategory};
use crate::info_with_username;

#[derive(Default)]
pub(super) struct LabelDbQuery;

#[Object]
impl LabelDbQuery {
    /// Look up a label database by the given name.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn label_db(&self, ctx: &Context<'_>, name: String) -> Result<LabelDb> {
        let store = super::get_store(ctx)?;
        let table = store.label_db_map();
        let Some(label_db) = table.get(&name)? else {
            return Err("no such label database".into());
        };
        Ok(label_db.into())
    }

    /// A list of label databases.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn label_db_list(&self, ctx: &Context<'_>) -> Result<Vec<LabelDb>> {
        let store = super::get_store(ctx)?;
        let table = store.label_db_map();

        info_with_username!(ctx, "Label DB list requested");
        Ok(table.get_list()?.into_iter().map(Into::into).collect())
    }

    /// Detail information of a rule in a label database.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn label_db_rule(
        &self,
        ctx: &Context<'_>,
        name: String,
        rule_id: String,
    ) -> Result<Option<LabelDbRule>> {
        let rule_id = rule_id
            .as_str()
            .parse::<u32>()
            .map_err(|_| "invalid rule ID")?;
        let store = super::get_store(ctx)?;
        let table = store.label_db_map();
        let Some(label_db) = table.get(&name)? else {
            return Err("no such label database".into());
        };
        label_db
            .patterns
            .into_iter()
            .find(|rule| rule.rule_id == rule_id)
            .map_or(Ok(None), |rule| Ok(Some(rule.into())))
    }
}

#[derive(Default)]
pub(super) struct LabelDbMutation;

#[Object]
impl LabelDbMutation {
    /// Inserts a new label database, overwriting any existing database with the same name.
    /// `dbfile` should be encoded string of `LabelDb` instance that is serialized
    /// with `bincode::DefaultOptions::new().serialize`.
    /// Returns name and version.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_label_db(&self, ctx: &Context<'_>, dbfile: String) -> Result<LabelDbOutput> {
        let label_db = database::LabelDb::new(&dbfile)?;
        let output = LabelDbOutput {
            name: label_db.name.clone(),
            version: label_db.version.clone(),
        };

        let store = super::get_store(ctx)?;
        let table = store.label_db_map();
        table.insert(label_db)?;
        info_with_username!(ctx, "Label DB {} has been registered", output.name);

        Ok(output)
    }

    /// Removes label databases, returning the names that were removed.
    ///
    /// On error, some label databases may have been removed.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_label_db(
        &self,
        ctx: &Context<'_>,
        #[graphql(validator(min_items = 1))] names: Vec<String>,
    ) -> Result<Vec<String>> {
        let store = super::get_store(ctx)?;
        let table = store.label_db_map();
        let mut removed = Vec::with_capacity(names.len());
        for name in names {
            match table.remove(&name) {
                Ok(()) => removed.push(name),
                Err(e) => return Err(format!("{e:?}").into()),
            }
        }
        info_with_username!(ctx, "Label DB {:?} has been deleted", removed);
        Ok(removed)
    }

    /// Updates the given label database, returning its name and version.
    /// `new` should be encoded string of `LabelDb` instance that is serialized
    /// with `bincode::DefaultOptions::new().serialize`.
    ///
    /// Will return error if old and new label database name is different.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_label_db(
        &self,
        ctx: &Context<'_>,
        name: String,
        new: String,
    ) -> Result<LabelDbOutput> {
        let label_db = database::LabelDb::new(&new)?;
        let output = LabelDbOutput {
            name: label_db.name.clone(),
            version: label_db.version.clone(),
        };
        let store = super::get_store(ctx)?;
        let table = store.label_db_map();

        table.update(&name, label_db)?;
        info_with_username!(ctx, "Label DB {name} has been updated to {}", output.name);

        Ok(output)
    }
}

struct LabelDb {
    inner: database::LabelDb,
}

#[Object]
impl LabelDb {
    /// The database ID of the label database.
    async fn id(&self) -> ID {
        ID(self.inner.id.to_string())
    }

    /// The name of the label database.
    async fn name(&self) -> &str {
        &self.inner.name
    }

    /// The description of the label database.
    async fn description(&self) -> Option<&str> {
        self.inner.description.as_deref()
    }

    /// The kind of the label database.
    async fn kind(&self) -> LabelDbKind {
        self.inner.kind.into()
    }

    /// The MITRE category of the label database.
    async fn category(&self) -> ThreatCategory {
        self.inner.category.into()
    }

    /// The version of the label database.
    async fn version(&self) -> &str {
        &self.inner.version
    }

    /// The patterns in the label database.
    async fn patterns(&self) -> String {
        self.inner.patterns()
    }
}

impl From<database::LabelDb> for LabelDb {
    fn from(inner: database::LabelDb) -> Self {
        Self { inner }
    }
}

#[derive(Copy, Clone, Enum, Eq, PartialEq)]
#[graphql(remote = "database::LabelDbKind")]
enum LabelDbKind {
    Ip,
    Url,
    Token,
    Regex,
}

#[derive(Copy, Clone, Enum, Eq, PartialEq)]
enum LabelDbRuleKind {
    Os,
    AgentSoftware,
}

struct LabelDbRule {
    inner: database::LabelDbRule,
}

#[Object]
impl LabelDbRule {
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

    async fn kind(&self) -> Option<LabelDbRuleKind> {
        self.inner.kind.map(|k| match k {
            DbLabelDbRuleKind::Os => LabelDbRuleKind::Os,
            DbLabelDbRuleKind::AgentSoftware => LabelDbRuleKind::AgentSoftware,
        })
    }
}

impl From<database::LabelDbRule> for LabelDbRule {
    fn from(inner: database::LabelDbRule) -> Self {
        Self { inner }
    }
}

#[derive(SimpleObject)]
#[allow(clippy::module_name_repetitions)]
pub struct LabelDbOutput {
    name: String,
    version: String,
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn isud_label_db() {
        let schema = TestSchema::new().await;

        let query_list = r"{labelDbList{name,version,category}}";
        let res = schema.execute_as_system_admin(query_list).await;
        assert_eq!(res.data.to_string(), r"{labelDbList: []}");
    }
}
