use std::convert::{TryFrom, TryInto};

use async_graphql::{
    connection::{query, Connection, EmptyFields},
    Context, Enum, InputObject, Object, Result, StringNumber, Union,
};
use serde::{Deserialize, Serialize};

use super::{ParseEnumError, Role, RoleGuard};

#[derive(Default)]
pub(super) struct TemplateQuery;

#[Object]
impl TemplateQuery {
    /// A list of model templates.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn template_list(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<Connection<String, Template, TemplateTotalCount, EmptyFields>> {
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
pub(super) struct TemplateMutation;

#[Object]
impl TemplateMutation {
    /// Inserts a new template, overwriting any existing template with the same
    /// name.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn insert_template(
        &self,
        ctx: &Context<'_>,
        structured: Option<StructuredClusteringTemplateInput>,
        unstructured: Option<UnstructuredClusteringTemplateInput>,
    ) -> Result<String> {
        let (name, template) = match (structured, unstructured) {
            (Some(structured), None) => (
                structured.name.clone(),
                structured
                    .try_into()
                    .map_err(|_| "invalid clustering algorithm")?,
            ),
            (None, Some(unstructured)) => (
                unstructured.name.clone(),
                unstructured
                    .try_into()
                    .map_err(|_| "invalid clustering algorithm")?,
            ),
            (Some(_), Some(_)) => {
                return Err(
                    "cannot specify both structured and unstructured clustering algorithms".into(),
                );
            }
            (None, None) => {
                return Err(
                    "must specify either structured or unstructured clustering algorithms".into(),
                );
            }
        };

        let store = crate::graphql::get_store(ctx).await?;
        let map = store.template_map();
        map.insert(template)?;
        Ok(name)
    }

    /// Removes a template, returning the name of the removed template if it no
    /// longer exists.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn remove_template(&self, ctx: &Context<'_>, name: String) -> Result<String> {
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.template_map();
        map.remove(&name)?;
        Ok(name)
    }

    /// Updates the given template.
    #[allow(clippy::too_many_arguments)]
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))")]
    async fn update_template(
        &self,
        ctx: &Context<'_>,
        old_structured: Option<StructuredClusteringTemplateInput>,
        old_unstructured: Option<UnstructuredClusteringTemplateInput>,
        new_structured: Option<StructuredClusteringTemplateInput>,
        new_unstructured: Option<UnstructuredClusteringTemplateInput>,
    ) -> Result<bool> {
        let (old, new) = match (
            old_structured,
            old_unstructured,
            new_structured,
            new_unstructured,
        ) {
            (Some(old_structured), None, Some(new_structured), None) => {
                let old_template = old_structured
                    .try_into()
                    .map_err(|_| "invalid clustering algorithm")?;
                let new_template = new_structured
                    .try_into()
                    .map_err(|_| "invalid clustering algorithm")?;
                (old_template, new_template)
            }
            (None, Some(old_unstructured), None, Some(new_unstructured)) => {
                let old_template = old_unstructured
                    .try_into()
                    .map_err(|_| "invalid clustering algorithm")?;
                let new_template = new_unstructured
                    .try_into()
                    .map_err(|_| "invalid clustering algorithm")?;

                (old_template, new_template)
            }
            _ => {
                return Err(
                    "cannot specify both old_structured and new_structured, or old_unstructured and new_unstructured".into(),
                );
            }
        };
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.template_map();
        map.update(old, new)?;
        Ok(true)
    }
}

#[derive(InputObject)]
struct StructuredClusteringTemplateInput {
    name: String,
    description: Option<String>,
    algorithm: Option<StructuredClusteringAlgorithm>, // DBSCAN or OPTICS (default)
    eps: Option<f32>,
    format: Option<String>,
    time_intervals: Option<Vec<i64>>,
    numbers_of_top_n: Option<Vec<i32>>,
}

#[derive(Copy, Clone, Deserialize, Enum, Eq, PartialEq, Serialize)]
enum StructuredClusteringAlgorithm {
    Dbscan,
    Optics,
}

impl From<StructuredClusteringAlgorithm> for review_database::StructuredClusteringAlgorithm {
    fn from(input: StructuredClusteringAlgorithm) -> Self {
        match input {
            StructuredClusteringAlgorithm::Dbscan => Self::Dbscan,
            StructuredClusteringAlgorithm::Optics => Self::Optics,
        }
    }
}

impl From<review_database::StructuredClusteringAlgorithm> for StructuredClusteringAlgorithm {
    fn from(input: review_database::StructuredClusteringAlgorithm) -> Self {
        match input {
            review_database::StructuredClusteringAlgorithm::Dbscan => Self::Dbscan,
            review_database::StructuredClusteringAlgorithm::Optics => Self::Optics,
        }
    }
}

#[derive(Copy, Clone, Deserialize, Enum, Eq, PartialEq, Serialize)]
enum UnstructuredClusteringAlgorithm {
    Distribution,
    Prefix,
}

impl From<UnstructuredClusteringAlgorithm> for review_database::UnstructuredClusteringAlgorithm {
    fn from(input: UnstructuredClusteringAlgorithm) -> Self {
        match input {
            UnstructuredClusteringAlgorithm::Distribution => Self::Distribution,
            UnstructuredClusteringAlgorithm::Prefix => Self::Prefix,
        }
    }
}

impl From<review_database::UnstructuredClusteringAlgorithm> for UnstructuredClusteringAlgorithm {
    fn from(input: review_database::UnstructuredClusteringAlgorithm) -> Self {
        match input {
            review_database::UnstructuredClusteringAlgorithm::Distribution => Self::Distribution,
            review_database::UnstructuredClusteringAlgorithm::Prefix => Self::Prefix,
        }
    }
}

#[derive(InputObject)]
struct UnstructuredClusteringTemplateInput {
    name: String,
    description: Option<String>,
    algorithm: Option<UnstructuredClusteringAlgorithm>, // PREFIX (default) or DISTRIBUTION
    min_token_length: Option<i32>,
}

#[derive(Union)]
enum Template {
    Structured(StructuredClusteringTemplate),
    Unstructured(UnstructuredClusteringTemplate),
}

impl From<review_database::Template> for Template {
    fn from(inner: review_database::Template) -> Self {
        match inner {
            review_database::Template::Structured(s) => Self::Structured(s.into()),
            review_database::Template::Unstructured(u) => Self::Unstructured(u.into()),
        }
    }
}

struct StructuredClusteringTemplate {
    inner: review_database::Structured,
}

#[Object]
impl StructuredClusteringTemplate {
    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn description(&self) -> &str {
        &self.inner.description
    }

    async fn algorithm(&self) -> Option<StructuredClusteringAlgorithm> {
        self.inner.algorithm.map(Into::into)
    }

    async fn eps(&self) -> Option<f32> {
        self.inner.eps
    }

    async fn format(&self) -> Option<&str> {
        self.inner.format.as_deref()
    }

    /// The time interval of the template in string represantable by a vector of `i64`.
    async fn time_intervals(&self) -> Option<Vec<StringNumber<i64>>> {
        self.inner.time_intervals.as_ref().map(|v| {
            v.iter()
                .map(|i| StringNumber(*i))
                .collect::<Vec<StringNumber<i64>>>()
        })
    }

    async fn numbers_of_top_n(&self) -> Option<&[i32]> {
        self.inner.numbers_of_top_n.as_deref()
    }
}

impl From<review_database::Structured> for StructuredClusteringTemplate {
    fn from(inner: review_database::Structured) -> Self {
        Self { inner }
    }
}

struct UnstructuredClusteringTemplate {
    inner: review_database::Unstructured,
}

#[Object]
impl UnstructuredClusteringTemplate {
    async fn name(&self) -> &str {
        &self.inner.name
    }

    async fn description(&self) -> &str {
        &self.inner.description
    }

    async fn algorithm(&self) -> Option<UnstructuredClusteringAlgorithm> {
        self.inner.algorithm.map(Into::into)
    }

    async fn min_token_length(&self) -> Option<i32> {
        self.inner.min_token_length
    }
}

impl From<review_database::Unstructured> for UnstructuredClusteringTemplate {
    fn from(inner: review_database::Unstructured) -> Self {
        Self { inner }
    }
}

impl TryFrom<StructuredClusteringTemplateInput> for review_database::Template {
    type Error = ParseEnumError;

    fn try_from(input: StructuredClusteringTemplateInput) -> Result<Self, Self::Error> {
        Ok(Self::Structured(review_database::Structured {
            name: input.name,
            description: input.description.unwrap_or_default(),
            algorithm: input.algorithm.map(Into::into),
            eps: input.eps,
            format: input.format,
            time_intervals: input.time_intervals,
            numbers_of_top_n: input.numbers_of_top_n,
        }))
    }
}

impl TryFrom<UnstructuredClusteringTemplateInput> for review_database::Template {
    type Error = ParseEnumError;

    fn try_from(input: UnstructuredClusteringTemplateInput) -> Result<Self, Self::Error> {
        Ok(Self::Unstructured(review_database::Unstructured {
            name: input.name,
            description: input.description.unwrap_or_default(),
            algorithm: input.algorithm.map(Into::into),
            min_token_length: input.min_token_length,
        }))
    }
}

struct TemplateTotalCount;

#[Object]
impl TemplateTotalCount {
    /// The total number of edges.
    async fn total_count(&self, ctx: &Context<'_>) -> Result<usize> {
        use review_database::{Direction, Iterable};
        let store = crate::graphql::get_store(ctx).await?;
        let map = store.template_map();
        let count = map.iter(Direction::Forward, None).count();
        Ok(count)
    }
}

async fn load(
    ctx: &Context<'_>,
    after: Option<String>,
    before: Option<String>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<String, Template, TemplateTotalCount, EmptyFields>> {
    let store = crate::graphql::get_store(ctx).await?;
    let map = store.template_map();
    super::load_edges(&map, after, before, first, last, TemplateTotalCount)
}

#[cfg(test)]
mod tests {
    use crate::graphql::TestSchema;

    #[tokio::test]
    async fn test_unstructured_template() {
        let schema = TestSchema::new().await;
        let res = schema.execute(r#"{templateList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{templateList: {totalCount: 0}}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertTemplate(unstructured: {
                        name: "t1",
                        description: "test",
                        algorithm: "PREFIX",
                        minTokenLength: 1
                    })
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTemplate: "t1"}"#);

        let res = schema.execute(r#"{templateList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{templateList: {totalCount: 1}}"#);

        let res = schema
            .execute(
                r#"{
                templateList {
                    edges {
                        node {
                            ... on UnstructuredClusteringTemplate {
                                name
                            }
                        }
                    }
                totalCount
            }
        }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{templateList: {edges: [{node: {name: "t1"}}], totalCount: 1}}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                updateTemplate(oldUnstructured: {
                    name: "t1",
                    description: "test",
                    algorithm: "PREFIX",
                    minTokenLength: 1
                },
                newUnstructured: {
                    name: "t1",
                    description: "test",
                    algorithm: "DISTRIBUTION",
                    minTokenLength: 2
                })
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateTemplate: true}"#);

        let res = schema
            .execute(
                r#"{
                templateList {
                    edges {
                        node {
                            ... on UnstructuredClusteringTemplate {
                                algorithm
                            }
                        }
                    }
                totalCount
            }
        }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{templateList: {edges: [{node: {algorithm: DISTRIBUTION}}], totalCount: 1}}"#
        );

        let res = schema
            .execute(r#"mutation { removeTemplate(name: "t1") }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeTemplate: "t1"}"#);

        let res = schema.execute(r#"{templateList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{templateList: {totalCount: 0}}"#);
    }

    #[tokio::test]
    async fn test_structured_template() {
        let schema = TestSchema::new().await;
        let res = schema.execute(r#"{templateList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{templateList: {totalCount: 0}}"#);

        let res = schema
            .execute(
                r#"mutation {
                    insertTemplate(structured: {
                        name: "t1",
                        description: "test",
                        algorithm: "OPTICS",
                        eps: 0.5,
                        format: "json",
                        timeIntervals: [1, 2, 3],
                        numbersOfTopN: [1, 2, 3]
                    })
                }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{insertTemplate: "t1"}"#);

        let res = schema.execute(r#"{templateList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{templateList: {totalCount: 1}}"#);

        let res = schema
            .execute(
                r#"{
                templateList {
                    edges {
                        node {
                            ... on StructuredClusteringTemplate {
                                name
                                timeIntervals
                            }
                        }
                    }
                totalCount
            }
        }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{templateList: {edges: [{node: {name: "t1", timeIntervals: ["1", "2", "3"]}}], totalCount: 1}}"#
        );

        let res = schema
            .execute(
                r#"mutation {
                updateTemplate(oldStructured: {
                    name: "t1",
                    description: "test",
                    algorithm: "OPTICS",
                    eps: 0.5,
                    format: "json",
                    timeIntervals: [1, 2, 3],
                    numbersOfTopN: [1, 2, 3]
                },
                newStructured: {
                    name: "t1",
                    description: "test",
                    algorithm: "OPTICS",
                    eps: 0.5,
                    format: "json",
                    timeIntervals: [1, 2, 4],
                    numbersOfTopN: [1, 2, 4]
                })
            }"#,
            )
            .await;
        assert_eq!(res.data.to_string(), r#"{updateTemplate: true}"#);

        let res = schema
            .execute(
                r#"{
                templateList {
                    edges {
                        node {
                            ... on StructuredClusteringTemplate {
                                algorithm
                                timeIntervals
                            }
                        }
                    }
                totalCount
            }
        }"#,
            )
            .await;
        assert_eq!(
            res.data.to_string(),
            r#"{templateList: {edges: [{node: {algorithm: OPTICS, timeIntervals: ["1", "2", "4"]}}], totalCount: 1}}"#
        );

        let res = schema
            .execute(r#"mutation { removeTemplate(name: "t1") }"#)
            .await;
        assert_eq!(res.data.to_string(), r#"{removeTemplate: "t1"}"#);

        let res = schema.execute(r#"{templateList{totalCount}}"#).await;
        assert_eq!(res.data.to_string(), r#"{templateList: {totalCount: 0}}"#);
    }
}
