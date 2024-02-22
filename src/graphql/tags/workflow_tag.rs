use super::Tag;
use async_graphql::{Context, Object, Result, ID};

#[derive(Default)]
pub(in crate::graphql) struct WorkflowTagQuery;

#[Object]
impl WorkflowTagQuery {
    /// A list of workflow tags.
    async fn workflow_tag_list(&self, ctx: &Context<'_>) -> Result<Vec<Tag>> {
        let store = crate::graphql::get_store(ctx).await?;
        let set = store.workflow_tag_set()?;
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
pub(in crate::graphql) struct WorkflowTagMutation;

#[Object]
impl WorkflowTagMutation {
    /// Inserts a new workflow tag, returning the ID of the new tag.
    async fn insert_workflow_tag(&self, ctx: &Context<'_>, name: String) -> Result<ID> {
        let store = crate::graphql::get_store(ctx).await?;
        let mut set = store.workflow_tag_set()?;
        let id = set.insert(&name)?;
        Ok(ID(id.to_string()))
    }

    /// Removes a workflow tag for the given ID, returning the name of the removed
    /// tag.
    async fn remove_workflow_tag(&self, ctx: &Context<'_>, id: ID) -> Result<Option<String>> {
        let store = crate::graphql::get_store(ctx).await?;
        // TODO: Delete the tag from workflows when assigning tags to a workflow
        // is implemented.
        let mut set = store.workflow_tag_set()?;
        let name = set.remove(id.0.parse()?)?;
        Ok(Some(name))
    }

    /// Updates the name of a workflow tag for the given ID.
    ///
    /// It returns `true` if the name was updated, `false` if the tag was
    /// different or not found.
    async fn update_workflow_tag(
        &self,
        ctx: &Context<'_>,
        id: ID,
        old: String,
        new: String,
    ) -> Result<bool> {
        let store = crate::graphql::get_store(ctx).await?;
        let mut set = store.workflow_tag_set()?;
        Ok(set.update(id.0.parse()?, &old, &new)?)
    }
}
