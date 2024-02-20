mod event_tag;
mod network_tag;
mod workflow_tag;

use super::Role;
use async_graphql::{ComplexObject, SimpleObject, ID};
pub(super) use event_tag::EventTagMutation;
pub(super) use event_tag::EventTagQuery;
pub(super) use network_tag::NetworkTagMutation;
pub(super) use network_tag::NetworkTagQuery;
pub(super) use workflow_tag::WorkflowTagMutation;
pub(super) use workflow_tag::WorkflowTagQuery;

#[derive(SimpleObject)]
#[graphql(complex)]
struct Tag {
    #[graphql(skip)]
    id: u32,
    name: String,
}

#[ComplexObject]
impl Tag {
    async fn id(&self) -> ID {
        ID(self.id.to_string())
    }
}
