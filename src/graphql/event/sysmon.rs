use super::TriageScore;
use async_graphql::Object;
use chrono::{DateTime, Utc};
use review_database as database;

// #[allow(clippy::module_name_repetitions)]
// pub(super) struct CommonNetworkEvent {
//     inner: database::CommonNetworkEvent,
// }

// #[Object]
// impl CommonNetworkEvent {
//     async fn event_kind(&self) -> EventKind {
//         self.inner.event_kind
//     }

//     async fn time(&self) -> DateTime<Utc> {
//         self.inner.time
//     }

//     async fn source(&self) -> &str {
//         &self.inner.source
//     }

//     async fn session_end_time(&self) -> DateTime<Utc> {
//         self.inner.session_end_time
//     }

//     async fn src_addr(&self) -> String {
//         self.inner.src_addr.to_string()
//     }

//     async fn src_port(&self) -> u16 {
//         self.inner.src_port
//     }

//     /// The two-letter country code of the source IP address. `"XX"` if the
//     /// location of the address is not known, and `"ZZ"` if the location
//     /// database is unavailable.
//     async fn src_country(&self, ctx: &Context<'_>) -> String {
//         country_code(ctx, self.inner.src_addr)
//     }

//     async fn src_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
//         let store = crate::graphql::get_store(ctx).await?;
//         let map = store.customer_map();
//         find_ip_customer(&map, self.inner.src_addr)
//     }

//     async fn src_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
//         let store = crate::graphql::get_store(ctx).await?;
//         let map = store.network_map();
//         find_ip_network(&map, self.inner.src_addr)
//     }

//     async fn dst_addr(&self) -> String {
//         self.inner.dst_addr.to_string()
//     }

//     async fn dst_port(&self) -> u16 {
//         self.inner.dst_port
//     }

//     /// The two-letter country code of the destination IP address. `"XX"` if the
//     /// location of the address is not known, and `"ZZ"` if the location
//     /// database is unavailable.
//     async fn dst_country(&self, ctx: &Context<'_>) -> String {
//         country_code(ctx, self.inner.dst_addr)
//     }

//     async fn dst_customer(&self, ctx: &Context<'_>) -> Result<Option<Customer>> {
//         let store = crate::graphql::get_store(ctx).await?;
//         let map = store.customer_map();
//         find_ip_customer(&map, self.inner.dst_addr)
//     }

//     async fn dst_network(&self, ctx: &Context<'_>) -> Result<Option<Network>> {
//         let store = crate::graphql::get_store(ctx).await?;
//         let map = store.network_map();
//         find_ip_network(&map, self.inner.dst_addr)
//     }

//     async fn proto(&self) -> u8 {
//         self.inner.proto
//     }

//     async fn service(&self) -> &str {
//         &self.inner.service
//     }

//     async fn content(&self) -> &str {
//         &self.inner.content
//     }

//     async fn confidence(&self) -> f32 {
//         self.inner.confidence
//     }

//     async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
//         self.inner
//             .triage_scores
//             .as_ref()
//             .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
//     }
// }

// impl From<database::CommonNetworkEvent> for CommonNetworkEvent {
//     fn from(inner: database::CommonNetworkEvent) -> Self {
//         Self { inner }
//     }
// }

#[allow(clippy::module_name_repetitions)]
pub(super) struct WindowsThreat {
    inner: database::WindowsThreat,
}

#[Object]
impl WindowsThreat {
    async fn time(&self) -> DateTime<Utc> {
        self.inner.time
    }

    async fn source(&self) -> &str {
        &self.inner.source
    }

    async fn service(&self) -> &str {
        &self.inner.service
    }

    async fn agent_name(&self) -> &str {
        &self.inner.agent_name
    }

    async fn agent_id(&self) -> &str {
        &self.inner.agent_id
    }

    async fn process_guid(&self) -> &str {
        &self.inner.process_guid
    }

    async fn process_id(&self) -> u32 {
        self.inner.process_id
    }

    async fn image(&self) -> &str {
        &self.inner.image
    }

    async fn user(&self) -> &str {
        &self.inner.user
    }

    async fn content(&self) -> &str {
        &self.inner.content
    }

    async fn db_name(&self) -> &str {
        &self.inner.db_name
    }

    async fn rule_id(&self) -> u32 {
        self.inner.rule_id
    }

    async fn matched_to(&self) -> &str {
        &self.inner.matched_to
    }

    async fn cluster_id(&self) -> usize {
        self.inner.cluster_id
    }

    async fn attack_kind(&self) -> &str {
        &self.inner.attack_kind
    }

    async fn confidence(&self) -> f32 {
        self.inner.confidence
    }

    async fn triage_scores(&self) -> Option<Vec<TriageScore>> {
        self.inner
            .triage_scores
            .as_ref()
            .map(|scores| scores.iter().map(Into::into).collect::<Vec<TriageScore>>())
    }
}

impl From<database::WindowsThreat> for WindowsThreat {
    fn from(inner: database::WindowsThreat) -> Self {
        Self { inner }
    }
}
