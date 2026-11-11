use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Request, Schema};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber, error, info, warn};
use tracing_subscriber::layer::{Context as LayerContext, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use super::{Role, RoleGuard};
use crate::auth::MtlsIdentity;

#[derive(Clone, Default)]
pub(super) struct CapturedEvents(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

#[derive(Default)]
struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }
}

impl<S: Subscriber> Layer<S> for CapturedEvents {
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }
}

impl CapturedEvents {
    pub(super) fn start() -> (Self, tracing::subscriber::DefaultGuard) {
        let events = Self::default();
        let guard = tracing::subscriber::set_default(Registry::default().with(events.clone()));
        (events, guard)
    }

    pub(super) fn assert_fields(&self, message: &str, caller: &str, role: &str) {
        let events = self.0.lock().unwrap();
        let matching: Vec<_> = events
            .iter()
            .filter(|fields| {
                fields
                    .get("message")
                    .is_some_and(|m| m.starts_with(message))
            })
            .collect();
        assert_eq!(matching.len(), 1, "{events:?}");
        let fields = matching.first().unwrap();
        assert_eq!(fields.get("caller").map(String::as_str), Some(caller));
        assert_eq!(fields.get("role").map(String::as_str), Some(role));
        assert!(!fields.get("message").unwrap().contains("user="));
    }

    pub(super) async fn wait_for(&self, message: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if self.0.lock().unwrap().iter().any(|fields| {
                    fields
                        .get("message")
                        .is_some_and(|m| m.starts_with(message))
                }) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the subscription task must log its send failure");
    }
}

pub(super) fn identity(instance: &str) -> MtlsIdentity {
    MtlsIdentity {
        instance: instance.to_string(),
        service: "web-app".to_string(),
        host: "node-01".to_string(),
        domain: "customer.internal".to_string(),
    }
}

struct LogQuery;

#[Object]
impl LogQuery {
    async fn log(&self, ctx: &Context<'_>) -> bool {
        crate::error_with_username!(ctx, "error {}", 42);
        crate::info_with_username!(ctx, "info {}", 42);
        crate::warn_with_username!(ctx, "warn {}", 42);
        true
    }
}

#[tokio::test(flavor = "current_thread")]
async fn macros_record_connection_fields_and_preserve_messages() {
    let schema = Schema::build(LogQuery, EmptyMutation, EmptySubscription).finish();
    for authenticated in [true, false] {
        let (events, _guard) = CapturedEvents::start();
        let mut request =
            Request::new("{ log }").data(RoleGuard::Role(Role::SecurityAdministrator));
        if authenticated {
            request = request.data(identity("001"));
        }
        let response = schema.execute(request).await;
        assert!(response.errors.is_empty(), "{response:?}");
        let caller = if authenticated {
            "001.web-app.node-01.customer.internal"
        } else {
            "an unauthenticated caller"
        };
        for message in ["error 42", "info 42", "warn 42"] {
            events.assert_fields(message, caller, "SecurityAdministrator");
        }
    }
}
