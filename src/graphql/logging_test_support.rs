use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context as LayerContext, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

use crate::auth::MtlsIdentity;

#[derive(Clone, Default)]
pub(super) struct CapturedEvents {
    events: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    notify: Arc<tokio::sync::Notify>,
}

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
        self.events.lock().unwrap().push(fields.0);
        self.notify.notify_one();
    }
}

impl CapturedEvents {
    pub(super) fn start() -> (Self, tracing::subscriber::DefaultGuard) {
        let events = Self::default();
        let guard = tracing::subscriber::set_default(Registry::default().with(events.clone()));
        (events, guard)
    }

    pub(super) fn assert_fields(&self, message: &str, caller: &str, role: Option<&str>) {
        let events = self.events.lock().unwrap();
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
        assert_eq!(fields.get("role").map(String::as_str), role);
        assert!(!fields.get("message").unwrap().contains("user="));
    }

    pub(super) async fn wait_for(&self, message: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if self.events.lock().unwrap().iter().any(|fields| {
                    fields
                        .get("message")
                        .is_some_and(|m| m.starts_with(message))
                }) {
                    break;
                }
                self.notify.notified().await;
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
