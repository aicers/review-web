use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Request, Schema};
use tracing::{error, info, warn};

use super::logging_test_support::{CapturedEvents, identity};
use super::{Role, RoleGuard};

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
            events.assert_fields(message, caller, Some("SecurityAdministrator"));
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn macros_omit_missing_role() {
    let schema = Schema::build(LogQuery, EmptyMutation, EmptySubscription).finish();
    let (events, _guard) = CapturedEvents::start();
    let response = schema.execute(Request::new("{ log }")).await;
    assert!(response.errors.is_empty(), "{response:?}");
    for message in ["error 42", "info 42", "warn 42"] {
        events.assert_fields(message, "an unauthenticated caller", None);
    }
}
