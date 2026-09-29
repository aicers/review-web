//! The maintenance gate under which GraphQL mutations are refused.
//!
//! An embedding application closes the gate for a maintenance window, such as
//! the snapshot of a pending `Rollback` update, and opens it again when the
//! window ends. While it is closed, every GraphQL document containing a
//! mutation is refused before any resolver runs; documents without a mutation
//! run as usual.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use async_graphql::{
    ErrorExtensionValues, Response, ServerError, ServerResult, Variables,
    extensions::{Extension, ExtensionContext, ExtensionFactory, NextExecute, NextParseQuery},
    parser::types::{ExecutableDocument, OperationType},
};
use tokio::sync::RwLock;

/// The `extensions.code` of the error a mutation is refused with while the
/// gate is closed.
pub const MAINTENANCE_ERROR_CODE: &str = "MAINTENANCE";

const MAINTENANCE_ERROR_MESSAGE: &str =
    "REview is under maintenance; retry the request after the update completes";

/// A handle on the gate that admits GraphQL mutations.
///
/// Clones share one state: the embedding application keeps one clone to close
/// and open the gate, and passes another to [`crate::serve`] through
/// [`crate::ServerConfig::maintenance_gate`].
///
/// A mutation is admitted while its execution runs by holding a read guard on
/// the state, and closing the gate takes the write lock. Acquiring the write
/// lock therefore waits for every admitted mutation, and the lock's fairness
/// makes a mutation that arrives meanwhile wait behind it and then be refused.
#[derive(Clone, Debug, Default)]
pub struct MaintenanceGate {
    /// `true` while the gate is closed.
    state: Arc<RwLock<bool>>,
}

impl MaintenanceGate {
    /// Creates an open gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Closes the gate and returns once every mutation admitted ahead of it has
    /// finished.
    ///
    /// This call requests the gate's write lock, and a mutation is admitted by
    /// the read guard it requests on the same lock as its execution starts.
    /// The lock grants requests in the order they entered its fair queue, so
    /// whether a mutation is admitted depends on where its read request stands
    /// relative to this call's write request, not on when the returned future
    /// is first polled:
    ///
    /// - A read request queued after this call's write request waits behind it
    ///   for the whole drain, and its mutation is then refused, unless a later
    ///   [`Self::open`] queued ahead of that read request opens the gate first.
    /// - A read request queued ahead of it may still admit its mutation, even
    ///   after the returned future has been polled: it may be waiting behind an
    ///   earlier write request, such as a pending [`Self::open`], that opens the
    ///   gate before this call's write request is granted. Such a mutation is
    ///   part of the drain, and this call does not return until it has
    ///   finished.
    ///
    /// Closing a gate that stays closed until this call's write request is
    /// granted, with no [`Self::open`] queued ahead of it, admits nothing new
    /// and returns without waiting on any mutation, since none was admitted.
    ///
    /// The drain waits as long as the slowest admitted mutation takes, with no
    /// bound of its own; a caller that needs a bound applies its own timeout.
    /// A mutation received over a WebSocket makes progress only while its
    /// connection's send loop runs, so a client that stops reading its socket
    /// can stall an admitted mutation, and this call with it.
    ///
    /// Dropping the returned future before it completes leaves the gate either
    /// as it was, if the drain had not finished, or closed, if it had; never
    /// half-closed.
    ///
    /// It may be called before [`crate::serve`], so that the server starts
    /// with the gate closed.
    ///
    /// The caller must never call this from inside a mutation, or from code a
    /// mutation awaits: the drain would wait for that mutation, and so for
    /// itself.
    pub async fn close(&self) {
        *self.state.write().await = true;
    }

    /// Opens the gate, so that mutations run again.
    ///
    /// Opening an open gate leaves it open. It takes the same lock as
    /// [`Self::close`], so on an open gate it waits for the running mutations
    /// to finish, and the same caller contract applies: never call it from
    /// inside a mutation or from code a mutation awaits.
    pub async fn open(&self) {
        *self.state.write().await = false;
    }
}

/// Reports whether `error` is the refusal of a mutation under a closed gate.
pub(crate) fn is_refusal(error: &ServerError) -> bool {
    error
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get("code"))
        .is_some_and(|code| *code == async_graphql::Value::from(MAINTENANCE_ERROR_CODE))
}

fn refusal() -> ServerError {
    let mut extensions = ErrorExtensionValues::default();
    extensions.set("code", MAINTENANCE_ERROR_CODE);
    let mut error = ServerError::new(MAINTENANCE_ERROR_MESSAGE, None);
    error.extensions = Some(extensions);
    error
}

/// Refuses GraphQL documents containing a mutation while the gate is closed.
pub(crate) struct MaintenanceExtension {
    gate: MaintenanceGate,
}

impl MaintenanceExtension {
    pub(crate) fn new(gate: MaintenanceGate) -> Self {
        Self { gate }
    }
}

impl ExtensionFactory for MaintenanceExtension {
    fn create(&self) -> Arc<dyn Extension> {
        Arc::new(MaintenanceAdmission {
            gate: self.gate.clone(),
            has_mutation: AtomicBool::new(false),
        })
    }
}

/// The admission of one operation.
///
/// The factory creates one per HTTP request and per WebSocket operation, so
/// `has_mutation` describes the document of that operation alone.
struct MaintenanceAdmission {
    gate: MaintenanceGate,
    /// Whether the parsed document contains a mutation. Both hooks of one
    /// operation run in sequence on the same task, so relaxed ordering
    /// suffices.
    has_mutation: AtomicBool,
}

#[async_trait::async_trait]
impl Extension for MaintenanceAdmission {
    async fn parse_query(
        &self,
        ctx: &ExtensionContext<'_>,
        query: &str,
        variables: &Variables,
        next: NextParseQuery<'_>,
    ) -> ServerResult<ExecutableDocument> {
        let document = next.run(ctx, query, variables).await?;
        let has_mutation = document
            .operations
            .iter()
            .any(|(_, operation)| operation.node.ty == OperationType::Mutation);
        if !has_mutation {
            return Ok(document);
        }
        self.has_mutation.store(true, Ordering::Relaxed);
        if *self.gate.state.read().await {
            return Err(refusal());
        }
        Ok(document)
    }

    async fn execute(
        &self,
        ctx: &ExtensionContext<'_>,
        operation_name: Option<&str>,
        next: NextExecute<'_>,
    ) -> Response {
        if !self.has_mutation.load(Ordering::Relaxed) {
            return next.run(ctx, operation_name).await;
        }
        let admission = self.gate.state.read().await;
        if *admission {
            return Response::from_errors(vec![refusal()]);
        }
        let response = next.run(ctx, operation_name).await;
        drop(admission);
        response
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::pin,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_graphql::{
        Context, Object, Request, Schema, Subscription, ValidationResult,
        extensions::NextValidation,
    };
    use futures::{FutureExt, Stream, StreamExt};
    use tokio::sync::oneshot;

    use super::*;

    const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
    const MUTATION: &str = "mutation { increment }";
    const QUERY: &str = "{ value }";

    type TestSchema = Schema<Query, Mutation, TestSubscription>;

    /// The entry signal and the release of the next mutation that blocks.
    #[derive(Default)]
    struct Blocker(Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>);

    impl Blocker {
        /// Makes the next mutation signal its entry and wait for its release.
        fn arm(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
            let (entered_tx, entered_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            *self.0.lock().unwrap() = Some((entered_tx, release_rx));
            (entered_rx, release_tx)
        }
    }

    struct Query;

    #[Object]
    impl Query {
        async fn value(&self) -> i32 {
            1
        }
    }

    struct Mutation;

    #[Object]
    impl Mutation {
        async fn increment(&self, ctx: &Context<'_>) -> usize {
            let blocked = ctx
                .data_unchecked::<Arc<Blocker>>()
                .0
                .lock()
                .unwrap()
                .take();
            if let Some((entered, release)) = blocked {
                entered.send(()).unwrap();
                release.await.unwrap();
            }
            ctx.data_unchecked::<Arc<AtomicUsize>>()
                .fetch_add(1, Ordering::SeqCst)
                + 1
        }
    }

    struct TestSubscription;

    #[Subscription]
    impl TestSubscription {
        async fn once(&self) -> impl Stream<Item = i32> {
            futures::stream::once(async { 1 })
        }

        async fn never(&self) -> impl Stream<Item = i32> {
            futures::stream::pending()
        }
    }

    struct Harness {
        gate: MaintenanceGate,
        schema: TestSchema,
        counter: Arc<AtomicUsize>,
        blocker: Arc<Blocker>,
    }

    fn harness() -> Harness {
        harness_with(|builder| builder)
    }

    fn harness_with(
        configure: impl FnOnce(
            async_graphql::SchemaBuilder<Query, Mutation, TestSubscription>,
        )
            -> async_graphql::SchemaBuilder<Query, Mutation, TestSubscription>,
    ) -> Harness {
        let gate = MaintenanceGate::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let blocker = Arc::new(Blocker::default());
        let builder = Schema::build(Query, Mutation, TestSubscription)
            .data(counter.clone())
            .data(blocker.clone())
            .extension(MaintenanceExtension::new(gate.clone()));
        Harness {
            gate,
            schema: configure(builder).finish(),
            counter,
            blocker,
        }
    }

    fn assert_refused(response: &Response) {
        assert_eq!(response.errors.len(), 1, "errors: {:?}", response.errors);
        assert!(is_refusal(&response.errors[0]));
        assert_eq!(response.errors[0].message, MAINTENANCE_ERROR_MESSAGE);
        assert_eq!(response.data, async_graphql::Value::Null);
    }

    fn assert_succeeded(response: &Response) {
        assert!(response.errors.is_empty(), "errors: {:?}", response.errors);
    }

    #[tokio::test]
    async fn open_gate_runs_mutations_and_queries() {
        let h = harness();

        assert_succeeded(&h.schema.execute(MUTATION).await);
        assert_succeeded(&h.schema.execute(QUERY).await);
        assert_eq!(h.counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn closed_gate_refuses_a_mutation_before_its_resolver() {
        let h = harness();
        h.gate.close().await;

        assert_refused(&h.schema.execute(MUTATION).await);
        assert_eq!(h.counter.load(Ordering::SeqCst), 0);

        let invalid = h.schema.execute("mutation {").await;
        assert_eq!(invalid.errors.len(), 1);
        assert!(!is_refusal(&invalid.errors[0]));

        h.gate.open().await;
        assert_succeeded(&h.schema.execute(MUTATION).await);
        assert_eq!(h.counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn closing_twice_and_opening_twice_are_idempotent() {
        let h = harness();
        h.gate.close().await;
        h.gate.close().await;
        assert_refused(&h.schema.execute(MUTATION).await);

        h.gate.open().await;
        h.gate.open().await;
        assert_succeeded(&h.schema.execute(MUTATION).await);
        assert_eq!(h.counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn closed_gate_refuses_a_mixed_document_whatever_operation_is_selected() {
        let h = harness();
        h.gate.close().await;

        let request = Request::new("query Read { value } mutation Write { increment }")
            .operation_name("Read");
        assert_refused(&h.schema.execute(request).await);
        assert_eq!(h.counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn closed_gate_lets_queries_and_subscriptions_run() {
        let h = harness();
        h.gate.close().await;

        let query = h.schema.execute(QUERY).await;
        assert_succeeded(&query);
        assert_eq!(
            query.data.into_json().unwrap(),
            serde_json::json!({ "value": 1 })
        );

        let mut events = h.schema.execute_stream("subscription { once }");
        let event = events
            .next()
            .await
            .expect("the subscription yields one item");
        assert_succeeded(&event);
        assert_eq!(
            event.data.into_json().unwrap(),
            serde_json::json!({ "once": 1 })
        );
        assert!(events.next().await.is_none());
    }

    #[tokio::test]
    async fn a_subscription_selected_from_a_mutation_document_does_not_hold_the_gate() {
        let h = harness();

        let request = Request::new("subscription Idle { never } mutation Write { increment }")
            .operation_name("Idle");
        let mut events = h.schema.execute_stream(request);
        assert!(events.next().now_or_never().is_none());

        tokio::time::timeout(CLOSE_TIMEOUT, h.gate.close())
            .await
            .expect("an idle subscription holds no admission");
        drop(events);
        assert_eq!(h.counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_subscription_selected_from_a_mutation_document_carries_the_refusal() {
        let h = harness();
        h.gate.close().await;

        let request = Request::new("subscription Once { once } mutation Write { increment }")
            .operation_name("Once");
        let mut events = h.schema.execute_stream(request);
        assert_refused(&events.next().await.expect("the refusal is yielded"));
    }

    #[tokio::test]
    async fn close_waits_for_an_admitted_mutation() {
        let h = harness();
        let (entered, release) = h.blocker.arm();
        let mutation = tokio::spawn({
            let schema = h.schema.clone();
            async move { schema.execute(MUTATION).await }
        });
        entered.await.unwrap();

        let mut close = pin!(h.gate.close());
        assert!(close.as_mut().now_or_never().is_none());

        release.send(()).unwrap();
        close.await;
        assert_succeeded(&mutation.await.unwrap());
        assert_eq!(h.counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mutation_arriving_during_the_drain_is_refused() {
        let h = harness();
        let (entered, release) = h.blocker.arm();
        let first = tokio::spawn({
            let schema = h.schema.clone();
            async move { schema.execute(MUTATION).await }
        });
        entered.await.unwrap();

        let mut close = pin!(h.gate.close());
        assert!(close.as_mut().now_or_never().is_none());

        let second = tokio::spawn({
            let schema = h.schema.clone();
            async move { schema.execute(MUTATION).await }
        });
        release.send(()).unwrap();
        close.await;

        assert_succeeded(&first.await.unwrap());
        assert_refused(&second.await.unwrap());
        assert_eq!(h.counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropping_close_while_it_waits_leaves_the_gate_open() {
        let h = harness();
        let (entered, release) = h.blocker.arm();
        let mutation = tokio::spawn({
            let schema = h.schema.clone();
            async move { schema.execute(MUTATION).await }
        });
        entered.await.unwrap();

        let close = h.gate.close();
        assert!(close.now_or_never().is_none());

        release.send(()).unwrap();
        assert_succeeded(&mutation.await.unwrap());
        assert_succeeded(&h.schema.execute(MUTATION).await);
        assert_eq!(h.counter.load(Ordering::SeqCst), 2);
    }

    /// Holds validation, which runs between parsing and execution, until the
    /// test releases it.
    struct HeldValidation(Arc<Blocker>);

    impl ExtensionFactory for HeldValidation {
        fn create(&self) -> Arc<dyn Extension> {
            Arc::new(HeldValidation(self.0.clone()))
        }
    }

    #[async_trait::async_trait]
    impl Extension for HeldValidation {
        async fn validation(
            &self,
            ctx: &ExtensionContext<'_>,
            next: NextValidation<'_>,
        ) -> Result<ValidationResult, Vec<ServerError>> {
            let held = self.0.0.lock().unwrap().take();
            if let Some((entered, release)) = held {
                entered.send(()).unwrap();
                release.await.unwrap();
            }
            next.run(ctx).await
        }
    }

    #[tokio::test]
    async fn gate_closing_between_parsing_and_execution_refuses_the_mutation() {
        let validation = Arc::new(Blocker::default());
        let h = harness_with(|builder| builder.extension(HeldValidation(validation.clone())));
        let (entered, release) = validation.arm();
        let mutation = tokio::spawn({
            let schema = h.schema.clone();
            async move { schema.execute(MUTATION).await }
        });
        entered.await.unwrap();

        tokio::time::timeout(CLOSE_TIMEOUT, h.gate.close())
            .await
            .expect("a parsed mutation holds no admission before its execution");
        release.send(()).unwrap();

        assert_refused(&mutation.await.unwrap());
        assert_eq!(h.counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn mutation_queued_behind_open_and_ahead_of_close_is_admitted_and_drained() {
        let validation = Arc::new(Blocker::default());
        let h = harness_with(|builder| builder.extension(HeldValidation(validation.clone())));

        // The first mutation holds admission.
        let (running_entered, running_release) = h.blocker.arm();
        let running = tokio::spawn({
            let schema = h.schema.clone();
            async move { schema.execute(MUTATION).await }
        });
        running_entered.await.unwrap();

        // The second mutation is parsed, then held before its execution.
        let (parsed_entered, parsed_release) = validation.arm();
        let mut parsed = pin!(h.schema.execute(MUTATION));
        assert!(parsed.as_mut().now_or_never().is_none());
        parsed_entered.await.unwrap();

        let mut open = pin!(h.gate.open());
        assert!(open.as_mut().now_or_never().is_none());

        // Its execution read queues behind `open`, and `close` behind the read.
        let (admitted_entered, admitted_release) = h.blocker.arm();
        parsed_release.send(()).unwrap();
        assert!(parsed.as_mut().now_or_never().is_none());
        let mut close = pin!(h.gate.close());
        assert!(close.as_mut().now_or_never().is_none());

        running_release.send(()).unwrap();
        assert_succeeded(&running.await.unwrap());
        open.await;

        // `close` was polled first, yet the queued mutation is admitted.
        assert!(parsed.as_mut().now_or_never().is_none());
        admitted_entered.await.unwrap();
        assert!(close.as_mut().now_or_never().is_none());

        admitted_release.send(()).unwrap();
        assert_succeeded(&parsed.await);
        close.await;
        assert_refused(&h.schema.execute(MUTATION).await);
        assert_eq!(h.counter.load(Ordering::SeqCst), 2);
    }
}
