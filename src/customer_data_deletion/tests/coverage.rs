//! Deterministic fault and scheduling tests at review-web's Store boundaries.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    ScanJobs,
    CollectNodes,
    PersistRequest,
    Worker,
    Events,
    Hosts,
    TrafficFilters,
    Nodes,
    PersistTerminal,
}

type Hook = Arc<dyn Fn(Stage, u32) -> anyhow::Result<()> + Send + Sync>;
static HOOK: std::sync::Mutex<Option<(usize, Hook)>> = std::sync::Mutex::new(None);

// Hooks are scoped to a particular Store, never to a thread: the worker runs
// on Tokio's blocking pool. Other modules' concurrently running tests cannot
// hit this Store's hook, and a guard clears it even after a failed assertion.
struct HookGuard;

impl HookGuard {
    fn install(store: &RwLock<Store>, hook: Hook) -> Self {
        let address = std::ptr::from_ref(&*read_store(store).unwrap()).addr();
        *HOOK.lock().unwrap() = Some((address, hook));
        Self
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        *HOOK.lock().unwrap() = None;
    }
}

pub(crate) fn checkpoint(store: &Store, stage: Stage, customer_id: u32) -> anyhow::Result<()> {
    let hook = HOOK.lock().unwrap().as_ref().and_then(|(address, hook)| {
        (*address == std::ptr::from_ref(store).addr()).then(|| Arc::clone(hook))
    });
    if let Some(hook) = hook {
        hook(stage, customer_id)?;
    }
    Ok(())
}

fn job(store: &RwLock<Store>, customer_id: u32) -> CustomerDataDeletionJob {
    read_store(store)
        .unwrap()
        .customer_data_deletion_map()
        .get(customer_id)
        .unwrap()
        .unwrap()
}

fn put_job(
    store: &RwLock<Store>,
    customer_id: u32,
    results: Vec<CustomerDataDeletionServiceResult>,
) {
    read_store(store)
        .unwrap()
        .customer_data_deletion_map()
        .put(&CustomerDataDeletionJob {
            customer_id,
            service_results: results,
        })
        .unwrap();
}

fn terminal_result(
    service: CustomerDataDeletionService,
    host: &str,
    status: CustomerDataDeletionStatus,
) -> CustomerDataDeletionServiceResult {
    CustomerDataDeletionServiceResult {
        status,
        completed_at: Some(456),
        error: (status == CustomerDataDeletionStatus::Failed).then(|| "old failure".to_string()),
        ..pending_result(service, &[host])
    }
}

#[test]
fn only_the_service_segment_matches() {
    for service in ["piglet", "reproduce"] {
        assert!(agent_has_service(&format!("001.{service}"), service));
        assert!(agent_has_service(
            &format!("001.{service}.node.example"),
            service
        ));
        for key in [
            format!("{service}.hog.node.example"),
            format!("001.hog.{service}.example"),
            format!("001.not-{service}.example"),
            service.to_string(),
        ] {
            assert!(!agent_has_service(&key, service), "{key}");
        }
    }
}

#[test]
fn initial_and_retry_plans_are_sorted_and_deduplicated() {
    let test_store = TestStore::new();
    let z = put_active_node(&test_store, 1, "z.example");
    let a = put_active_node(&test_store, 1, "a.example");
    put_active_node(&test_store, 2, "unrelated.example");
    let plan = collect_initial_plan(&test_store.store, 1).unwrap().unwrap();
    let review = plan.review_targets.as_ref().unwrap();
    assert_eq!(review.node_ids, [z, a]);
    assert_eq!(review.host_fqdns, ["a.example", "z.example"]);
    assert_eq!(
        review.event_service_fqdns,
        ["piglet.a.example", "piglet.z.example"]
    );
    let initial = initial_job(&plan, 123);
    assert_eq!(initial.service_results.len(), 5);
    assert!(initial.service_results.iter().all(|r| r.requested_at == 123
        && r.completed_at.is_none()
        && r.error.is_none()
        && r.status == CustomerDataDeletionStatus::InProgress));
    assert_eq!(
        plan.remote_targets
            .iter()
            .map(CustomerDataDeletionTarget::target_service_key)
            .collect::<Vec<_>>(),
        [
            "hog.a.example",
            "hog.z.example",
            "piglet.a.example",
            "piglet.z.example"
        ]
    );

    let mut failed = initial;
    for result in &mut failed.service_results {
        result.status = CustomerDataDeletionStatus::Failed;
    }
    failed
        .service_results
        .push(failed.service_results.last().unwrap().clone());
    failed.service_results.first_mut().unwrap().host_fqdns =
        vec!["z.example".into(), "a.example".into(), "z.example".into()];
    let retry = retry_plan(&test_store.store, &failed).unwrap();
    assert_eq!(retry.remote_targets, plan.remote_targets);
    let review = retry.review_targets.unwrap();
    assert_eq!(review.node_ids, [z, a]);
    assert_eq!(review.host_fqdns, ["a.example", "z.example"]);
    assert_eq!(
        review.event_service_fqdns,
        [
            "piglet.a.example",
            "piglet.z.example",
            "reproduce.a.example",
            "reproduce.z.example"
        ]
    );
}

#[tokio::test]
async fn pre_start_failures_return_graphql_errors_without_starting_work() {
    let test_store = TestStore::new();
    put_active_node(&test_store, 1, "one.example");
    let manager = Arc::new(CustomerDataDeletionTaskManager::default());
    let agent = Arc::new(RecordingAgentManager::default());
    let shared: SharedAgentManager = agent.clone();
    let schema = test_schema(&test_store, shared, Arc::clone(&manager));
    for stage in [Stage::ScanJobs, Stage::CollectNodes, Stage::PersistRequest] {
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |at, _| {
                if at == stage {
                    bail!("injected {stage:?} failure");
                }
                Ok(())
            }),
        );
        let response = schema
            .execute(
                Request::new(r#"mutation { deleteCustomerData(customerId: "1") }"#)
                    .data(RoleGuard::Role(Role::SystemAdministrator)),
            )
            .await;
        assert_eq!(response.errors.len(), 1);
        assert!(
            response
                .errors
                .first()
                .unwrap()
                .message
                .contains(&format!("{stage:?}"))
        );
        assert!(manager.state.lock().await.active.is_none());
        assert!(agent.targets.lock().unwrap().is_empty());
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .customer_data_deletion_map()
                .get(1)
                .unwrap()
                .is_none()
        );
    }
    let failed = terminal_result(
        CustomerDataDeletionService::Sensor,
        "one.example",
        CustomerDataDeletionStatus::Failed,
    );
    put_job(&test_store.store, 1, vec![failed]);
    let before = job(&test_store.store, 1);
    let _hook = HookGuard::install(
        &test_store.store,
        Arc::new(|stage, _| {
            if stage == Stage::PersistRequest {
                bail!("retry persistence failed");
            }
            Ok(())
        }),
    );
    let response = schema
        .execute(
            Request::new(r#"mutation { deleteCustomerData(customerId: "1") }"#)
                .data(RoleGuard::Role(Role::SystemAdministrator)),
        )
        .await;
    assert_eq!(response.errors.len(), 1);
    assert!(manager.state.lock().await.active.is_none());
    assert!(agent.targets.lock().unwrap().is_empty());
    assert_eq!(job(&test_store.store, 1), before);
}

#[tokio::test]
async fn delivery_finishes_before_local_work_for_initial_and_retry_requests() {
    let test_store = TestStore::new();
    for (customer_id, retry, fail) in [
        (1, false, false),
        (2, true, false),
        (3, false, true),
        (4, true, true),
    ] {
        // Complete earlier remote results so they do not block the next customer.
        for previous in 1..customer_id {
            put_job(
                &test_store.store,
                previous,
                vec![terminal_result(
                    CustomerDataDeletionService::Review,
                    "done",
                    CustomerDataDeletionStatus::Succeeded,
                )],
            );
        }
        let node = put_active_node(&test_store, customer_id, &format!("{customer_id}.example"));
        if retry {
            let plan = collect_initial_plan(&test_store.store, customer_id)
                .unwrap()
                .unwrap();
            let mut persisted = initial_job(&plan, 123);
            for result in &mut persisted.service_results {
                result.status = CustomerDataDeletionStatus::Failed;
            }
            put_job(&test_store.store, customer_id, persisted.service_results);
        }
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let agent = Arc::new(RecordingAgentManager {
            fail_delivery: fail,
            delivery_gate: Some(Arc::clone(&gate)),
            ..RecordingAgentManager::default()
        });
        let shared: SharedAgentManager = agent.clone();
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        assert_eq!(
            request_deletion(customer_id, Arc::clone(&test_store.store), shared, &manager)
                .await
                .unwrap(),
            CustomerDataDeletionRequestStatus::Accepted
        );
        agent.delivery_started.notified().await;
        assert_eq!(agent.targets.lock().unwrap().len(), 2);
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .node_map()
                .get_by_id(node)
                .unwrap()
                .is_some()
        );
        let before = job(&test_store.store, customer_id);
        assert!(
            before
                .service_results
                .iter()
                .all(|r| r.status == CustomerDataDeletionStatus::InProgress)
        );
        // Shutdown must await the outer delivery supervisor, even though no
        // blocking worker exists yet.
        let shutdown = manager.shutdown_and_wait();
        tokio::pin!(shutdown);
        assert!(futures::poll!(&mut shutdown).is_pending());
        gate.add_permits(1);
        shutdown.await;
        let after = job(&test_store.store, customer_id);
        let review = after.service_results.first().unwrap();
        assert_eq!(
            review.requested_at,
            before.service_results.first().unwrap().requested_at
        );
        assert!(review.completed_at.is_some());
        assert_eq!(
            review.status,
            if fail {
                CustomerDataDeletionStatus::Failed
            } else {
                CustomerDataDeletionStatus::Succeeded
            }
        );
        assert_eq!(
            read_store(&test_store.store)
                .unwrap()
                .node_map()
                .get_by_id(node)
                .unwrap()
                .is_some(),
            fail
        );
        assert!(
            after
                .service_results
                .iter()
                .skip(1)
                .all(|r| r.status == CustomerDataDeletionStatus::InProgress)
        );
    }
}

#[tokio::test]
async fn worker_errors_and_panics_persist_failure_without_changing_requested_at() {
    let test_store = TestStore::new();
    for panic_worker in [false, true] {
        put_job(
            &test_store.store,
            1,
            vec![pending_result(
                CustomerDataDeletionService::Review,
                &["one.example"],
            )],
        );
        let _hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, _| {
                if stage == Stage::Worker {
                    assert!(!panic_worker, "injected worker panic");
                    bail!("injected deletion failure");
                }
                Ok(())
            }),
        );
        let targets =
            restore_review_targets(&test_store.store, 1, &["one.example".into()]).unwrap();
        run_review_worker_and_persist(Arc::clone(&test_store.store), 1, targets).await;
        let result = job(&test_store.store, 1).service_results.remove(0);
        assert_eq!(result.status, CustomerDataDeletionStatus::Failed);
        assert_eq!(result.requested_at, 123);
        assert!(result.completed_at.is_some());
        assert!(result.error.unwrap().contains(if panic_worker {
            "failed to join"
        } else {
            "injected deletion failure"
        }));
    }
}

#[tokio::test]
async fn deletion_stops_at_each_failed_boundary_and_retry_finishes() {
    const STAGES: [Stage; 4] = [
        Stage::Events,
        Stage::Hosts,
        Stage::TrafficFilters,
        Stage::Nodes,
    ];
    let test_store = TestStore::new();
    for fail_stage in STAGES {
        let node = put_active_node(&test_store, 1, "one.example");
        put_job(
            &test_store.store,
            1,
            vec![pending_result(
                CustomerDataDeletionService::Review,
                &["one.example"],
            )],
        );
        let visited = Arc::new(std::sync::Mutex::new(Vec::new()));
        let calls = Arc::clone(&visited);
        let hook = HookGuard::install(
            &test_store.store,
            Arc::new(move |stage, _| {
                if STAGES.contains(&stage) {
                    calls.lock().unwrap().push(stage);
                }
                if stage == fail_stage {
                    bail!("injected RocksDB boundary error");
                }
                Ok(())
            }),
        );
        let targets =
            restore_review_targets(&test_store.store, 1, &["one.example".into()]).unwrap();
        run_review_worker_and_persist(Arc::clone(&test_store.store), 1, targets).await;
        let expected: Vec<_> = STAGES
            .into_iter()
            .take_while(|s| *s != fail_stage)
            .chain([fail_stage])
            .collect();
        assert_eq!(*visited.lock().unwrap(), expected);
        let failed = job(&test_store.store, 1);
        assert_eq!(
            failed.service_results.first().unwrap().status,
            CustomerDataDeletionStatus::Failed
        );
        if fail_stage == Stage::Events {
            let error = failed
                .service_results
                .first()
                .unwrap()
                .error
                .as_ref()
                .unwrap();
            assert!(error.contains("events"));
            assert!(error.contains("piglet.one.example"));
            assert!(error.contains("reproduce.one.example"));
        }
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .node_map()
                .get_by_id(node)
                .unwrap()
                .is_some()
        );
        drop(hook);
        let manager = Arc::new(CustomerDataDeletionTaskManager::default());
        let agent = Arc::new(RecordingAgentManager::default());
        let shared: SharedAgentManager = agent.clone();
        assert_eq!(
            request_deletion(1, Arc::clone(&test_store.store), shared, &manager)
                .await
                .unwrap(),
            CustomerDataDeletionRequestStatus::Accepted
        );
        manager.shutdown_and_wait().await;
        assert_eq!(
            job(&test_store.store, 1)
                .service_results
                .first()
                .unwrap()
                .status,
            CustomerDataDeletionStatus::Succeeded
        );
        assert!(agent.targets.lock().unwrap().is_empty());
        assert!(
            read_store(&test_store.store)
                .unwrap()
                .node_map()
                .get_by_id(node)
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn recovery_continues_after_worker_and_terminal_persistence_failures() {
    let test_store = TestStore::new();
    for customer_id in [4, 3, 2, 1] {
        put_job(
            &test_store.store,
            customer_id,
            vec![pending_result(
                CustomerDataDeletionService::Review,
                &[&format!("{customer_id}.example")],
            )],
        );
    }
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let calls = Arc::clone(&order);
    let _hook = HookGuard::install(
        &test_store.store,
        Arc::new(move |stage, customer| {
            if stage == Stage::Worker {
                calls.lock().unwrap().push(customer);
                if customer == 1 {
                    bail!("deletion failed");
                }
                assert_ne!(customer, 2, "worker panicked");
            }
            if stage == Stage::PersistTerminal && customer == 3 {
                bail!("terminal persistence failed");
            }
            Ok(())
        }),
    );
    let manager = Arc::new(CustomerDataDeletionTaskManager::default());
    assert!(
        recover_customer_data_deletion_on_startup(
            Arc::clone(&test_store.store),
            Arc::clone(&manager)
        )
        .await
        .unwrap()
        .is_empty()
    );
    // Keep the outer handle registered while waiting for it.
    loop {
        if manager
            .state
            .lock()
            .await
            .active
            .as_ref()
            .unwrap()
            .1
            .is_finished()
        {
            break;
        }
        tokio::task::yield_now().await;
    }
    manager.shutdown_and_wait().await;
    assert_eq!(*order.lock().unwrap(), [1, 2, 3, 4]);
    for (customer_id, status) in [
        (1, CustomerDataDeletionStatus::Failed),
        (2, CustomerDataDeletionStatus::Failed),
        (3, CustomerDataDeletionStatus::InProgress),
        (4, CustomerDataDeletionStatus::Succeeded),
    ] {
        let result = job(&test_store.store, customer_id)
            .service_results
            .remove(0);
        assert_eq!(result.status, status);
        assert_eq!(result.requested_at, 123);
        assert_eq!(result.completed_at.is_none(), customer_id == 3);
    }
}

#[tokio::test]
async fn recovery_returns_all_remote_targets_before_sequential_workers_finish() {
    let test_store = TestStore::new();
    for customer_id in [20, 10] {
        let host = format!("{customer_id}.example");
        put_job(
            &test_store.store,
            customer_id,
            vec![
                pending_result(CustomerDataDeletionService::Review, &[&host]),
                pending_result(CustomerDataDeletionService::Sensor, &[&host]),
            ],
        );
    }
    let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
    let (release, releases) = std::sync::mpsc::channel();
    let releases = std::sync::Mutex::new(releases);
    let _hook = HookGuard::install(
        &test_store.store,
        Arc::new(move |stage, customer| {
            if stage == Stage::Worker {
                started.send(customer).unwrap();
                releases.lock().unwrap().recv().unwrap();
            }
            Ok(())
        }),
    );
    let manager = Arc::new(CustomerDataDeletionTaskManager::default());
    let targets = recover_customer_data_deletion_on_startup(
        Arc::clone(&test_store.store),
        Arc::clone(&manager),
    )
    .await
    .unwrap();
    assert_eq!(
        targets
            .iter()
            .map(CustomerDataDeletionTarget::customer_id)
            .collect::<Vec<_>>(),
        [10, 20]
    );
    assert_eq!(
        targets
            .iter()
            .map(CustomerDataDeletionTarget::target_service_key)
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
    let outer_id = manager.state.lock().await.active.as_ref().unwrap().1.id();
    assert_eq!(starts.recv().await, Some(10));
    assert_eq!(manager.state.lock().await.active.as_ref().unwrap().0, 10);
    assert!(starts.try_recv().is_err());
    assert_eq!(
        job(&test_store.store, 20)
            .service_results
            .first()
            .unwrap()
            .status,
        CustomerDataDeletionStatus::InProgress
    );
    release.send(()).unwrap();
    assert_eq!(starts.recv().await, Some(20));
    {
        let state = manager.state.lock().await;
        let (customer, handle) = state.active.as_ref().unwrap();
        assert_eq!(*customer, 20);
        assert_eq!(handle.id(), outer_id);
    }
    assert_eq!(
        job(&test_store.store, 10)
            .service_results
            .first()
            .unwrap()
            .status,
        CustomerDataDeletionStatus::Succeeded
    );
    release.send(()).unwrap();
    manager.shutdown_and_wait().await;
    assert_eq!(
        job(&test_store.store, 20)
            .service_results
            .first()
            .unwrap()
            .status,
        CustomerDataDeletionStatus::Succeeded
    );
}

#[tokio::test]
async fn shutdown_finishes_current_recovery_and_leaves_queued_jobs_pending() {
    let test_store = TestStore::new();
    for customer_id in [1, 2] {
        put_job(
            &test_store.store,
            customer_id,
            vec![pending_result(
                CustomerDataDeletionService::Review,
                &[&format!("{customer_id}.example")],
            )],
        );
    }
    let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
    let (release, releases) = std::sync::mpsc::channel();
    let releases = std::sync::Mutex::new(releases);
    let _hook = HookGuard::install(
        &test_store.store,
        Arc::new(move |stage, customer| {
            if stage == Stage::Worker {
                started.send(customer).unwrap();
                releases.lock().unwrap().recv().unwrap();
            }
            Ok(())
        }),
    );
    let manager = Arc::new(CustomerDataDeletionTaskManager::default());
    recover_customer_data_deletion_on_startup(Arc::clone(&test_store.store), Arc::clone(&manager))
        .await
        .unwrap();
    assert_eq!(starts.recv().await, Some(1));
    let shutdown = manager.shutdown_and_wait();
    tokio::pin!(shutdown);
    assert!(futures::poll!(&mut shutdown).is_pending());
    assert!(manager.state.lock().await.shutting_down);
    release.send(()).unwrap();
    shutdown.await;
    assert!(starts.try_recv().is_err());
    assert_eq!(
        job(&test_store.store, 1)
            .service_results
            .first()
            .unwrap()
            .status,
        CustomerDataDeletionStatus::Succeeded
    );
    assert_eq!(
        job(&test_store.store, 2).service_results.first().unwrap(),
        &pending_result(CustomerDataDeletionService::Review, &["2.example"])
    );
}

#[tokio::test]
async fn shutdown_winning_the_mutex_prevents_request_registration() {
    let test_store = TestStore::new();
    put_active_node(&test_store, 1, "one.example");
    let manager = Arc::new(CustomerDataDeletionTaskManager::default());
    let agent = Arc::new(RecordingAgentManager::default());
    let shared: SharedAgentManager = agent.clone();
    let state = manager.state.lock().await;
    let shutdown = manager.shutdown_and_wait();
    tokio::pin!(shutdown);
    assert!(futures::poll!(&mut shutdown).is_pending());
    let request = request_deletion(1, Arc::clone(&test_store.store), shared, &manager);
    tokio::pin!(request);
    assert!(futures::poll!(&mut request).is_pending());
    drop(state);
    shutdown.await;
    assert_eq!(
        request.await.unwrap(),
        CustomerDataDeletionRequestStatus::BlockedByShutdown
    );
    assert!(manager.state.lock().await.active.is_none());
    assert!(agent.targets.lock().unwrap().is_empty());
    assert!(
        read_store(&test_store.store)
            .unwrap()
            .customer_data_deletion_map()
            .get(1)
            .unwrap()
            .is_none()
    );
}
