# Implementation doc D3: review-web — PackageDeployer trait, mutations, upload route

**Repo:** `aicers/review-web` · **Grounded on** `origin/main` @ `5d0eba5`
(v0.34.0). Re-verify before relying.

**Status:** `aicers/review-web` — an aicers repo (in-repo issue flow,
AgentCoop-decomposable; **not** draft-only). Derived from the RFC-D scope
(the review-web slice). This
document is **self-contained**: it restates inline every cross-repo contract an
issue needs.

**Position:** review-web is the GraphQL backend (and an axum server). It
**defines** the traits the manager implements and **calls** them from
resolvers. `aicers/review` (D2) **depends on** this crate (the `web` feature),
so **the `PackageDeployer` trait defined here (§4) is a compile-time
precedent for review's impl (D2 §4c)** — this trait-definition issue should
land before review's trait-impl issue. The persisted types come from
`aicers/review-database` (D1).

## 1. Scope

review-web today exposes GraphQL for node config (apply-draft flow) + coarse
status, and serves some binary axum routes. It has **no** install / package /
version / upload surface. This doc adds, additively on the immediate-action
model (**no `desiredVersion`**):

1. a new **`PackageDeployer` trait** (sibling to `AgentManager`), the install/
   deploy interface review implements;
2. **immediate-action mutations** — `installService` / `updateService` /
   `removeService` / `updateCoreComponent` / `onboardHost`;
3. **`installedVersion` + `installedCommit` + `lifecycle` + `updateAvailable`**
   as **inline fields** on the node/agent/external-service + core-component
   read types (not a separate rollup — RFC-E §8);
4. a **streaming binary upload axum route** for signed `.pkg` (not base64 in
   GraphQL), fronted by the aice-web-next BFF;
5. **SDL regen**.

## 2. Current state (grounded, `origin/main` @ `5d0eba5`)

- **`AgentManager` trait** (`src/backend.rs:12`, `pub trait AgentManager: Send
  - Sync`):`online_apps_by_host_id`(`:43`),`get_process_list`(`:53`),
  `get_resource_usage`(`:56`),`halt`(`:59`),`ping`(`:63`),`reboot`
  (`:66`),`update_config`(`:69`), plus broadcast/send helpers. It is
  **agent-specific** (monitoring + config push).
- **GraphQL node** (`src/graphql/node.rs` + `src/graphql/node/`): mutations in
  `node/control.rs` — `node_reboot` (`:98`), `node_shutdown` (`:116`),
  `apply_node` (`:144`), `apply_node_draft` (`:244`), `apply_agent_config`
  (`:303`); `notify_agents` (`:383`), `update_db` (`:467`).
  `node/crud.rs` (`node_list`/`insert_node`), `node/status.rs`,
  `node/input.rs` (`NodeInput`).
- **Status enums** (`src/graphql/node.rs`): `AgentStatus` (`:60`) and
  `ExternalServiceStatus` (`:69`), each
  `Disabled`/`Enabled`/`ReloadFailed`/`Unknown` — a **config-reload** state
  (`Unknown` mirrors review-database's `Status::Unknown`, RFC-D1 §2).
  **No version, lifecycle, or update fields.**
- **axum precedent**: `src/archive.rs` builds an axum `Router` with `post`
  handlers (`:172-174`) — the upload route follows **only its Router/route
  wiring + auth pattern**. ⚠️ It is **not** a streaming-body precedent: it
  buffers the whole body with `axum::body::to_bytes(body, usize::MAX)`
  (`:135`), which the upload route must **not** copy (§5c requires a streamed
  body).
- **No install/package/module-store/upload surface.**

## 3. Contract this repo must provide (restated, self-contained)

- **Immediate actions** (not draft edits): each mutation drives review's apply
  (D2 §4b) and returns success/failure. **No `desiredVersion`.** Config keeps
  its existing `apply_node_draft` / `apply_agent_config` draft→Apply flow,
  untouched.
- **Build selector** = a released `version` **or** a `commit` (RFC-A §4),
  carried through the trait as a `BuildSelector` (version XOR commit).
  **review (D2) resolves it to a full `(version, commit)` `BuildId` against
  its store index — in both directions:** a `version` → that version's
  most-recently accepted commit; a `commit` → the `version` that build's
  in-package manifest carries. A selector that matches **no** accepted build
  is a typed error (no silent default). review-web does **not** resolve —
  only review owns the index. Actions carry an **`on_failure`** policy
  (`Rollback` default | `Hold`).
- **`installedVersion` + `installedCommit` + `lifecycle` + `updateAvailable`**
  are read fields; `updateAvailable` is computed per build (installed
  `(version, commit)` ≠ store `latest_build`). **Inline** on the existing
  list/status read path, **not** a separate fleet-rollup query (so a future
  fleet view is frontend-only — RFC-E §8).
- **Package identity** = manifest `component` == request `target`
  (host-agnostic); modules and core components alike. Canonical package-ids:
  `piglet`/`giganto`/`hog`/`reconverge`/`crusher` (modules), `review`/
  `aice-web-next`/`roxyd` (core), `bootroot` (core, **not** updatable —
  installer-managed).
- **Upload** is a streaming binary transfer (the signed `.pkg`), **not** base64
  in GraphQL; review-web relays the bytes to review's store receiver (D2 §4a),
  which verifies and stores.

## 4. The `PackageDeployer` trait

- **A new sibling trait, NOT an extension of `AgentManager`.** `AgentManager`
  (`backend.rs:12`) is agent-specific (monitoring + config for agents that
  dial in); install/update targets **packages** by package-id — covering
  agents, **external services (Giganto)**, and **core components** alike, all
  driven **via roxyd**, not via the installed thing being an agent. So the
  deploy surface is its own concern.
- **Name**: `PackageDeployer` — deliberately not `…Manager` (overloaded) and
  not `…Controller` (immediate commands, not a reconcile loop).
- Define it in `src/backend.rs` beside `AgentManager` (restated; review D2
  §4c implements it):
  ```rust
  #[async_trait]
  pub trait PackageDeployer: Send + Sync {
      // deploy: install = update.
      // `selector` is version-XOR-commit; review (D2) resolves it to a full
      // (version, commit) BuildId against its store index — the trait does
      // NOT take both pre-resolved, because only review owns the index that
      // maps a version→its latest accepted commit or a commit→its version.
      // Applied  = the agent finished and reported a terminal outcome.
      // Accepted = self-disrupting apply (roxyd's OWN binary, or REView
      //            itself): the agent answered before the swap tore down the
      //            response channel, so the true outcome is reconciled from
      //            operation_attempt on reconnect (RFC-C §4, RFC-D2 §4e).
      //            A bare Result<()> cannot express this, and the resolver
      //            must not report it as "done" — it returns the operation
      //            id and the UI polls (§5b).
      // Every package-scoped method carries the `instance` it acts on
      // (Option<u32>: None = a single-instance core component, Some(n) = one
      // of a module's instances). A host may run 001.piglet and 002.piglet
      // at once (RFC-D1 §2), so (host, target) alone is ambiguous.
      async fn deploy(
          &self, host: &str, target: &str, instance: Option<u32>,
          selector: BuildSelector,
          bootstrap_material: Option<BootstrapMaterial>,
          on_failure: FailurePolicy,
      ) -> Result<DeployOutcome, anyhow::Error>;
      async fn remove(
          &self, host: &str, target: &str, instance: Option<u32>,
      ) -> Result<(), anyhow::Error>;
      async fn package_status(
          &self, host: &str, target: &str, instance: Option<u32>,
      ) -> Result<PackageState, anyhow::Error>;
      async fn read_version(
          &self, host: &str, target: &str, instance: Option<u32>,
      ) -> Result<BuildId, anyhow::Error>;
      // register mints a bootroot identity for ONE instance. v1 pins the
      // instance to Some(1) for a module and None for a core component
      // (RFC-A §4) -- nothing here allocates. The registrar derives the
      // registration_id and the SAN from the parts (service_name, host,
      // instance); `service_name` is the component's PLAIN keyword, never a
      // composed name. The `spec` (RFC-A §4 registration template) and
      // `idempotency_key` (operation_attempt ledger, D1 §4d) are NOT
      // parameters: the caller holds neither the signed package nor the
      // ledger -- review's impl resolves both and puts them, with the
      // instance, on the node.enroll Register wire (RFC-C §5).
      async fn register(
          &self, service_name: &str, host: &str, instance: Option<u32>,
          mode: DeliveryMode,
      ) -> Result<BootstrapMaterial, anyhow::Error>;
      async fn deregister(
          &self, service_name: &str, host: &str, instance: Option<u32>,
      ) -> Result<(), anyhow::Error>;
  }
  ```
  Resolvers hold a `dyn PackageDeployer` the same way they hold the
  `dyn AgentManager` in the GraphQL context.

## 5. GraphQL surface + upload route

### 5a. Immediate-action mutations (`src/graphql/node/`)

Follow the existing resolver pattern in `node/control.rs` — but **replicate its
full guard chain, not just a role gate**. Every existing host-scoped mutation
runs **two** checks before touching the backend: a `#[graphql(guard = ...)]`
**`RoleGuard`** *and* a per-host **`customer_access::check_hostname_access(ctx,
&hostname)?`** (verified `control.rs:96-99` — `node_reboot` guards on
`SystemAdministrator`/`SecurityAdministrator` then calls
`check_hostname_access` before `agents.reboot`). Because every new mutation
below carries a security-sensitive **`host`** and actuates a real install on
it, each **MUST** apply the same authorization before any `PackageDeployer`
call — a missing customer-access check would let a scoped user install/remove
on a host outside their customer. Specifically:

- **`installService` / `updateService` / `removeService`** — `RoleGuard`
  (`SystemAdministrator` **or** `SecurityAdministrator`, matching the existing
  node mutations) **and** `customer_access::check_hostname_access(ctx, &host)?`
  on the target module host, before the backend call.
- **`updateCoreComponent` / `onboardHost`** — these touch control-plane
  infrastructure (core hosts) or a **not-yet-registered** host with no customer
  mapping, so per-host customer scoping does not apply; require the **stricter
  `SystemAdministrator`** role instead (fleet/infra authority), not the
  Security-admin-or-customer path. `onboardHost` in particular mints a bootroot
  identity (D2 §4d) — a privileged infra action.

New mutations:

- **[DECISION] v1 installs ONE instance per `(component, host)`; the
  mutations still name it.** RFC-A §4 pins the instance to `1` for v1 and
  defers allocation, so `installService` for a `(component, host)` that
  already has a service row is **rejected** with a typed error rather than
  adding a second one. The mutations nevertheless **carry an `instance`**
  (`Some(1)` for a module, `None` for a core component) so that v2 changes
  which values are accepted and not the surface: `updateService` and
  `removeService` take it and reject a value that does not exist. The
  instance is a **number the operator never types** (RFC-A §4): the UI
  passes back what it read from the row it acted on (RFC-E §4). Core
  components take **no** instance and
  a request that supplies one for them is rejected — only the five modules
  are multi-instance.
- **`installService(host, target, buildSelector, onFailure)`** — installs
  the module on a host that does not have it. Because v1 does not allocate,
  the triple `(host, target, instance)` is fully determined by the request,
  so **single-flight dedupes a double-click on its own** — no
  client-supplied key is needed. (This is the direct benefit of pinning the
  number: an allocating mutation would form a fresh triple on every click
  and single-flight could not tell a double-submit from a deliberate second
  add.)
  **[DECISION] Single-flight per
  `(host, target, instance)`:** like
  `onboardHost` is idempotent-per-hostname (D2 §4d), `installService` /
  `updateService` / **`removeService`** must be **single-flight per
  `(host, target, instance)`** — a second call
  while one is in flight is coalesced/rejected, not started, so a double-click
  does not spawn two `operation_attempt`s (with distinct `idempotency_key`s) and
  two concurrent applies (which roxyd's per-target apply lock, RFC-B §4, would
  otherwise have to serialize). **The instance is part of the key**: keying
  on `(host, target)` alone would block adding a second instance while the
  first one's install is still running, which is a legitimate concurrent
  operation rather than a repeated click (RFC-D2 §4b). Instance *allocation*
  is serialized separately and more coarsely, per `(component, host)`
  (RFC-D2 §4d). **`removeService` is in the rule, not just the
  two install mutations**: a `remove` and an `update` dispatched close together
  otherwise reach roxyd concurrently and interleave into a half-removed,
  half-updated module with an owed `Deregister` against an identity the update
  path just re-registered. **Enforcement lives in review's ledger, not in the
  resolver** (RFC-D2 §4b): resolvers are stateless per request, so a
  process-memory guard would not survive a REView restart — review rejects or
  joins an existing non-terminal attempt for the pair before writing a new one
  (RFC-D1 §4d provides the index), and the resolver surfaces that as a typed
  rejection. **Explicit two-step, in this order:** the
  resolver
  (1) calls **`register(service_name = "<target>", host, mode)`** — the
  component's **plain keyword**, never a composed `<target>-<host>` string:
  the registrar derives `registration_id` + SAN from the parts
  `(service_name, host, instance)` (RFC-C §5, RFC-F §5.5), so review sends no
  composed name and there is no caller value to disagree with. The
  module-enrollment `DeliveryMode` is the **`RemoteBootstrap`** variant (RFC-C
  §5; bootroot-remote enrollment via the on-host agent, RFC-B §5). `register`
  takes the **`instance`** — `Some(1)` for a module in v1, `None` for a
  core component or for `onboardHost`'s `roxyd` (RFC-A §4) — and mints the
  bootroot identity, returning the `BootstrapMaterial` (review derives the
  `spec` + `idempotency_key` internally, D2 §4d). The registrar refuses a
  `Register` whose `instance` presence contradicts the component's
  multiplicity (`ServiceInstanceMismatch`, RFC-C §5). Then (2) calls
  **`deploy(host, target, instance, selector, Some(material), onFailure)`** —
  with the same `instance` — to stream +
  apply. A first install is **never** `deploy(..., None, ...)`; if a `None`
  first-install ever reaches roxyd, roxyd **fail-closes with
  `MissingBootstrapMaterial`** (RFC-C §4), so a resolver that skipped `register`
  cannot silently install a module without a bootroot identity. **Failure
  compensation:** because `register` mints an identity **before** `deploy`
  applies, a first install is **not terminal until `deploy` completes** —
  review arms the `operation_attempt` `cleanup_state` with an owed `Deregister`
  of the same parts `(service_name, host, instance)` — from which the
  registrar re-derives the identity to tear down — **before** the mint (D2
  §4d). So if `deploy` **fails,
  times out, or is cancelled** after a successful `register`, review discharges
  that compensation and the minted identity **never orphans** (a resume
  re-drives the idempotent `register` if the operation continues instead of
  being abandoned).
- **[DECISION] The compensation is `remove` THEN `deregister`, never a bare
  `deregister`.** A `deploy` that **times out** or dies on a transport error is
  **not** evidence the install did not happen: roxyd may have verified,
  bootstrapped, applied and started the unit, with only the terminal `Done`
  lost. A bare `Deregister` on that outcome tears down the AppRole, policy and
  per-service KV of a module that is **running with a valid certificate** —
  the host-verify guard does not fire, since the host matches — so the UI keeps
  showing a healthy service until `bootroot-agent` fails to renew and it dies
  silently, days later, with nothing pointing at the cause. Driving `remove`
  first makes the compensation **correct under either outcome** and idempotent:
  if nothing was installed, `remove` is a no-op; if something was, it is torn
  down before its identity is. This is preferred over probing
  `node.package Status` before discharging, because the host is often
  unreachable precisely when the ambiguity arises — a probe would then leave
  the attempt non-terminal with the obligation still owed, converting a
  determinable case into an indefinite one.
- **`updateService(host, target, instance, buildSelector, onFailure)`** —
  update the named instance to a
  selected build (install=update); the identity already exists, so it calls
  **`deploy(host, target, instance, selector, None, onFailure)`** — **no**
  `register` (a stray `Some` on an existing identity is ignored, RFC-C §4).
  The `instance` is the number the UI read from the row it acted on (RFC-E §4),
  not typed by the operator; the resolver rejects one that does not exist.
- **`removeService(host, target, instance)`** — behind the same guard; drives
  **`remove(host, target, instance)`**
  then crash-safe `deregister` (D2 §4d). Confirmation is a UI concern (RFC-E).
- **[DECISION] Bind the target's package class to the mutation's guard tier —
  at the resolver, not by convention.** The three module mutations above
  (`installService`/`updateService`/`removeService`) MUST **reject any
  `target` that is not one of the five module package-ids**
  (`piglet`/`giganto`/`hog`/`reconverge`/`crusher`, §3 registry) with a typed
  error, and `updateCoreComponent` MUST reject any `component` not in the core
  set. Otherwise the weaker `SecurityAdministrator`+customer-scope guard on the
  module mutations would reach a **core** package-id (`review`/`aice-web-next`/
  `roxyd`) — a package-id is per-host-valid for `roxyd`, so
  `updateService(target="roxyd")` would drive a core self-update/downgrade that
  the design reserves for `SystemAdministrator` via `updateCoreComponent`. The
  class→guard binding is the authorization boundary; do not rely on callers
  passing the "right" mutation.
- **`updateCoreComponent(component, host, buildSelector, onFailure)`** —
  covers `review` + `aice-web-next` (singletons; host = their fixed host) and
  `roxyd` (**host-scoped** — selects the instance). Argument is
  **`(component, host)` uniformly**, keyed to the core-component registry (D1
  §4c). Accepts only `review`/`aice-web-next`/`roxyd`; `bootroot` and any
  module package-id are rejected (installer-managed / wrong class).
  **`HOLD` on a self-affecting core target is a UI-confirmed choice, not a
  rejected one.** For `review` and `aice-web-next`, `onFailure = HOLD` means a
  failed update stays in place — REView does not serve, or the operator has no
  UI at all — and the revert can then only be done on the host. That is a real
  hazard next to the uniform toggle it is presented as, but it is **not**
  rejected here: leaving a failed build in place for diagnosis is a legitimate
  operator choice, and refusing it just pushes the operator to do it by hand
  outside the product. The safeguard belongs where the human is — RFC-E §5
  requires an explicit confirmation naming the consequence for those two
  targets. No extra mutation argument is added for this: a caller that passes
  `HOLD` deliberately is making a deliberate choice, and a contract field whose
  only purpose is friction protects nobody. (`roxyd` is not in this carve-out —
  a failed roxyd update leaves the UI up, and the bootler supervisor, RFC-A §8,
  is its own defense **where it exists**; see the capability gate below, which
  is what makes that parenthetical true rather than assumed.)
- **[DECISION] `onFailure = ROLLBACK` is REJECTED for a host that does not
  advertise `rollback-supervisor`.** Automatic binary rollback for roxyd's own
  update depends on a **bootler-installed** supervisor unit (RFC-A §8), and a
  host onboarded by `roxyd join` has one only because the join installs it
  (RFC-B §7 step 1b) — a host provisioned before that, or one whose unit is
  masked, has none. roxyd advertises the tag in its capability set when the
  supervisor answers a heartbeat (RFC-C §6, RFC-B §8). Without this gate the
  default `ROLLBACK` (RFC-C §4) reaches such a host and is silently downgraded
  to `HOLD`: the operator believes rollback is armed for every future update
  and it never is, in a state indistinguishable from a healthy one until an
  update fails. So `installService` / `updateService` / `updateCoreComponent`
  **reject `ROLLBACK`** with a typed error naming the missing capability rather
  than coercing it, and the gate is enforced **here at the mutation boundary**,
  not only in the UI — a resumed operation or a non-UI caller reaches this path
  with the default already set, so a UI-only check would not hold.
- **`onboardHost(host)`** — issue a join token (review commands the registrar,
  D2 §4d); returns the one-time token/one-liner for the UI (RFC-E §6). The
  pending host + its expiry/cancel cleanup are review-side (D2 §4d).
- **`buildSelector`** input = one of `{ version: String }` **or**
  `{ commit: String }` (the GraphQL form of the trait's `BuildSelector`;
  exactly one field set — reject both/neither at the resolver). It is passed
  through the trait as-is and **resolved by review to a full `(version,
  commit)` build in either direction** (§3); the resolver does not itself look
  up the store. **`onFailure`** enum = `ROLLBACK` (default) | `HOLD`.

### 5b. Read types — inline version/lifecycle

- **Read types return one entry per installed instance, not per kind.** A
  node may hold several instances of one module (RFC-A §4), each a separate
  backend row (RFC-D1 §2), so the list resolvers return them all and each
  entry carries its **`instance`** number alongside the fields below. An
  install **in flight** has no row yet — review creates the row only on
  terminal success (RFC-D2 §4b) — so its card comes from the
  **non-terminal `operation_attempt`** surfaced below, not from a
  placeholder row; that is what keeps the config plane and the certificate
  lookup free of entries no peer will ever match. A
  resolver that collapses to one entry per `AgentKind` would hide every
  instance after the first.
- Extend the agent / external-service / node GraphQL types **and** add a
  core-component listing type with: `installedVersion`, `installedCommit`,
  `lifecycle` (enum mirroring D1: `NOT_INSTALLED` / `INSTALLING` / `RUNNING` /
  `STOPPED` / `FAILED` / `REMOVING` / **`UNKNOWN`** — the last is not
  optional: D1 stores `Unknown` as the fallback for a value this build does
  not recognize (RFC-D1 §4a), and omitting it from the GraphQL enum leaves a
  stored state with no representation, which the resolver can only handle by
  erroring or by silently substituting another state), and
  **`updateAvailable: Boolean`**
  (computed per build). **No `desiredVersion`.**
- **Surface `boundAddrs`** on the external-service type — the `(config-key,
  host:port)` pairs the instance **is currently bound to**, as reported by
  roxyd on **every** status report and recorded by review (RFC-D1 §4b,
  RFC-C §4). Because it is refreshed rather than captured at install, it
  stays correct after an operator changes a port through the config plane.
  It is empty for the four agent
  modules, which bind nothing. Without it the UI cannot tell where a Giganto
  instance is listening and would keep offering the package default to an
  instance roxyd put somewhere else (RFC-E §4). It is **read-only** — the
  operator changes ports through the config plane, not by writing this.
- These are **inline** on the existing list/status read path (extend the
  `node/status.rs` resolvers), not a separate rollup — a future fleet view is
  then frontend-only (RFC-E §8).
- Also surface the persisted **agent version** review now keeps (D2 §4c) here
  — this is the "GraphQL API to retrieve agent's version" the code comment at
  review `agent.rs:801` anticipated.
- **[DECISION] Surface the operation record — RFC-E's progress and reconnect
  design reads it, and nothing else exposes it.** The inline fields above
  cannot answer "is this mid-update, and did it succeed, fail, or roll back?":
  a rolled-back update and an update that never ran both end at the old version
  with `lifecycle = RUNNING`. RFC-E §5 makes the **server-side operation
  record** the source of truth for exactly that question, RFC-E §6 shows a
  pending onboarding's expiry, and RFC-E §10 polls phase transitions — none of
  which is reachable today. So add:
  - **`operationAttempt(id)`** — `action`, `phase`, `outcome`,
    `resolvedVersion`, `resolvedCommit`, `startedAt`, `expiresAt`, and
    **`cleanupOwed`** with a human-readable reason when compensation is still
    owed (D2 §4d). `cleanupOwed` is what makes a blocked re-install or
    re-onboard legible instead of a mysterious rejection.
  - the **latest attempt per `(host, target, instance)` inline** on the same
    read path as
    the fields above — **not** a separate history query. Keying on
    `(host, target)` would collapse several instances of one module onto a
    single attempt, so an instance's card could show a sibling's outcome. This
    matches the
    inline-fields decision (RFC-E §8) and keeps a future fleet view
    frontend-only; a full attempt history is post-v1.
  - **the five mutations return the operation id** (`idempotencyKey`), so the
    UI can poll a specific operation rather than guessing which one it started.
  (An operator-facing **force-discharge** of an owed compensation is
  deliberately **post-v1**: the only way an obligation becomes permanently
  undischargeable is the registrar never returning, which means bootroot is
  gone and the PKI is being rebuilt anyway. v1 makes the state *visible*; a
  destructive admin override waits for a real case.)

### 5c. Signed-package upload — streaming axum route

- Add a **streaming binary axum route** (e.g. `POST /api/module/upload`),
  reusing the `src/archive.rs` Router/route + auth wiring (`:172`) but **not**
  its buffering. It **must consume the request body as a stream** — take
  `axum::body::Body` and drive `Body::into_data_stream()` /
  `BodyDataStream` (or an equivalent chunked reader), forwarding chunks to
  review's store receiver (D2 §4a) as they arrive. It **must not** call
  `axum::body::to_bytes(_, usize::MAX)` or otherwise load the whole `.pkg`
  into memory (signed packages can be large; the store receiver verifies
  signature + hashes + manifest-completeness on the streamed bytes before
  accepting). Returns the accepted build id `(package-id, version, commit)` or
  a typed verification error.
- **[DECISION] The route enforces a configured maximum body size while
  streaming — sized for the largest legitimate package, not a guessed number —
  and the role comes from the same source as the GraphQL guards.**
  A core component may ship a **container image** (RFC-A §4 lets each package
  declare its `ArtifactKind`), so the cap must accommodate those, not just
  module binaries — a cap sized for module binaries alone would reject the
  largest builds the product legitimately ships. (The host-side ingest path,
  RFC-D2 §4a, does not traverse this route: that route requires a client
  certificate carrying an admin identity, which is why the ingest goes through
  review's admin channel instead.)
  Streaming without a cap means an authenticated uploader can write unbounded
  bytes into `pending/`, which lives under the same volume as REView's data dir
  — filling the control plane's disk (D2 §4a pairs this with a `pending/`
  sweep). And because §5c's tier check needs "the caller's authorized package
  class(es) **from its role**", the route MUST resolve the caller's role
  through the **same** source as the GraphQL `RoleGuard`; reusing
  `archive.rs`'s Router/auth wiring does not by itself establish that it yields
  a GraphQL `Role`, so the impl states the extraction path explicitly rather
  than assuming it.
- **The upload route carries the same class→tier authz binding as the mutations
  (§5a).** It is not enough to be "auth-guarded": the accepted `.pkg`'s
  package-id determines the required role. Uploading a **core** package-id
  (`review` / `aice-web-next` / `roxyd`) requires **`SystemAdministrator`**;
  a **module** package-id requires the module tier (`SecurityAdministrator`).
  Otherwise a `SecurityAdministrator` — confined to module actions — could
  `POST` a validly-signed **core** build into the shared store, where it becomes
  that component's `latest_build` and lights an `updateAvailable` badge a
  SystemAdministrator may then apply. (The release signature bounds this to
  *authentic* builds, so it is a tier-model leak, not code-exec — but the tier
  boundary must hold at the upload route too.) **The class is taken from the
  `.pkg`'s signed manifest `component` (confirmed after verification), never
  from a client-supplied field** — so it cannot be spoofed (a
  `SecurityAdministrator` cannot forge a core build's release signature, and an
  authentic core `.pkg` reveals `component ∈ {review, aice-web-next, roxyd}` and
  is rejected).
- **[DECISION] Authorization precedes the store commit — it never follows it.**
  The class is known only **after** the receiver verifies the signature (D2 §4a),
  and the receiver commits by renaming `pending/` → `accepted/` and updating
  `index.json`/`latest_build`. If the tier check ran only in review-web after
  the receiver had already committed, a `SecurityAdministrator` core upload
  would have crossed the tier boundary before rejection. So the tier check
  **gates that commit**: review-web passes the **caller's authorized package
  class(es)** — from its role (`SystemAdministrator` ⇒ {core, module},
  `SecurityAdministrator` ⇒ {module}) — with the upload, and the receiver
  **refuses to rename into `accepted/` or touch `index.json`/`latest_build`**
  unless the verified `component`'s class is in that set, discarding the
  `pending/` file otherwise (D2 §4a). A rejected upload therefore leaves the
  store and `latest_build` **unchanged**. **Acceptance:** a
  `SecurityAdministrator` streaming a validly-signed **core** build is rejected
  **and** `accepted/`, `index.json`, and `latest_build` are unchanged.
  **Scope of the guarantee — it is about this ROUTE, not about the bytes on
  disk.** The store is writable by REView's service account, and every
  component on that host except roxyd shares it (RFC-A §4, RFC-B §4), so a
  compromised module on the REView host can edit `accepted/`/`index.json`
  directly without traversing any route. This criterion asserts that the
  upload path cannot be used to cross a tier — not that the store is
  protected from a same-uid compromise, which it is not. What still holds in
  that case is the apply-time check: roxyd verifies signature, `key_id` and
  the withdrawn list against its root-owned trust set (RFC-A §5), so the
  reachable outcome is an **authentic older build**, not attacker-chosen
  code.
- Fronted by the aice-web-next BFF (RFC-E §7); air-gapped USB→browser→BFF→here
  works.
- **[DECISION] A SEPARATE trust-plane ingress route — not the module store.**
  Add a second streamed route (e.g. `POST /api/trust/generation`) that hands a
  signed release-signing trust-set generation to review's trust manager
  (RFC-D2 §4a). It exists because there is otherwise **no runtime path** for a
  new generation to reach REView — bootler is gone at runtime, `trust` is
  deliberately outside the RFC-A §4 UI package-id registry so it cannot ride
  the upload route above, and no mutation in §5a carries one; without it,
  runtime key revocation and build withdrawal are undeliverable. Constraints:
  **`SystemAdministrator` only** (it is the highest-privilege channel in the
  system); it goes to the **trust manager, never the store** — no `pending/`,
  no `accepted/` path, no `index.json` entry, never servable as a build; and it
  is **the only such ingress** (no watched directory or second endpoint —
  a second way in is a second thing to secure for no gain). review performs
  verify-then-activate and the strictly-greater-`epoch` check; this route does
  not interpret the generation. The action is audited (RFC-E §9).
- **Regenerate the SDL** after the type/mutation changes.

## 6. Acceptance criteria

- **`ROLLBACK` is refused where it cannot be honored.** A test asserts a
  mutation carrying `onFailure = ROLLBACK` against a host whose capability set
  lacks `rollback-supervisor` is **rejected with a typed error**, not coerced
  to `HOLD`, and that the same request succeeds once the tag is present. The
  gate lives at the mutation boundary, so the test drives it without the UI.
- `PackageDeployer` compiles as a sibling trait in `backend.rs`; review (D2)
  implements it; resolvers obtain it from context like `AgentManager`.
- **Every host-scoped mutation authorizes before any backend call**, matching
  the existing `control.rs` chain: `installService`/`updateService`/
  `removeService` apply a `RoleGuard` (`SystemAdministrator` or
  `SecurityAdministrator`) **and** `customer_access::check_hostname_access(ctx,
  &host)`; `updateCoreComponent`/`onboardHost` require `SystemAdministrator`
  (control-plane / new-host infra, no customer scoping). A scoped user is
  rejected on a host outside their customer, and a non-admin on core/onboarding
  actions.
- **Target package-class is bound to the guard tier at the resolver:**
  `installService`/`updateService`/`removeService` reject any `target` not in
  the five module package-ids; `updateCoreComponent` rejects any `component`
  not in `{review, aice-web-next, roxyd}`. A `SecurityAdministrator` calling
  `updateService(target="roxyd"|"review"|"aice-web-next")` is **rejected**
  (cannot reach a core package-id through the weaker module guard); `bootroot`
  is rejected everywhere.
- **First-install failure leaves no orphan identity:** on a first install where
  `register` **succeeds** but `deploy` **errors** (fails / times out / is
  cancelled), the compensation armed before the mint is discharged
  (D2 §4d), so the minted identity — derived by the registrar from the parts,
  not a review-composed name — is torn down — a
  test drives `register ok + deploy error` and asserts the identity is
  deregistered, not left orphaned. **The compensation runs `remove` before
  `deregister`:** a second test drives `register ok + deploy TIMES OUT while
  the install actually succeeded on the host` and asserts the module is torn
  down (unit stopped, artifacts removed) **and then** deregistered — never a
  running module stripped of its identity.
- **Instances are addressed, not allocated:** every mutation carries the
  `instance` (`Some(1)` for a module, `None` for a core component);
  `updateService` / `removeService` reject a value that does not exist; a
  core component rejects any `instance`; and single-flight is keyed
  `(host, target, instance)`, which — because v1 does not allocate — is
  fully determined by the request, so a test asserts a **double-submitted**
  `installService` is coalesced without any client-supplied key. A test
  asserts a second `installService` for a `(component, host)` that already
  has a row is **rejected** with a typed error. Read types return **one
  entry per instance**, each carrying its number, so the shape does not
  change when v2 allows more than one.
- Each mutation is an immediate action returning success/failure (no draft
  state); `buildSelector` accepts `version` **xor** `commit` (both/neither
  rejected) and is passed through the trait as `BuildSelector`, with **review
  resolving it to a full `(version, commit)` build in either direction** and a
  non-matching selector returning a typed error; `onFailure` defaults to
  `ROLLBACK`; `updateCoreComponent` takes `(component, host)`, accepts
  `review`/`aice-web-next`/`roxyd`, and **rejects `bootroot`**.
- The existing config draft→Apply mutations are **unchanged**; version/install
  do not ride the draft.
- Read types expose `installedVersion` + `installedCommit` + `lifecycle` +
  `updateAvailable` **inline** on the current list/status queries; no
  `desiredVersion`; `updateAvailable` reflects the per-build comparison
  (same-version hotfix shows true).
- The upload route **consumes the body as a stream** (`Body::into_data_stream`
  / `BodyDataStream`, forwarding chunks) and **never** calls
  `to_bytes(_, usize::MAX)` — verified by an upload larger than any sane
  in-memory buffer completing without loading the whole `.pkg` into memory; it
  is auth-guarded **with the same class→tier binding as the mutations**
  (uploading a core package-id requires `SystemAdministrator`; a module
  package-id requires the module tier), relays to the store receiver, and
  returns the build id or a typed error; **no base64-in-GraphQL** path exists.
  A `SecurityAdministrator` uploading a core-component build is **rejected**.
- The **trust-plane ingress route** accepts a signed generation only for
  `SystemAdministrator`, hands it to review's trust manager, and **never**
  writes to the module store: a test asserts that after posting a generation,
  `pending/`, `accepted/`, `index.json`, and `latest_build` are all unchanged,
  and that a `SecurityAdministrator` is rejected.
- SDL regenerated and committed; schema snapshot tests pass.

## 7. Issue decomposition (AgentCoop — aicers/review-web)

Self-contained issues; dependency order within this repo:

1. **`PackageDeployer` trait definition** (§4) — the trait + associated
   types (`BuildSelector` [version XOR commit], `BootstrapMaterial`,
   `FailurePolicy`, `PackageState`, `BuildId`, `DeliveryMode`,
   **`DeployOutcome` [`Applied` | `Accepted`]**) in
   `backend.rs`. **Land first** — it is the compile precedent for review
   D2 §4c.
2. **Read-type extension** (§5b) — inline `installedVersion` /
   `installedCommit` / `lifecycle` / `updateAvailable` + agent version on the
   node/agent/external-service + core-component read path; SDL regen. Depends
   on D1's types.
2b. **`rollback-supervisor` capability gate** (§5a) — reject
   `onFailure = ROLLBACK` at the mutation boundary when the target host's
   capability set lacks the tag, with a typed error rather than coercion to
   `HOLD` (RFC-A §8, RFC-B §8, RFC-C §6). Small, but it is what makes §5a's
   "the bootler supervisor is its own defense" true instead of assumed.
   Depends on 3.
3. **Immediate-action mutations** (§5a) — the five mutations + `buildSelector`
   / `onFailure` inputs, wired to `PackageDeployer`, **each with the full
   `control.rs` auth chain** (RoleGuard + `check_hostname_access` for module
   mutations; `SystemAdministrator` for `updateCoreComponent`/`onboardHost`)
   **and the target→package-class binding** (module mutations reject non-module
   targets; `updateCoreComponent` rejects non-core), so the guard tier cannot
   be bypassed by target choice; SDL regen. Depends on 1.
4. **Upload axum route** (§5c) — a **streamed-body** `POST` route reusing the
   archive.rs Router/auth wiring but **not** its `to_bytes` buffering
   (`Body::into_data_stream`/`BodyDataStream`, forwarding chunks), relaying to
   the store receiver; typed errors. Depends on review's store receiver
   (D2 §4a) for the end-to-end path, but the route itself can be built +
   unit-tested against a stub receiver.
5. **Trust-plane ingress route** (§5c) — a `SystemAdministrator`-only streamed
   `POST` route handing a signed trust-set generation to review's trust
   manager, bypassing the store entirely (no `pending/`/`accepted/`/
   `index.json` writes), with the store-untouched and role-rejection tests.
   Independent of 1–4; depends on review's trust manager (D2 §4a) end-to-end.

Cross-repo: issue 1 (trait def) should land **before** review D2's trait-impl
issue; the mutations/route are exercised end-to-end once review (D2) is wired.

## 8. Non-goals

- **No `desiredVersion` / reconcile** — immediate action only.
- **No** store, verification, roxyd-control, or registrar **logic** — those are
  review (D2); review-web defines the trait + GraphQL/route surface and calls
  into review.
- **No schema/type persistence** — that is review-database (D1).
- **bootroot update** — rejected at the mutation boundary (installer-managed).
