//! The Clumit Endpoint (`senta`) read queries.
//!
//! Every query reads the endpoint tables `REview` writes into review-database
//! and nothing else: none writes a table or calls the
//! [`EndpointManager`](crate::backend::EndpointManager).
//!
//! A customer-bound result is limited to the customers in the caller's scope
//! (see [`users_customers`]). An endpoint's customer is the customer id of its
//! endpoint row, so a scoped caller naming an endpoint without one, or of a
//! customer outside the scope, is refused with `Forbidden`, as is one naming a
//! customer outside the scope. `endpointActiveListStatus` and
//! `endpointTelemetryEntries` mix customers and are for a System
//! Administrator only.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use async_graphql::{
    Context, Enum, ID, Object, Result, SimpleObject, StringNumber,
    connection::{Connection, Edge, EmptyFields, OpaqueCursor},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use review_database::{self as database, Iterable, Store, event::Direction};
use uuid::Uuid;

use super::{parse_customer_id, parse_hash, parse_uuid};
use crate::graphql::customer_access::{is_member, users_customers};
use crate::graphql::{Role, RoleGuard, get_store, query_with_constraints, timestamp::Timestamp};

/// The error a scoped caller gets for an endpoint or a customer outside its
/// scope.
const FORBIDDEN: &str = "Forbidden";

/// The state of an enrollment attempt.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
enum SentaEndpointEnrollmentState {
    /// The attempt waits for a decision.
    Pending,
    /// The attempt was approved.
    Approved,
    /// The attempt was denied.
    Denied,
}

/// An enrollment attempt of an endpoint.
#[derive(Debug, SimpleObject)]
struct SentaEndpointEnrollmentAttempt {
    /// The SHA-256 hash of the endpoint's subject public key info, as 64
    /// lowercase hexadecimal characters.
    spki_hash: String,
    /// The attempt id.
    attempt_id: ID,
    /// The customer `REview` resolved for the attempt.
    customer_id: ID,
    /// The enrollment request, as standard padded base64.
    request: String,
    /// The address the request came from.
    source_address: String,
    /// When the request was received.
    received_at: Timestamp,
    /// The state of the attempt.
    state: SentaEndpointEnrollmentState,
    /// The reason of a pending or denied attempt; `null` when approved.
    reason: Option<String>,
    /// The enrollment-result JWS of an approved attempt; `null` otherwise.
    enrollment_result: Option<String>,
}

impl SentaEndpointEnrollmentState {
    fn of(result: &database::SentaEndpointEnrollmentResult) -> Self {
        match result {
            database::SentaEndpointEnrollmentResult::Pending { .. } => Self::Pending,
            database::SentaEndpointEnrollmentResult::Approved { .. } => Self::Approved,
            database::SentaEndpointEnrollmentResult::Denied { .. } => Self::Denied,
        }
    }
}

impl SentaEndpointEnrollmentAttempt {
    fn new(attempt: database::SentaEndpointEnrollmentAttempt) -> Result<Self> {
        let (state, reason, enrollment_result) = match attempt.result {
            database::SentaEndpointEnrollmentResult::Pending { reason } => {
                (SentaEndpointEnrollmentState::Pending, Some(reason), None)
            }
            database::SentaEndpointEnrollmentResult::Approved { result } => {
                (SentaEndpointEnrollmentState::Approved, None, Some(result))
            }
            database::SentaEndpointEnrollmentResult::Denied { reason } => {
                (SentaEndpointEnrollmentState::Denied, Some(reason), None)
            }
        };
        Ok(Self {
            spki_hash: hex(&attempt.spki_hash),
            attempt_id: uuid_id(attempt.attempt_id),
            customer_id: ID(attempt.customer_id.to_string()),
            request: STANDARD.encode(&attempt.request),
            source_address: attempt.source_address.to_string(),
            received_at: timestamp(attempt.received_at)?,
            state,
            reason,
            enrollment_result,
        })
    }
}

/// A Giganto node, identified as its service row identifies it.
#[derive(Debug, SimpleObject)]
struct SentaEndpointNode {
    /// The host name of the node.
    hostname: String,
    /// The instance number of Giganto on the host.
    instance: StringNumber<u32>,
}

impl From<database::SentaEndpointGigantoNode> for SentaEndpointNode {
    fn from(node: database::SentaEndpointGigantoNode) -> Self {
        Self {
            hostname: node.host,
            instance: StringNumber(node.instance),
        }
    }
}

/// The slot of an address document: its recovery epoch and version.
#[derive(Debug, SimpleObject)]
struct SentaEndpointAddressDocumentSlot {
    /// The recovery epoch of the document.
    epoch: StringNumber<u64>,
    /// The version of the document.
    version: StringNumber<u64>,
}

/// The last status report of an endpoint.
#[derive(Debug, SimpleObject)]
struct SentaEndpointStatusReport {
    /// The report, as `REview` stored it.
    report: String,
    /// When the report was received.
    received_at: Timestamp,
    /// The slot of the address document the endpoint reported; `null` if it
    /// reported none.
    address_document_slot: Option<SentaEndpointAddressDocumentSlot>,
}

/// When a Giganto node last received data from an endpoint.
#[derive(Debug, SimpleObject)]
struct SentaEndpointLastReceived {
    /// The node.
    node: SentaEndpointNode,
    /// When the node last received data from the endpoint.
    last_received_at: Timestamp,
    /// When `REview` fetched this time from the node.
    fetched_at: Timestamp,
}

/// An enrolled endpoint.
#[derive(Debug, SimpleObject)]
struct SentaEndpoint {
    /// The endpoint id.
    endpoint_id: ID,
    /// The customer the endpoint belongs to.
    customer_id: ID,
    /// The customer endpoint id of the endpoint's customer.
    customer_endpoint_id: ID,
    /// The SHA-256 hash of the endpoint's subject public key info, as 64
    /// lowercase hexadecimal characters.
    spki_hash: String,
    /// The standing of the endpoint, as `REview` stored it.
    standing: String,
    /// The host name the endpoint reported.
    host_name: String,
    /// The operating system the endpoint reported.
    os: String,
    /// The `senta` version the endpoint reported.
    senta_version: String,
    /// The bundle the endpoint reported.
    bundle: String,
    /// When the endpoint was enrolled.
    enrolled_at: Timestamp,
    /// When the endpoint last connected.
    last_connected_at: Timestamp,
    /// Whether the endpoint is connected now.
    connected: bool,
    /// The last status report of the endpoint; `null` if there is none.
    status_report: Option<SentaEndpointStatusReport>,
    /// When each Giganto node last received data from the endpoint, in
    /// node order.
    last_received: Vec<SentaEndpointLastReceived>,
}

impl SentaEndpoint {
    fn load(store: &Store, endpoint: database::SentaEndpoint) -> Result<Self> {
        let status_report = store
            .senta_endpoint_status_report_map()
            .get(endpoint.endpoint_id)?
            .map(|report| -> Result<_> {
                Ok(SentaEndpointStatusReport {
                    report: report.report,
                    received_at: timestamp(report.received_at)?,
                    address_document_slot: report.address_document_slot.map(|(epoch, version)| {
                        SentaEndpointAddressDocumentSlot {
                            epoch: StringNumber(epoch),
                            version: StringNumber(version),
                        }
                    }),
                })
            })
            .transpose()?;
        let last_received = store
            .senta_endpoint_giganto_last_received_map()
            .iter_endpoint(endpoint.endpoint_id)
            .map(|row| -> Result<_> {
                let row = row?;
                Ok(SentaEndpointLastReceived {
                    node: row.key.node.into(),
                    last_received_at: timestamp(row.last_received_at)?,
                    fetched_at: timestamp(row.fetched_at)?,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            endpoint_id: uuid_id(endpoint.endpoint_id),
            customer_id: ID(endpoint.customer_id.to_string()),
            customer_endpoint_id: uuid_id(endpoint.customer_endpoint_id),
            spki_hash: hex(&endpoint.spki_hash),
            standing: endpoint.standing,
            host_name: endpoint.host_name,
            os: endpoint.os,
            senta_version: endpoint.senta_version,
            bundle: endpoint.bundle,
            enrolled_at: timestamp(endpoint.enrolled_at)?,
            last_connected_at: timestamp(endpoint.last_connected_at)?,
            connected: endpoint.connected,
            status_report,
            last_received,
        })
    }
}

/// The number of endpoints the filters of `endpoints` select.
struct SentaEndpointTotalCount {
    count: usize,
}

#[Object]
impl SentaEndpointTotalCount {
    /// The total number of edges.
    async fn total_count(&self) -> StringNumber<usize> {
        StringNumber(self.count)
    }
}

/// An entry of the active list.
#[derive(Debug, SimpleObject)]
struct SentaEndpointActiveListEntry {
    /// The endpoint the entry names.
    endpoint_id: ID,
    /// The SHA-256 hash of the endpoint's subject public key info, as 64
    /// lowercase hexadecimal characters.
    spki_hash: String,
    /// The customer endpoint id of the endpoint's customer.
    customer_endpoint_id: ID,
    /// The state of the entry, as `REview` stored it.
    state: String,
}

/// How far the active list has reached one Giganto node.
#[derive(Debug, SimpleObject)]
struct SentaEndpointNodeActiveListStatus {
    /// The node.
    node: SentaEndpointNode,
    /// The version of the active list the node applied; `null` if it has
    /// applied none.
    applied_version: Option<StringNumber<u64>>,
    /// When `REview` last confirmed the node's entry; `null` if it never
    /// did.
    last_confirmed_at: Option<Timestamp>,
    /// Whether the node's applied version is absent or differs from
    /// `REview`'s version; `false` when no list is stored.
    lagging: bool,
}

/// The active list `REview` applied, and how far it has reached the Giganto
/// nodes.
#[derive(Debug, SimpleObject)]
struct SentaEndpointActiveListStatus {
    /// The version of `REview`'s active list; `null` when no list is stored.
    version: Option<StringNumber<u64>>,
    /// The entries of `REview`'s active list, in the order they are stored;
    /// empty when no list is stored.
    entries: Vec<SentaEndpointActiveListEntry>,
    /// The state of each Giganto node's endpoint entry, in node order.
    nodes: Vec<SentaEndpointNodeActiveListStatus>,
    /// The version `REview` and every Giganto node have applied: the minimum
    /// of the nodes' applied versions and `REview`'s version, or `REview`'s
    /// version when there is no node. `null` when no list is stored or any
    /// node has applied none.
    applied_everywhere: Option<StringNumber<u64>>,
}

/// The last result an endpoint reported for a document.
#[derive(Debug, SimpleObject)]
struct SentaEndpointReportedDocumentResult {
    /// The type of the document; empty for a reply that names no document.
    typ: String,
    /// The target of the document; empty for a reply that names no document.
    target: String,
    /// The version of the document; `null` if the reply gave none.
    version: Option<StringNumber<u64>>,
    /// The result, as `REview` stored it.
    result: String,
    /// When the result was reported.
    at: Timestamp,
}

/// The state of a command sent to an endpoint.
#[derive(Clone, Copy, Debug, Enum, Eq, PartialEq)]
enum SentaEndpointCommandState {
    /// The command waits to be sent.
    Pending,
    /// The command was sent.
    Sent,
    /// The endpoint returned the command's result.
    Result,
    /// The command expired.
    Expired,
}

impl From<database::SentaEndpointCommandState> for SentaEndpointCommandState {
    fn from(state: database::SentaEndpointCommandState) -> Self {
        match state {
            database::SentaEndpointCommandState::Pending => Self::Pending,
            database::SentaEndpointCommandState::Sent => Self::Sent,
            database::SentaEndpointCommandState::Result => Self::Result,
            database::SentaEndpointCommandState::Expired => Self::Expired,
        }
    }
}

/// A command for an endpoint.
#[derive(Debug, SimpleObject)]
struct SentaEndpointCommand {
    /// The command id.
    command_id: ID,
    /// The sequence number of the command.
    sequence: StringNumber<u64>,
    /// The command JWS.
    command: String,
    /// When the command expires.
    expires_at: Timestamp,
    /// The state of the command.
    state: SentaEndpointCommandState,
    /// The result the endpoint returned, as standard padded base64; `null`
    /// if there is none.
    result: Option<String>,
}

/// A `DuplicateKey` event of an endpoint.
#[derive(Debug, SimpleObject)]
struct SentaEndpointDuplicateKeyEvent {
    /// When the event happened.
    at: Timestamp,
    /// The Giganto node the event was fetched from; `null` when `REview`
    /// observed it itself.
    node: Option<SentaEndpointNode>,
    /// The sequence number of the event at its source.
    sequence: StringNumber<u64>,
    /// The SHA-256 hash of the subject public key info the event names, as
    /// 64 lowercase hexadecimal characters.
    spki_hash: String,
    /// The addresses the key was seen at.
    addresses: Vec<String>,
    /// How many times the key was replaced.
    replacement_count: StringNumber<u64>,
    /// When `REview` fetched the event from the node; `null` when `REview`
    /// observed it itself.
    fetched_at: Option<Timestamp>,
}

/// A loss record a Giganto node reported for an endpoint.
#[derive(Debug, SimpleObject)]
struct SentaEndpointGigantoLoss {
    /// When the node received the loss record.
    received_at: Timestamp,
    /// The node.
    node: SentaEndpointNode,
    /// The stream the loss is in.
    stream_id: ID,
    /// The first sequence number of the lost range.
    range_from: StringNumber<u64>,
    /// The last sequence number of the lost range.
    range_to: StringNumber<u64>,
    /// The reason code of the loss, as `REview` stored it.
    reason: String,
    /// The detail of the reason, as `REview` stored it.
    detail: String,
    /// When `REview` fetched the record from the node.
    fetched_at: Timestamp,
}

/// The `DuplicateKey` events and the Giganto loss records of an endpoint.
#[derive(Debug, SimpleObject)]
struct SentaEndpointEvents {
    /// The `DuplicateKey` events, in key order: by time, then source, then
    /// sequence.
    duplicate_keys: Vec<SentaEndpointDuplicateKeyEvent>,
    /// The loss records, in key order: by time received, then node, stream
    /// and range.
    losses: Vec<SentaEndpointGigantoLoss>,
}

/// The endpoint entry of a Giganto node.
#[derive(Debug, SimpleObject)]
struct SentaEndpointTelemetryEntry {
    /// The node.
    node: SentaEndpointNode,
    /// The id of the node's endpoint entry.
    entry_id: ID,
    /// The server name of the entry.
    server_name: String,
    /// The host of the entry.
    host: String,
}

/// How many of a customer's endpoints have adopted a trust root.
#[derive(Debug, SimpleObject)]
struct SentaEndpointTrustRootAdoption {
    /// The customer.
    customer_id: ID,
    /// The number of the customer's endpoints whose last status report names
    /// an address document of the customer that lists the root.
    adopted: StringNumber<usize>,
    /// The number of the customer's endpoints.
    total: StringNumber<usize>,
}

/// An unenroll request of an endpoint.
#[derive(Debug, SimpleObject)]
struct SentaEndpointUnenrollRequest {
    /// The endpoint that asked to be unenrolled.
    endpoint_id: ID,
    /// The customer of the endpoint; `null` if the endpoint has no endpoint
    /// row.
    customer_id: Option<ID>,
    /// When the request was received.
    received_at: Timestamp,
}

#[derive(Default)]
pub(in crate::graphql) struct SentaEndpointQuery;

#[Object]
impl SentaEndpointQuery {
    /// Lists the enrollment attempts in key order, by SPKI hash and then
    /// attempt id, optionally only those in `state` or of `customerId`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn endpoint_enrollment_attempts(
        &self,
        ctx: &Context<'_>,
        state: Option<SentaEndpointEnrollmentState>,
        customer_id: Option<ID>,
    ) -> Result<Vec<SentaEndpointEnrollmentAttempt>> {
        let scope = CustomerScope::new(ctx, customer_id.as_ref())?;
        let store = get_store(ctx)?;
        let table = store.senta_endpoint_enrollment_attempt_map();
        let mut attempts = Vec::new();
        for attempt in table.iter(Direction::Forward, None) {
            let attempt = attempt?;
            if scope.includes(attempt.customer_id)
                && state
                    .is_none_or(|state| state == SentaEndpointEnrollmentState::of(&attempt.result))
            {
                attempts.push(SentaEndpointEnrollmentAttempt::new(attempt)?);
            }
        }
        Ok(attempts)
    }

    /// Lists the enrolled endpoints in endpoint id order, optionally only
    /// those of `customerId`, with the standing `standing` (an exact match of
    /// the stored text), or whose connection state is `connected`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    #[allow(clippy::too_many_arguments)] // The three filters and the four connection arguments.
    async fn endpoints(
        &self,
        ctx: &Context<'_>,
        customer_id: Option<ID>,
        standing: Option<String>,
        connected: Option<bool>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> Result<
        Connection<OpaqueCursor<Vec<u8>>, SentaEndpoint, SentaEndpointTotalCount, EmptyFields>,
    > {
        let scope = CustomerScope::new(ctx, customer_id.as_ref())?;
        let filter = EndpointFilter {
            scope,
            standing,
            connected,
        };
        query_with_constraints(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                load_endpoints(ctx, &filter, after.as_ref(), before.as_ref(), first, last)
            },
        )
        .await
    }

    /// Returns `REview`'s active list and how far it has reached each Giganto
    /// node.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn endpoint_active_list_status(
        &self,
        ctx: &Context<'_>,
    ) -> Result<SentaEndpointActiveListStatus> {
        let store = get_store(ctx)?;
        let list = store.senta_endpoint_active_list_map().get()?;
        let entries = store
            .senta_endpoint_giganto_entry_map()
            .iter()
            .collect::<anyhow::Result<Vec<_>>>()?;
        let version = list.as_ref().map(|list| list.version);
        let applied_everywhere =
            applied_everywhere(version, entries.iter().map(|entry| entry.applied_version));
        let nodes = entries
            .into_iter()
            .map(|entry| -> Result<_> {
                Ok(SentaEndpointNodeActiveListStatus {
                    lagging: version.is_some_and(|version| entry.applied_version != Some(version)),
                    applied_version: entry.applied_version.map(StringNumber),
                    last_confirmed_at: entry.last_confirmed_at.map(timestamp).transpose()?,
                    node: entry.node.into(),
                })
            })
            .collect::<Result<_>>()?;
        let entries = list
            .map_or_default(|list| list.entries)
            .into_iter()
            .map(|entry| SentaEndpointActiveListEntry {
                endpoint_id: uuid_id(entry.endpoint_id),
                spki_hash: hex(&entry.spki_hash),
                customer_endpoint_id: uuid_id(entry.customer_endpoint_id),
                state: entry.state,
            })
            .collect();
        Ok(SentaEndpointActiveListStatus {
            version: version.map(StringNumber),
            entries,
            nodes,
            applied_everywhere: applied_everywhere.map(StringNumber),
        })
    }

    /// Lists the last document results of `endpointId` in key order, by
    /// document type and then target.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn endpoint_document_results(
        &self,
        ctx: &Context<'_>,
        endpoint_id: ID,
    ) -> Result<Vec<SentaEndpointReportedDocumentResult>> {
        let endpoint_id = parse_uuid("endpointId", &endpoint_id)?;
        let scope = users_customers(ctx)?;
        let store = get_store(ctx)?;
        check_endpoint_scope(&store, scope.as_deref(), endpoint_id)?;
        store
            .senta_endpoint_document_result_map()
            .iter_endpoint(endpoint_id)
            .map(|result| -> Result<_> {
                let result = result?;
                Ok(SentaEndpointReportedDocumentResult {
                    typ: result.key.typ,
                    target: result.key.target,
                    version: result.version.map(StringNumber),
                    result: result.result,
                    at: timestamp(result.at)?,
                })
            })
            .collect()
    }

    /// Lists the commands of `endpointId` in sequence order.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn endpoint_commands(
        &self,
        ctx: &Context<'_>,
        endpoint_id: ID,
    ) -> Result<Vec<SentaEndpointCommand>> {
        let endpoint_id = parse_uuid("endpointId", &endpoint_id)?;
        let scope = users_customers(ctx)?;
        let store = get_store(ctx)?;
        check_endpoint_scope(&store, scope.as_deref(), endpoint_id)?;
        let mut commands = store
            .senta_endpoint_command_map()
            .of_endpoint(endpoint_id)?;
        commands.sort_unstable_by_key(|command| (command.sequence, command.command_id));
        commands
            .into_iter()
            .map(|command| -> Result<_> {
                Ok(SentaEndpointCommand {
                    command_id: uuid_id(command.command_id),
                    sequence: StringNumber(command.sequence),
                    command: command.jws,
                    expires_at: timestamp(command.expires_at)?,
                    state: command.state.into(),
                    result: command.result.map(|result| STANDARD.encode(result)),
                })
            })
            .collect()
    }

    /// Lists the `DuplicateKey` events and the Giganto loss records of
    /// `endpointId`, optionally only the events at or after `since` and the
    /// loss records received at or after it.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn endpoint_events(
        &self,
        ctx: &Context<'_>,
        endpoint_id: ID,
        since: Option<Timestamp>,
    ) -> Result<SentaEndpointEvents> {
        let endpoint_id = parse_uuid("endpointId", &endpoint_id)?;
        let since = since.map(|since| since.as_nanosecond());
        let kept = |at: i64| since.is_none_or(|since| i128::from(at) >= since);
        let scope = users_customers(ctx)?;
        let store = get_store(ctx)?;
        check_endpoint_scope(&store, scope.as_deref(), endpoint_id)?;
        let mut duplicate_keys = Vec::new();
        for event in store.senta_endpoint_event_map().iter_endpoint(endpoint_id) {
            let event = event?;
            if !kept(event.key.at) {
                continue;
            }
            let node = match event.key.source {
                database::SentaEndpointEventSource::Review => None,
                database::SentaEndpointEventSource::Node(node) => Some(node.into()),
            };
            duplicate_keys.push(SentaEndpointDuplicateKeyEvent {
                at: timestamp(event.key.at)?,
                node,
                sequence: StringNumber(event.key.sequence),
                spki_hash: hex(&event.spki_hash),
                addresses: event.addresses,
                replacement_count: StringNumber(event.replacement_count),
                fetched_at: event.fetched_at.map(timestamp).transpose()?,
            });
        }
        let mut losses = Vec::new();
        for loss in store
            .senta_endpoint_giganto_loss_map()
            .iter_endpoint(endpoint_id)
        {
            let loss = loss?;
            if !kept(loss.key.received_at) {
                continue;
            }
            losses.push(SentaEndpointGigantoLoss {
                received_at: timestamp(loss.key.received_at)?,
                node: loss.key.node.into(),
                stream_id: uuid_id(loss.key.stream_id),
                range_from: StringNumber(loss.key.range_from),
                range_to: StringNumber(loss.key.range_to),
                reason: loss.key.reason_code,
                detail: loss.reason_detail,
                fetched_at: timestamp(loss.fetched_at)?,
            });
        }
        Ok(SentaEndpointEvents {
            duplicate_keys,
            losses,
        })
    }

    /// Lists the endpoint entry of every Giganto node, in node order.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)")]
    async fn endpoint_telemetry_entries(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Vec<SentaEndpointTelemetryEntry>> {
        let store = get_store(ctx)?;
        store
            .senta_endpoint_giganto_entry_map()
            .iter()
            .map(|entry| -> Result<_> {
                let entry = entry?;
                Ok(SentaEndpointTelemetryEntry {
                    node: entry.node.into(),
                    entry_id: uuid_id(entry.entry_id),
                    server_name: entry.server_name,
                    host: entry.host,
                })
            })
            .collect()
    }

    /// Counts, for each customer in scope registered for Clumit Endpoint, how
    /// many of its endpoints have adopted the trust root `fingerprint` (64
    /// lowercase hexadecimal characters), in customer id order.
    ///
    /// An endpoint has adopted the root when its last status report names an
    /// address document slot whose roots, among the endpoint's own
    /// customer's, include the fingerprint. An endpoint without a status
    /// report or a slot counts only in `total`.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn endpoint_trust_root_adoption(
        &self,
        ctx: &Context<'_>,
        fingerprint: String,
    ) -> Result<Vec<SentaEndpointTrustRootAdoption>> {
        let fingerprint = parse_hash("fingerprint", &fingerprint)?;
        let scope = users_customers(ctx)?;
        let store = get_store(ctx)?;
        let mut counts = BTreeMap::new();
        for customer in store
            .senta_endpoint_customer_map()
            .iter(Direction::Forward, None)
        {
            let customer = customer?;
            if is_member(scope.as_deref(), customer.customer_id) {
                counts.insert(customer.customer_id, (0_usize, 0_usize));
            }
        }
        let reports = store.senta_endpoint_status_report_map();
        let roots = store.senta_endpoint_address_root_map();
        for endpoint in store.senta_endpoint_map().iter(Direction::Forward, None) {
            let endpoint = endpoint?;
            let Some((adopted, total)) = counts.get_mut(&endpoint.customer_id) else {
                continue;
            };
            *total += 1;
            let Some((recovery_epoch, version)) = reports
                .get(endpoint.endpoint_id)?
                .and_then(|report| report.address_document_slot)
            else {
                continue;
            };
            if roots.contains(&database::SentaEndpointAddressRoot {
                customer_id: endpoint.customer_id,
                recovery_epoch,
                version,
                fingerprint,
            })? {
                *adopted += 1;
            }
        }
        Ok(counts
            .into_iter()
            .map(
                |(customer_id, (adopted, total))| SentaEndpointTrustRootAdoption {
                    customer_id: ID(customer_id.to_string()),
                    adopted: StringNumber(adopted),
                    total: StringNumber(total),
                },
            )
            .collect())
    }

    /// Lists the unenroll requests in endpoint id order.
    ///
    /// A request of an endpoint without an endpoint row has no customer and
    /// is listed only for an unscoped caller.
    #[graphql(guard = "RoleGuard::new(Role::SystemAdministrator)
        .or(RoleGuard::new(Role::SecurityAdministrator))
        .or(RoleGuard::new(Role::SecurityManager))
        .or(RoleGuard::new(Role::SecurityMonitor))")]
    async fn endpoint_unenroll_requests(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Vec<SentaEndpointUnenrollRequest>> {
        let scope = users_customers(ctx)?;
        let store = get_store(ctx)?;
        let endpoints = store.senta_endpoint_map();
        let mut requests = Vec::new();
        for request in store.senta_endpoint_unenroll_request_map().iter() {
            let request = request?;
            let customer_id = endpoints
                .get(request.endpoint_id)?
                .map(|endpoint| endpoint.customer_id);
            let visible = match (scope.as_deref(), customer_id) {
                (None, _) => true,
                (Some(scope), Some(customer_id)) => scope.contains(&customer_id),
                (Some(_), None) => false,
            };
            if visible {
                requests.push(SentaEndpointUnenrollRequest {
                    endpoint_id: uuid_id(request.endpoint_id),
                    customer_id: customer_id.map(|customer_id| ID(customer_id.to_string())),
                    received_at: timestamp(request.received_at)?,
                });
            }
        }
        Ok(requests)
    }
}

/// The customers a customer-bound query covers: those in the caller's scope,
/// narrowed to the one named by the query's customer argument, if any.
struct CustomerScope {
    /// The caller's customers; `None` for an unscoped caller.
    scope: Option<Vec<u32>>,
    /// The customer the query names.
    customer_id: Option<u32>,
}

impl CustomerScope {
    /// Returns the scope of the caller, narrowed to `customer_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if `customer_id` is not a `u32`, the caller's scope
    /// cannot be read, or `customer_id` is outside the caller's scope.
    fn new(ctx: &Context<'_>, customer_id: Option<&ID>) -> Result<Self> {
        let customer_id = customer_id.map(parse_customer_id).transpose()?;
        let scope = users_customers(ctx)?;
        if let Some(customer_id) = customer_id
            && !is_member(scope.as_deref(), customer_id)
        {
            return Err(FORBIDDEN.into());
        }
        Ok(Self { scope, customer_id })
    }

    /// Returns whether rows of `customer_id` are covered.
    fn includes(&self, customer_id: u32) -> bool {
        self.customer_id.is_none_or(|named| named == customer_id)
            && is_member(self.scope.as_deref(), customer_id)
    }
}

/// The filters of `endpoints`.
struct EndpointFilter {
    scope: CustomerScope,
    standing: Option<String>,
    connected: Option<bool>,
}

impl EndpointFilter {
    fn matches(&self, endpoint: &database::SentaEndpoint) -> bool {
        self.scope.includes(endpoint.customer_id)
            && self
                .standing
                .as_deref()
                .is_none_or(|standing| standing == endpoint.standing)
            && self
                .connected
                .is_none_or(|connected| connected == endpoint.connected)
    }
}

/// Returns the page of the endpoints `filter` selects, keyed by endpoint id.
fn load_endpoints(
    ctx: &Context<'_>,
    filter: &EndpointFilter,
    after: Option<&OpaqueCursor<Vec<u8>>>,
    before: Option<&OpaqueCursor<Vec<u8>>>,
    first: Option<usize>,
    last: Option<usize>,
) -> Result<Connection<OpaqueCursor<Vec<u8>>, SentaEndpoint, SentaEndpointTotalCount, EmptyFields>>
{
    let store = get_store(ctx)?;
    let mut selected = Vec::new();
    for endpoint in store.senta_endpoint_map().iter(Direction::Forward, None) {
        let endpoint = endpoint?;
        if filter.matches(&endpoint) {
            selected.push(endpoint);
        }
    }
    let total = selected.len();
    let after = after.map(|cursor| cursor.0.as_slice());
    let before = before.map(|cursor| cursor.0.as_slice());
    let mut window: Vec<_> = selected
        .into_iter()
        .filter(|endpoint| {
            let key = endpoint.endpoint_id.as_bytes().as_slice();
            after.is_none_or(|after| key > after) && before.is_none_or(|before| key < before)
        })
        .collect();
    let (has_previous, has_next) = if let Some(first) = first {
        let has_next = window.len() > first;
        window.truncate(first);
        (false, has_next)
    } else if let Some(last) = last {
        let excess = window.len().saturating_sub(last);
        window.drain(..excess);
        (excess > 0, false)
    } else {
        (false, false)
    };
    let mut connection = Connection::with_additional_fields(
        has_previous,
        has_next,
        SentaEndpointTotalCount { count: total },
    );
    for endpoint in window {
        let cursor = endpoint.endpoint_id.as_bytes().to_vec();
        connection.edges.push(Edge::new(
            OpaqueCursor(cursor),
            SentaEndpoint::load(&store, endpoint)?,
        ));
    }
    Ok(connection)
}

/// Returns the version `REview` and every node have applied, given
/// `REview`'s version and each node's applied version.
fn applied_everywhere(
    version: Option<u64>,
    mut nodes: impl Iterator<Item = Option<u64>>,
) -> Option<u64> {
    nodes.try_fold(version?, |lowest, applied| Some(lowest.min(applied?)))
}

/// Refuses a scoped caller for an endpoint without an endpoint row or of a
/// customer outside `scope`.
fn check_endpoint_scope(store: &Store, scope: Option<&[u32]>, endpoint_id: Uuid) -> Result<()> {
    let Some(scope) = scope else {
        return Ok(());
    };
    match store.senta_endpoint_map().get(endpoint_id)? {
        Some(endpoint) if scope.contains(&endpoint.customer_id) => Ok(()),
        _ => Err(FORBIDDEN.into()),
    }
}

/// Converts nanoseconds since the Unix epoch to a `Timestamp`.
fn timestamp(nanoseconds: i64) -> Result<Timestamp> {
    jiff::Timestamp::from_nanosecond(i128::from(nanoseconds))
        .map(Timestamp::from)
        .map_err(|e| async_graphql::Error::new(format!("invalid time {nanoseconds}: {e}")))
}

fn uuid_id(id: Uuid) -> ID {
    ID(id.hyphenated().to_string())
}

/// Returns `bytes` as lowercase hexadecimal characters.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            write!(text, "{byte:02x}").expect("writing to a String does not fail");
            text
        })
}

#[cfg(test)]
mod tests;
