# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `Config` to the public API under the `backend` module to ensure all
  types used by the public traits `AgentManager` and `CertManager` are
  accessible.
- Added session limitation based on the `max_parallel_sessions` field of `Account`
  during sign-in.
- Added ip access control based on the `allow_access_from` field of `Account`
  during sign-in.

### Changed

- Change admin account to read environment variable `REVIEW_ADMIN` from hardcoded
  value.
- Moved `AgentManager` and `CertManager` traits from the `graphql` module to a
  newly created `backend` module. This change better organizes the code
  structure by separating concerns, as these traits are not directly related to
  the GraphQL API but are instead utilized within it.
- Update `TestSchema` to accept `test_addr` for simulating client IP.
- Update dependencies version.
- Fix code based on a dependency update.
  - Fix code associated with changed fields in events detected in HTTP, SMTP,
    CONN, NTLM, SSH, and TLS protocols.
  - Fix code based on changes in test code results.
  - Split the contents of the `Mutation` and `Query` structures into
    substructures to fix an issue where a "Requirement evaluation overflow"
    error occurs when implementing the `MergedObject` trait on the `Mutation`
    and `query` structures after an update of async-graphql. this is a bug in
    async-graphql 7.0.2 and later, and will be merged back into one structure
    when async-graphql is patched for that bug in the future.
- Apply rustfmt's option `group_imports=StdExternalCrate`.
  - Modify the code with the command `cargo fmt -- --config group_imports=StdExternalCrate`.
    This command must be applied automatically or manually before all future pull
    requests are submitted.
  - Add `--config group_imports=StdExternalCrate` to the CI process like:
    - `cargo fmt -- --check --config group_imports=StdExternalCrate`
- Updated version of rustls to "0.23" and fixed related code due to reqwest
  version update.
- Modified the `Node`, `NodeProfile` fields.
  - Modified `Node` related CRUD APIs.
  - Removed `get_node_settings` function as it is no longer used.
  - Renamed `get_customer_id_of_review_host` to `get_customer_id_of_node`.
- Updated review-database to 0.29.1.
- In `BlockListSmb`, `Network`, `SamplingPolicy`, `Tidb`, and `TidbRule`,
  changed GraphQL APIs to return `StringNumber` or `ID` instead of integers
  beyond `i32`.
- Refactor `AgentManager::ping` to return `Duration` instead of `i64`. This
  refactor improves the flexibility and accuracy of the `ping` method, making it
  more robust and aligned with Rust's time handling conventions.

### Fixed

- Correct the release date of `0.20.0` to `2024-04-25`.

## [0.20.0] - 2024-04-25

### Added

- `AgentManager::halt` method to shut down a host.
- Add unit test for `nodeStatusList` to check ordering of nodes and edges.
- Add `validate_and_process_pagination_params` to check input valid
  combinations of first, last, before, and after and apply it to GraphQL
  queries with pagination.
- Added `LockyRansomware` detection event.
- Added GraphQL query `resetAdminPassword` to allow resetting the password for an
  existing user categorized as `SystemAdministrator` for administrators utilizing
  the local network. This feature enhances the security and accessibility of user
  accounts, providing administrators with a streamlined method for password management.

### Changed

- GraphQL queries `accountList`, `allowNetworkList`, `blockNetworkList`,
  `categories`, `networkList`, `qualifiers`, `samplingPolicyList`,
  `loadRoundsByModel`, `statuses`, `templateList`, `torExitNodeList`,
  `triageResponseList`, `nodeStatusList`, `clusters`, `customerList`,
  `dataSourceList`, `eventList`, `roundsByCluster`, `trustedUserAgentList`,
  `trustedDomainList`, `rankedOutliers`, `savedOutliers`, `outliers`, `models`,
  `triagePolicyList`, `nodeList` now explicitly reject user input with
  combinations of (before, after), (first, before), and (last, after)
  parameters, following the GraphQL pagination documentation guidelines.
  This enhancement ensures better consistency and adherence to best practices in
  handling pagination requests.
- GraphQL queries `insertTidb` requires `dbfile` to be encoded string of `Tidb`
  instance that is serialized with `bincode::DefaultOptions::new().serialize`
  instead of `bincode::serialize`.
- GraphQL queries `updateTidb` requires `new` to be encoded string of `Tidb`
  instance that is serialized with `bincode::DefaultOptions::new().serialize`
  instead of `bincode::serialize`.
- Add the result of `get_config` of each module to `nodeStatusList` GraphQL API.
- Use `set_config` of `AgentManager`, instead of `send_and_recv` in `applyNode`
  GraphQL API.
- Use `halt` of `AgentManager`, instead of `send_and_recv` in `nodeShutdown`
  GraphQL API.
- Updated review-database to 0.27.0.
- Fix the `nodeStatusList` GraphQL API to return appropriate results for each field.
- Remove `giganto` from `NodeStatus` struct and `nodeStatusList`.
- Converted fields in the `nodeStatusList` GraphQL API response from returning
  `Option<i64>` and `Option<u64>` to using `StringNumber`, like
  `Option<StringNumber<i64>>` and `Option<StringNumber<u64>>`. This adjustment
  safeguards against potential data loss resulting from GraphQL's handling of
  `Int` types. Affected fields are `total_memory`, `used_memory`,
  `total_disk_space`, `used_disk_space`, and `ping`.

### Removed

- `AgentManager` no longer provides shared behavior for the following methods:
  - `broadcast_crusher_sampling_policy`
  - `get_process_list`
  - `get_resource_usage`
  - `ping`
  - `reboot`
  The implementor of `AgentManager` is now responsible for providing the
  behavior for these methods.
- `AgentManager::send_and_recv` and `broadcast_to_crusher` has been removed
  because they exposed the underlying communication mechanism to the caller. The
  caller should now use the specific methods provided by `AgentManager` to
  interact with the agent.
- `AgentManager::default` has been removed that returns error.

### Fixed

- Corrected documentation for `NodeStatus::{total_memory, used_memory}` to
  specify that the numbers are in bytes, not in KB.

## [0.19.0] - 2024-03-18

### Changed

- Updated the `ModelIndicator` GraphQL type. Added `name` field as the name of
  the model indicator.
- Changed the return type of `indicatorList` GraphQL query to `[ModelIndicator!]!`.
- GraphQL query `updateExpirationTime` returns an error if the expiration time
  is less than one second.
- `init_expiration_time` and `update_jwt_expires_in` take `u32` instead of `i64`
  for the expiration time argument.
- `Node` struct now has `settings` and `settings_draft` of type `NodeSettings`,
  and `name` and `name_draft`. Upon initial insertion of `Node`, `name` must be
  provided, as it is used as the key of `Node` in the database. `name_draft` and
  `settings_draft` are introduced to support 2-step node-setting process, which
  is save & apply. `name_draft` and `settings_draft` fields mean that the data
  are only saved to the database. Once those are applied, the draft values are
  moved to `name`, and `settings`.
  - Renamed `updateNode` GraphQL API to `updateNodeDraft`, and modified
    parameter types. `old` to `NodeInput`, and `new` to `NodeDraftInput`.
  - `graphql::event::convert_sensors` uses `Node`'s `settings` value, to
    retrieve the hostnames of the sensors. This function is called by GraphQL
    APIs of `EventQuery` and `EventGroupQuery`.
  - `nodeStatusList` GraphQL API uses `hostname` from `Node`'s `settings` field.
  - `graphql::node::crud::get_node_settings` uses `Node`'s `settings` value.

### Removed

- Removed the obsoleted `ModelIndicatorOutput` GraphQL type. This type was
  previously used as return type of `indicatorList` GraphQL query. With
  advancements and improvements in our system, this type is no longer necessary
  and has been removed to streamline the codebase and enhance overall maintainability.

### Added

- Add unit tests to `customer_list` to check ordering of nodes and edges.
- `AgentManager::broadcast_crusher_sampling_policy` method to broadcast the
  sampling policy to the Crusher agents.
- `AgentManager::get_process_list` method to retrieve the list of processes
  usage running on host. It returns a `Vec` of `graphql::Process`.
- `AgentManager::get_resource_usage` method to retrieve the resource usage of a
  host. It returns `graphql::ResourceUsage`.
- `AgentManager::ping` method to measure the latency between the agent manager
  and a host.
- `AgentManager::reboot` method to reboot a host.
- `AgentManager::get_config` and `AgentManager::set_config` methods to get and
  set the configuration of an agent.
- Add `nodeShutdown` GraphQL API.
- Introduced `applyNode` GraphQL API, that applies draft values to modules and
  updates values in database. This API handles partial success of setting
  application settings, which may happen when a node carries multiple modules.
  The API returns the list of succeeded modules' names in
  `ApplyResult::success_modules`.

### Fixed

- Resolved an issue in the `processList` query function where applications were
  incorrectly identified by their agent ID instead of their application name.
  Previously, the function assumed the agent ID in the format
  "agent_id@hostname" directly corresponded to the application name, which was
  not always the case. This assumption did not support scenarios where multiple
  instances of the same application ran on the same host with unique agent IDs.
  The updated implementation now correctly identifies applications by their
  name, ensuring accurate application prioritization.

## [0.18.0] - 2024-02-26

### Added

- Add `apply_target_id` field to `Node` struct for reverting node status.
- Add `apply_in_progress` field to `Node` struct for reverting node status.
- Added the following GraphQL API to access workflow tags:
  - 'workflowTagList'
  - 'insertWorkflowTag'
  - 'removeWorkflowTag'
  - 'updateWorkflowTag'

### Fixed

- We've resolved an issue in the GraphQL API where the ordering of edges was
  inconsistent when using `last`/`before` pagination arguments. According to the
  GraphQL Cursor Connections Specification, the order of edges should remain the
  same whether using `first`/`after` or `last`/`before`, provided all other
  arguments are equal. Previously, our API returned edges in reverse order when
  `last`/`before` was used, which was contrary to the specification.
- Resolved a critical bug in the GraphQL API endpoint `updateCluster` where the
  user-specified `status_id` was being overwritten when `qualifier_id` change is
  requested at the same time.
  - The issue has been addressed to ensure that the user-provided `status_id` is
    now properly respected and retained.
  - User expecting `status_id` change when `qualifier_id` is changed will need to
    specify desired `qualifier_id` while updating cluster.
- When inserting a new filter using `filters.insert(new.name.clone(), new)`, the
  function now checks for conflicts in the filter collection.
  - If the `new.name` already exists, the function returns an error, preventing
    unintentional or malicious deletion of any filter.
  - This fix adds an extra layer of security, ensuring the integrity of the
    filter collection.

## [0.17.0] - 2024-01-19

### Added

- Add new `WindowsThreat` event message for Windows sysmon events.
- Add new `NetworkThreat` event message for network events.
- Add new `ExtraThreat` event message for misc log events.

### Changed

- Updated review-database to 0.23.0.

## [0.16.0] - 2024-01-15

### Added

- Added `ranked_outlier_stream` Graphql API to fetch `RankedOutlier` periodically.
  - Gets the id of the currently stored `Model`.
  - Generate a `RankedOutlier` iterator corresponding to the prefix of the
    `Model`'s id. If not first fetch, generate iterator since the last fetched key.
  - Stream through the `RankedOutlier` iterator, and repeat the behavior after a
    period of time.

### Changed

- Changed `Node` fields.
- Updated review-database to 0.22.1.
- Updated `column_statistics` according to review-database 0.21.0
  - Removed `event_range` argument.
  - Changed the `time` argument to `Vec<NaiveDateTime>`.
  - After adjustment, `column_statistics` now returns all column statistics of the
    specified `cluster` and created at the batch timestamp listed in the `time` argument.
  - The timestamp is now added to the return value field `batch_ts`, representing
    the batch timestamp for the specified `Statistics`.
  - The returned `Statistics` are now sorted according to `batch_ts` and `column_index`.

## [0.15.0] - 2023-11-15

### Changed

- Change the type of `id` in `ranked_outlier`/`saved_outlier` queries to `StringNumber`.
- Modified Ranked Outliers graphql query to take in a SearchFilter with
  `tag` and `remark`
- Change the distance search conditions for `ranked outliers`.
  - Start only: Search for outliers with the same distance value
  - Start/End: Search for outliers with distance values in the range.
- Change the data type of the `id` in the `RankedOutlier` structure from `StringNumber`
  to `ID`.
- Change the part about `RankedOutlierTotalCount` to count the total count differently
  depending on whether it is `saved_outliers` or `ranked_outliers`.

## [0.14.5] - 2023-11-02

### Changed

- Modified Ranked Outliers graphql query to take in a SearchFilter with
  distance range and time range

### Added

- Added new method for Ranked Outliers `load_ranked_outliers_with_filter`,
  `load_nodes_with_search_filter`, and `iter_through_search_filter_nodes`
  to load Ranked Outliers depending on new Search Filter.

## [0.14.4] - 2023-10-19

### Added

- Added `processList` graphql query to get the host's list of processes.
- Add block list event.
  - DceRpc: `BlockListDceRpc`
  - Ftp: `BlockListFtp`
  - Http: `BlockListHttp`
  - Kerberos: `BlockListKerberos`
  - Ldap: `BlockListLdap`
  - Mqtt: `BlockListMqtt`
  - Nfs: `BlockListNfs`
  - Ntlm: `BlockListNtlm`
  - Rdp: `BlockListRdp`
  - Smb: `BlockListSmb`
  - Smtp: `BlockListSmtp`
  - Ssh: `BlockListSsh`
  - tls: `BlockListTls`

### Changed

- Updated review-database to 0.20.0.

### Fix

- Fix to provide multiple `country codes`/`Customers` for events with multiple
  `addresses`. (`RdpBruteForce`, `MultiHostPortScan`, `ExternalDdos`)

## [0.14.3] - 2023-09-04

### Changed

- Refactor the event processing code by separating it into protocol files.
- Modify outlier query to read outlier events from Rocks db.

## [0.14.2] - 2023-08-22

### Added

- Add block list event.
  - Conn: `BlockListConn`
  - Dns: `BlockListDns`

### Changed

- Modified `FtpBruteForce`, `LdapBruteForce`, `RdpBruteForce` events to align
  with the event fields provided.
- Updated review-database to 0.17.1.

## [0.14.1] - 2023-07-06

### Added

- Supports more events.
  - Dns: `CryptocurrencyMiningPool`
  - Ftp: `FtpBruteForce`, `FtpPlainText`
  - Ldap: `LdapBruteForce`, `LdapPlainText`
  - Http: `NonBrowser`
  - Session: `PortScan`, `MultiHostPortScan`, `ExternalDdos`

### Changed

- Updated review-database to 0.15.2.

## [0.14.0] - 2023-06-20

### Added

- Added five new GraphQL API methods:
  - `trusted_user_agent_list`: This new method allows users to retrieve the
    trusted user agent list.
  - `insert_trusted_user_agents`: This new feature enables users to insert
    trusted user agents into the list.
  - `remove_trusted_user_agents`: Users can now delete trusted user agents from
    the list using this method.
  - `update_trusted_user_agent`: This feature has been added to enable users to
    update the details of a trusted user agent.
  - `apply_trusted_user_agent`: This new method allows a list of trusted user
    agents to be applied to all `hog` associated with `REview`.

### Changed

- The `srcPort` and `dstPort` types in both `TorConnection` and
  `RepeatedHttpSessions` have been changed. These types were previously
  `!String` but have now been changed to `!Int`. This change will enhance data
  consistency and reduce errors related to data type mismatches.

## [0.13.1] - 2023-06-16

### Fixed

- Reverted an accidantal change made to the serialization of allow/block
  networks in 0.13.0.

## [0.13.0] - 2023-06-15

### Changed

- Updated review-database to 0.15.0.

## [0.12.0] - 2023-06-10

### Changed

- Updated review-database to 0.14.1.

## [0.11.0] - 2023-06-08

### Added

- Added new fields to the `Event` enum internal struct provided via GraphQL for
  enhanced `detect event filtering`. This will allow more detailed filtering
  capabilities in the GraphQL API.
- Introduced a `ping` field to `NodeStatus` struct, accessible via the
  `NodeStatusList` query. As part of this change, we updated the `status::load`
  function to include the `ping` field in the response of the `NodeStatusList`
  query. This enhancement allows users to retrieve the `ping` status of nodes
  using the GraphQL API.
- Updated the `status::load` function to include the `ping` field in the
  response of the `NodeStatusList` query. This change enables users to retrieve
  the `ping` status of nodes via the GraphQL API.

### Changed

- Modified serialization method in broadcasting of
  `internal networks,allow/block list`. The new implementation now uses
  `bincode::DefaultOptions::new().serialize()` instead of `bincode::serialize()`.
  This change is aimed at maintaining consistency with other serialized data
  across our system.

## [0.10.0] - 2023-05-31

### Added

- To enhance security and traceability, we have implemented a new logging
  feature which now writes a log message during specific user authentication
  activities.
  - User Sign-in Logging: A log message will be automatically generated each
    time a user signs in successfully.
  - User Sign-out Logging: In addition to sign-ins, we now log user sign-out
    events.
  - Sign-in Failure Logging: In an effort to help detect and mitigate potential
    security issues, we are now logging failed sign-in attempts. This includes
    the user identification (if applicable) and the reason for failure (e.g.,
    incorrect password, non-existent user ID, etc.).
- Added `eventstream` Graphql API to fetch events periodically.
  - Based on the `start` time, look for events in `EventDb` that meet the
    criteria and stream them.
  - After a period of time, look up the `EventDb` again, find the newly
    added events, stream them, and keep repeating.

### Changed

- Updated review-database to 0.13.2.

## [0.9.1] - 2023-05-25

### Added

- The `DomainGenerationAlgorithm` event in our `GraphQL` API query now includes
  a confidence field. This field will allow users to access and gauge the
  predictive certainty of the output.
- `AgentManager` trait has been extended with three new methods.
  - `broadcast_internal_networks`: This method is responsible for broadcasting
    the customer's network details, including intranet, extranet, and gateway
    IP addresses to clients.
  - `broadcast_allow_networks`: This method sends the IP addresses that are
    always accepted as benign to the clients.
  - `broadcast_block_networks`: This method broadcasts the IP addresses that
    are always considered suspicious.
- Four new functions have been added to the `graphql` module to assist with the
  implementation of the `AgentManager` trait:
  - `graphql::get_allow_networks`: Fetches the list of IP addresses that are
    always accepted as benign.
  - `graphql::get_block_networks`: Fetches the list of IP addresses that are
    always considered suspicious.
  - `graphql::get_customer_networks`: Gets the customer's network details,
    including intranet, extranet, and gateway IP addresses.
  - `get_customer_id_of_review_host`: Returns the customer ID associated with
    the review host.
- Two new GraphQL API methods have been added:
  - `applyAllowNetworks`: Applies the list of IP addresses that are always
    accepted as benign.
  - `applyBlockNetworks`: Applies the list of IP addresses that are always
    considered suspicious.

### Changed

- The behavior when a new node is added or the customer of a node is changed,
  has been updated to broadcast the customer networks of the node.
- If the customer networks of a node are updated, the changes are now
  broadcast. This provides an additional layer of communication to keep the
  system up-to-date with changes.

## [0.9.0] - 2023-05-22

### Changed

- Updated review-database to 0.12.0.
- Starting from this version, the policy field for TimeSeries data will be set
  to the same value as the source field. For other data types, the policy field
  will be set to null.

## [0.8.1] - 2023-05-18

### Changed

- The `update_traffic_filter_rules` function has been updated to explicitly
  take a `host_id` as an argument, replacing the previous `agent_id@host_id`
  argument format.
- Allows the clearing of filtering rules at an agent level by sending an empty
  rule set to the agent.

## [0.8.0] - 2023-05-18

### Added

- Extended `HttpThreat` object in the GraphQL API:
  - The `HttpThreat` object now exposes additional fields which encompass all
    the fields present in an HTTP request. Details of these additional fields
    can be found in the updated schema.
  - Introduced a new field, matched_to, within the `HttpThreat` object. This
    field presents all the patterns that correspond with the HTTP request.

### Changed

- Updated review-database to 0.11.0.

## [0.7.0] - 2023-05-16

### Changed

- Updated review-database to 0.10.1.

## [0.6.0] - 2023-05-15

### Added

- Added `kind` field to the return values of `dataSourceList` API.

### Changed

- From the GraphQL APIs `signIn` and `refreshToken`, the username field has
  been removed from the `AuthPayload` return object. This is due to redundancy
  as the caller of `signIn` or `refreshToken` already possesses knowledge of
  the username.
- Updated review-database to 0.9.0.

## [0.5.0] - 2023-05-08

### Changed

- Updated review-database to 0.8.0.

### Fixed

- Resolved an issue with the GraphQL query `clusters` that was introduced in
  version 0.4.0 due to a database schema change. The `clusters` query is now
  functional again, allowing users to retrieve cluster data as expected.

## [0.4.1] - 2023-05-05

### Added

- Added a GraphQL query, `rankedOutliers`, to retrieve outliers.

## [0.4.0] - 2023-05-04

### Changed

- Updated `review-database` to 0.7.1.

## [0.3.0] - 2023-05-02

### Changed

- Updated `ip2location` to 0.4.2.
- Updated `review-database` to 0.7.0.
- GraphQL API `columnStatistics`: This query's parameters have been modified to
  support event source.
  - Replaced separate firstEventId: Int and lastEventId: Int parameters with a
    single eventRange: EventRangeInput parameter.
  - EventRangeInput is a new input type that includes the following required
    fields:
    - firstEventId: !Int (equivalent to the previous firstEventId parameter).
    - lastEventId: !Int (equivalent to the previous lastEventId parameter).
    - eventSource: !String (a new required field indicating the source of the
      events).

## [0.2.0] - 2023-04-27

### Changed

- Added `port/procotol` to traffic filter rule to filter traffic in Piglet.

## [0.1.0] - 2023-04-24

### Added

- An initial version.

[Unreleased]: https://github.com/aicers/review-web/compare/0.20.0...main
[0.20.0]: https://github.com/aicers/review-web/compare/0.19.0...0.20.0
[0.19.0]: https://github.com/aicers/review-web/compare/0.18.0...0.19.0
[0.18.0]: https://github.com/aicers/review-web/compare/0.17.0...0.18.0
[0.17.0]: https://github.com/aicers/review-web/compare/0.16.0...0.17.0
[0.16.0]: https://github.com/aicers/review-web/compare/0.15.0...0.16.0
[0.15.0]: https://github.com/aicers/review-web/compare/0.14.5...0.15.0
[0.14.5]: https://github.com/aicers/review-web/compare/0.14.4...0.14.5
[0.14.4]: https://github.com/aicers/review-web/compare/0.14.3...0.14.4
[0.14.3]: https://github.com/aicers/review-web/compare/0.14.2...0.14.3
[0.14.2]: https://github.com/aicers/review-web/compare/0.14.1...0.14.2
[0.14.1]: https://github.com/aicers/review-web/compare/0.14.0...0.14.1
[0.14.0]: https://github.com/aicers/review-web/compare/0.13.1...0.14.0
[0.13.1]: https://github.com/aicers/review-web/compare/0.12.0...0.13.1
[0.13.0]: https://github.com/aicers/review-web/compare/0.12.0...0.13.0
[0.12.0]: https://github.com/aicers/review-web/compare/0.11.0...0.12.0
[0.11.0]: https://github.com/aicers/review-web/compare/0.10.0...0.11.0
[0.10.0]: https://github.com/aicers/review-web/compare/0.9.1...0.10.0
[0.9.1]: https://github.com/aicers/review-web/compare/0.9.0...0.9.1
[0.9.0]: https://github.com/aicers/review-web/compare/0.8.1...0.9.0
[0.8.1]: https://github.com/aicers/review-web/compare/0.8.0...0.8.1
[0.8.0]: https://github.com/aicers/review-web/compare/0.7.0...0.8.0
[0.7.0]: https://github.com/aicers/review-web/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/aicers/review-web/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/aicers/review-web/compare/0.4.1...0.5.0
[0.4.1]: https://github.com/aicers/review-web/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/aicers/review-web/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/aicers/review-web/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/aicers/review-web/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/aicers/review-web/tree/0.1.0
