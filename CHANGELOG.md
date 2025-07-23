# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `TorConnectionConn` event detection for connection-level Tor network
  monitoring. This extends existing Tor detection capabilities beyond HTTP
  connections to include all connection types.
- Added `comprehensiveUserList` GraphQL query for system administrators to
  fetch all user accounts with security status information including account
  lock/suspension status, creation time, last signin time, and access
  restrictions.

### Changed

- Added safeguards to the `updateAccount` GraphQL mutation to prevent system administrators
  from demoting themselves and to block other roles from promoting themselves to
  system administrator.
- Updated the `removeAccounts` GraphQL mutation to prevent users from removing
  their own accounts.
- Enhanced `signedInAccountList` GraphQL API to include customer IDs in the `SignedInAccount`
  type.
- Updated `myAccount` GraphQL API to return the new `MyAccount` type instead of
  `Account`. The `MyAccount` type adds an `expire_times` field, which provides JWT
  expiration times for all active sessions of the current user.
- Changed the return type of the `removeTrustedUserAgents` GraphQL API from
  `bool` to `Vec<String>`. The API now returns a list of removed user agents when
  all input agents are successfully deleted, or an error message if any agents
  could not be removed. Even in case of an error, `apply_allow_networks` is called
  to apply the removed agents.

### Fixed

- Improved customer removal to prevent stale references in account and node
  tables. The process now checks for existing references in accounts or nodes
  and returns an error if any are found.

## [0.27.0] - 2025-07-15

### Added

- Added `confidence` field to most Blocklist GraphQL objects for consistency
  with `BlocklistTls`. The field provides confidence scores for security
  detections across different protocol blocklists.
- Added `level` field to 27 detection event types that previously lacked
  ThreatLevel values. All blocklist and brute force events return Medium
  threat level, while plain text events return Low threat level.

### Changed

- Updated review-database to 0.39.0.
- The `updateAccount` GraphQL mutation's `password` parameter type has been
  changed from `Option<UpdatePassword>` to `Option<String>`. The mutation now
  accepts the new password directly without requiring the old password, as
  SystemAdministrators do not have access to users' current passwords.
- Modified the GraphQL API to prevent additional System administrator accounts
  from being created during insert/update.

### Fixed

- Fixed external service removal in `applyNode` mutation. When an external
  service's draft is set to `null`, the service is now properly removed from
  the node during application.

## [0.26.0] - 2025-06-25

### Added

- Introduced `myAccount` GraphQL API, which allows users of all roles to query
  their own account information.
- Enhanced `signedInAccountList` GraphQL API to include additional account
  details (`name`, `department`, `role`) in the `SignedInAccount` type, providing
  richer information about currently signed-in users.
- Added `updateMyAccount` GraphQL mutation that allows authenticated users to
  update their own account information including password, name, department,
  language, and theme settings. This enables user self-service account
  management for all user roles.
- Added username validation and normalization with the following rules:
  - No whitespace allowed
  - Only lowercase English letters, digits, and special characters
    (`.`, `-`, `_`) are allowed
  - No consecutive special characters or special characters at the end
  - Must start with a lowercase English letter
  - Length must be 3-30 characters
  - Uppercase letters are automatically converted to lowercase
- Added `level` and `learningMethod` fields to all detected event types:
  - Threat level: `HttpThreat` events return `LOW`, all others return `MEDIUM`
  - Learning method: `HttpThreat`, `NetworkThreat`, `WindowsThreat`, and
    `ExtraThreat` events return `UNSUPERVISED`, all others return
    `SEMI_SUPERVISED`
- Added `forceSignOut` GraphQL mutation to allow system administrators and
  security administrators to forcefully terminate all active sessions for any
  user, enhancing security management capabilities.

### Changed

- Restricted `updateAccount` GraphQL mutation access to `SystemAdministrator`
  role only for enhanced security. Previously accessible to both
  `SystemAdministrator` and `SecurityAdministrator` roles.
- Fixed the event stream query iterator performance issue by implementing
  dynamic advancement of stuck event time variables. Added
  `event_stuck_check_interval` parameter to `eventStream` to configure the
  check interval (defaults to 5 minutes). This prevents the iterator from
  getting stuck on old timestamps when certain event types become inactive
  for extended periods.
- Renamed GraphQL field `lastTime` to `endTime` in all event types to better
  reflect its semantic meaning. This affects all event objects in the GraphQL
  schema, including but not limited to `PortScan`, `MultiHostPortScan`,
  `ExternalDdos`, `BlocklistConn`, `BlocklistTls`, `SuspiciousTlsTraffic`, and
  other event types in the `src/graphql/event/` modules.
- Updated the GraphQL APIs related to account as the `customer_ids` field was
  added to the `Account` structure in the review-database.
- Added `confidence` field to `BlocklistTlsFields` event structure.
- Changed the behavior of the `EventListFilterInput::sensors` in event related
  GraphQL APIs.
  - If the `sensors` field is provided, only events collected from the sensors
    are returned.
  - If the `sensors` field is not provided, the software filters events from
    sensors owned by the customers the user belongs to.
- Replaced `Vec<u32>` with `Vec<ID>` for `customer_ids` and `tag_ids`. The
  affected GraphQL APIs are as follows:
  - Parameter type changes: `insertAccount`, `updateAccount`, `insertNetwork`,
    `updateNetwork`, `insertTriageResponse`, `updateTriageResponse`.
  - Return type changes: `account`, `accountList`, `triageResponse`,
    `triageResponseList`.
- Updated `removeTrustedDomain` GraphQL API to `removeTrustedDomains` to support
  multiple removals.
- Updated review-database to 0.37.0, which fixes event filtering by multiple IP
  addresses for `ExternalDdos`, `MultiHostPortScan`, and `RdpBruteForce`.
- Renamed `BlockList` to `Blocklist` and `block_list` to `blocklist` in line
  with the Rust API Guidelines for acronyms/compound words. This affects GraphQL
  APIs such as `eventList` and `eventStream` and may cause breaking changes for
  clients relying on the old field name.
- Changed behavior of blocklist, allowlist and trusted user agents updates to
  automatically broadcast without manual apply.
  - As a result of this change, the following GraphQL APIs used for manual apply
    have been removed: `applyBlockNetworks`, `applyAllowNetworks`, `applyTrustedUserAgent`
  - The following GraphQL APIs have been updated to immediately broadcast
    changes, without requiring a separate apply step: `insertAllowNetwork`,
    `removeAllowNetworks`, `updateAllowNetwork`, `insertBlockNetwork`,
    `removeBlockNetworks`, `updateBlockNetwork`, `insertTrustedUserAgents`,
    `removeTrustedUserAgents`, `updateTrustedUserAgent`
- Renamed `host_names` field to `hostnames` in GraphQL types: `FilterInput`,
  `EventListFilterInput`, and `Filter`. This affects GraphQL APIs such as
  `insertFilter`, `replaceFilter`, `filter`, and `filterList`.
- Enhanced password security by preventing password reuse in `updateAccount` and
  `resetAdminPassword` GraphQL APIs.
  - The `updateAccount` API now requires password changes to provide both old
    and new password values using the format `{ old: "...", new: "..." }`
    instead of just the new password.
  - Both APIs now validate that the new password is different from the current
    password and reject changes that attempt to reuse the current password.
- Modified code related to the packet attribute triage. The scoring
  functionality for packet attribute triage was previously not implemented, but
  is now correctly supported on the review-database side. To reflect this,
  the related code has been updated accordingly.
  - A new field `raw_event_kind` of type `RawEventKind` has been added to `PacketAttrInput`.
  - The same field has also been added as a return field to `PacketAttr`, which
    is one of the types used in triage-related GraphQL API queries.
  - Introduced new enum variants (`UInteger`, `Vector`, `IpAddr`, `Bool`) to the
    `ValueKind` enum for strict type matching of packet attributes.
  - This changes affects GraphQL APIs such as `insertTriagePolicy`,
    `updateTriagePolicy` , `triagePolicyList`, and `triagePolicy`. They may
    introduce breaking changes for clients relying on the previous GraphQL schema.
- Modified code related to node management. The review-database has introduced
  the concept of "external service" to clearly distinguish applications that
  provide an API for interaction and operate outside the REview agent ecosystem,
  from directly connected agents over QUIC. To reflect this concept, the
  node-related code has been updated accordingly.
  - Added new structs `ExternalService` and `ExternalServiceSnapshot`, along
    with enums `ExternalServiceStatus` and `ExternalServiceKind`, to represent
    configuration for external services. The previously used `Giganto` struct,
    which was responsible for storing configuration for the DataStore, has been
    removed and replaced by `ExternalService`.
  - Replaced the `giganto` field of type `Option<GigantoInput>` in both
    `NodeInput` and `NodeDraftInput` with an `external_services` field of type
    `Vec<ExternalServiceInput>`. The `GigantoInput` struct, which was limited to
    handling input for the DataStore only, has been removed. Configuration input
    for all external services—including DataStore—is now provided through `ExternalServiceInput`.
  - Breaking changes have been introduced in the GraphQL APIs (`nodeStatusList`,
    `nodeList`, `node`, `insertNode`, `updateNodeDraft`, `applyNode`). So
    clients that use the affected APIs may need to update their code to maintain
    compatibility.
- Modified `ThreatCategory` to include all MITRE categories.
  `Collection`, `DefenseEvasion`, `Persistence`, `PrivilegeEscalation`,
  `ResourceDevelopment` are added.

### Fixed

- Fixed a security issue where the `language`, `updateLanguage`, `theme`, and
  `updateTheme` APIs allowed changing another user's settings by providing a
  different `username` parameter.
  - The `username` parameter has been removed, and the APIs now extract the
    username from the JWT for authorization.
- Fixed a bug in the `updateNodeDraft` GraphQL API where adding a new agent to
  an already configured node could fail.
- Fixed an issue where GraphQL APIs using `EventListFilterInput` failed to
  filter events by `kinds`.
- Corrected instances of `referrer` to `referer` for the HTTP header field name
  to align with the official HTTP standard's spelling.

### Removed

- `graphql::get_trusted_user_agent_list` has been removed as it is no longer
  used.
- The `theme` and `language` GraphQL APIs are removed. Use the `myAccount`
  GraphQL API instead to retrieve equivalent information.
- The deprecated member `HttpThreat` of `ThreatCategory` is removed.

## [0.25.0] - 2025-01-27

### Added

- Added the `updateTrustedDomain` GraphQL API, allowing users to modify a
  trusted domain.
- Added `IpAddress` GraphQL custom scalar for IP addresses.
  - Applied it to the GraphQL APIs `ipLocation`, `ipLocationList`,
    `insertAccount`, `updateAccount`, `insertSamplingPolicy`, and
    `updateSamplingPolicy`.
  - The API returns the following error message when a value cannot be parsed as
    an `IpAddr` (e.g., when "abc" is given):
    ```text
    Failed to parse "IpAddress": Invalid IP address: abc (occurred while
    parsing "[IpAddress!]")
    ```
- Added the `theme` field to the `Account` struct to store the user's selected
  screen color mode. Accordingly, the functions for inserting and updating
  accounts have been modified, and new APIs have been added to retrieve and
  update the user's selected screen color mode.

### Changed

- The paginated GraphQL queries use different representations for cursors. The
  cursor values obtained from earlier versions of the API are not compatible
  with the new cursor values.
- Replaced the term source with sensor, where it refers to a device or software
  that captures or detects raw events. This update broadly affects GraphQL APIs
  that previously used source field as a parameter, and GraphQL APIs that return
  event, outlier, or triage related structs.
- Updated review-database to 0.34.0.
- The `ip2location::DB` argument for `serve` no longer needs to be wrapped in
  `Arc` and `Mutex`. This change simplifies the code and improves performance by
  removing unnecessary locking.
- Modified the type of `cluster_id` field of the detection event structures from
  `usize` to `Option<usize>`: `HttpThreat`, `ExtraThreat`, `NetworkThreat`,
  `WindowsThreat`.
- The GraphQL API for `WindowsThreat` event structure is changed to return `ID`
  type instead of `usize` type value for the `cluster_id` field.
- Updated `insertNode` GraphQL API to no longer require `config` for the
  `agents` parameter.
- Updated account-related GraphQL APIs to reflect the type change of
  `Account::max_parallel_sessions` from `Option<u32>` to `Option<u8>`.
  - The `account` and related queries such as `accountList` now return
    `maxParallelSessions` as an `Int` within the range of `u8`.
  - The `insertAccount` and `updateAccount` GraphQL APIs remain unchanged in
    their interfaces but now only accept parameters related to max parallel
    sessions within the range of `u8`.
- Changed `AgentManager::broadcast_trusted_user_agent_list` method signature
  from `&[u8]` to `&[String]`. Implementors of `AgentManager` will need to
  update their implementations. This change simplifies the API by removing
  serialization concerns from callers.
- Modified to broadcast the correct internal network list for each
  Semi-supervised Engine. The changes are as follows.
  - Renamed the `broadcast_internal_networks` method of to `AgentManager` trait
    to `send_agent_specific_internal_networks` as the functionality of
    `broadcast_internal_networks` changes from broadcast to fine-targeting nodes
    and agents using agent keys and hostnames to send.
  - Changed the argument type of the `send_agent_specific_internal_networks`
    method from `HostNetworkGroup` to `NetworksTargetAgentKeysPair` array. This
    change will allow the Central Management Server that implements
    `send_agent_specific_internal_networks` to provide the internal networks
    corresponding to the agent information of the Semi-supervised Engine.
  - Renamed `get_customer_id_of_node` to `agent_keys_by_customer_id` as the
    functionality of `get_customer_id_of_node` has changed. The function returns
    agent info list by all customer id.

### Removed

- Removed `graphql::account::reset_admin_password` function as it was obsoleted
  by the GraphQL API `resetAdminPassword`.

### Fixed

- Resolved an issue in the `applyNode` GraphQL API, where configuration values
  set to an empty string were not saved to the `config` in the database.
- Fixed an issue where configuration conversion failures were silently ignored,
  leading to incorrect None handling.

## [0.24.0] - 2024-11-19

### Added

- Added the `TimeSeriesGenerator` variant to the `AgentKind` enum.
- Added `signInWithNewPassword` GraphQL API for signing in with a new password.
  - The `signIn` GraphQL API now returns an error if the account was never
    signed in before. This change is part of enhancing account security by
    requiring all users to update their passwords upon their first signing in.

### Changed

- Modified `applyNode` GraphQL API logic to prevent notifying agents that are
  operating with local configuration.
- Updated `updateNodeDraft` GraphQL API to no longer require `config` in
  `NodeDraftInput::agents`.
- Updated review-database to 0.32.0.
- Renamed `AgentKind` enum variants to align with review-database.

### Fixed

- Added missing `node` field in `samplingPolicy` and `samplingPolicyList`
  GraphQL API responses in the `SamplingPolicy` object.

## [0.23.0] - 2024-10-23

### Changed

- Modified the `AgentManager` trait to accept `HostNetworkGroup` directly
  instead of its serialized form. This change decouples review-web from
  dictating the serialized form of `HostNetworkGroup`, which should be handled
  by the review-protocol crate.
- The `applyNode` GraphQL API now accepts a `NodeInput` argument, in order to
  validate that the provided node data matches the current state in the database
  before applying changes.
- The default connection size is no longer used. Instead, the maximum connection
  size is applied if users don't specify a size.
- Changed the distance search conditions for `rankedOutliers` GraphQL API.
  - start only: Search for outliers whose distance value is greater than or
    equal to the start value.

### Fixed

- Fixed `savedOutliers` and `rankedOutliers` to properly validate pagination
  parameters.
- Fixed to return results from the `rankedOutliers` GraphQL API in ascending
  order. This change ensures a consistent pattern for `rankedOutliers` cursors,
  helping users avoid confusion with various start and end cursor patterns when
  using query.
- Fixed the `rankedOutliers` GraphQL API
  - when `rankedOutliers` called with a cursor, the `RankedOutlier` value
    corresponding to that cursor is excluded from the returned results.
  - Removed the code associated with the `to` variable because `after` and
    `before` are not used together in the query.
  - Removed unnecessary `continue` that is performed after checking the number
    of outliers. This change will return results faster because not all outliers
    are checked.

## [0.22.0] - 2024-10-04

### Added

- Added the `ipLocationList` GraphQL API for multiple addresses.

### Changed

- Updated review-database to 0.31.0.
- Updated `nodeStatusList` GraphQL API response to include `nameDraft`,
  `profile`, `profileDraft`, and `gigantoDraft`, offering a more comprehensive
  view of the node’s status.

### Fixed

- Fixed an issue in the `applyNode` GraphQL API where agents could not be
  properly identified.

### Removed

- The `AgentManager::get_config` method has been removed as part of the new
  configuration management approach. This aligns with the update to
  `review-protocol` version 0.7.0.

## [0.21.0] - 2024-09-05

### Added

- Added `Config` to the public API under the `backend` module to ensure all
  types used by the public traits `AgentManager` and `CertManager` are
  accessible.
- Added session limitation based on the `max_parallel_sessions` field of
  `Account` during sign-in.
- Added ip access control based on the `allow_access_from` field of `Account`
  during sign-in.
- Added `AgentManager::update_config` method to notify agents to update their
  configurations.
- Added new detected events:
  - `BlockListBootp`, `BlockListDhcp`, `SuspiciousTlsTraffic`
- Added the `language` GraphQL API to get the user's UI language selection, and
  the `updateLanguage` GraphQL API to modify it.

### Changed

- Changed to retrieve the admin account's name and password from the
  `REVIEW_ADMIN` environment variable, which is in `username:password` format,
  instead of using hardcoded credentials.
- Moved `AgentManager` and `CertManager` traits from the `graphql` module to a
  newly created `backend` module. This change better organizes the code
  structure by separating concerns, as these traits are not directly related to
  the GraphQL API but are instead utilized within it.
- Updated depedencies, including:
  - Updated review-database to 0.30.0. As part of this update, the fields of
    detected events, including `BlockListConn`, `HttpThreat`, `BlockListNtlm`,
    `BlockListSmtp`, `BlockListSsh`, and `BlockListTls`, and `TorConnection` to
    align with the updated version of review-database.
  - Updated review-protocol to 0.4.2.
  - Updated rustls to version 0.23 and reqwest to version 0.12. These updates
    were made together to ensure the rustls version used by the reqwest library
    matches the version directly depended on by this module.
  - Updated async-graphql to 7. As part of this update, the `Mutation` and
    `Query` structures were split into substructures to avoid the "Requirement
    evaluation overflow" error when implementing the `MergedObject` trait. This
    is a bug in async-graphql 7.0.2 and later, and these structures will be
    merged back into one structure when async-graphql is patched for that bug in
    the future.
- Modified the `Node` and `NodeProfile` fields, along with updating
  `Node`-related CRUD APIs to align with the updated schema. The changes reflect
  the introduction of the new `Agent` table, which stores configuration data in
  TOML format strings.
- Added `category` field to TI db and rules.
- Added `category` fields to all the the detected events.
- Changed GraphQL API `preserveOutliers` to use `PreserveOutliersOutput` in its
  response.
  - Instead of returning the count of successfully marked outliers, this
    endpoint now returns a list of outliers that were not marked as saved.
- Changed GraphQL APIs to return `StringNumber` or `ID` instead of integers
  beyond `i32` in all applicable APIs.
- Refactored `AgentManager::ping` to return `Duration` instead of `i64`. This
  refactor improves the flexibility and accuracy of the `ping` method, making it
  more robust and aligned with Rust's time handling conventions.
- In the GraphQL API, modified the `ping` field in `NodeStatus` to return a
  `Float` (seconds) instead of a `Int` (microseconds). This change improves
  precision when converting the internal representation of the `ping` field to a
  GraphQL-compatible type.
- Added a `language` field to the `Account`. Consequently, the `account` and
  `accountList` API responses now include this field. The `insertAccount` and
  `updateAccount` GraphQL API endpoints are also updated to support the field.
- Updated the `applyNode` GraphQL API to align with the new node and agent
  management approach.
  - The API updates the database with draft values, notifies agents to update
    their configurations, and logs the changes, as long as each step is needed.
  - The `successModules` field has been removed from the API response. Instead,
    the response now includes `gigantoDraft`, representing the draft
    configuration of the Giganto module. If `gigantoDraft` is `None`, it means
    either the node does not have the Giganto module or the draft for the
    Giganto is unavailable. In the latter case, this indicates that the Giganto
    should be disabled, resulting in the node no longer having the Giganto
    module.
- Updated the `nodeStatusList` GraphQL API to align with the new node and agent
  management approach. Key changes include:
  - For nodes with the Manager module, the `ping` field now consistently returns
    0.0 instead of `None`. This change reflects the negligible round-trip time
    when the node has the Manager module, clarifying that the node is reachable
    and avoiding the potential misinterpretation that `None` might suggest the
    node is unreachable.
  - The API response now includes an `agents` field that provides detailed
    information about the agents on the node. This field is in `AgentSnapshot`,
    which contains `kind`, `storedStatus`, `config`, and `draft` attributes for
    each agent.
    - The `storedStatus` field now replaces the previous `piglet`, `reconverge`,
      and `learner` fields. `storedStatus` represents the agent's status as
      stored in the database. With the removal of agent-specific status fields,
      GraphQL clients now need to use the `kind` field to identify the agent
      type.
    - The `config` and `draft` fields replace the old `pigletConfig` and
      `hogConfig` fields. Providing both `config` and `draft` allows GraphQL
      clients to clearly differentiate between an agent's active configuration
      and its draft configuration, offering the flexibility to utilize both sets
      of information as needed.

### Removed

- Removed `get_node_settings` function as it is no longer used.
- The `AgentManager::set_config` method has been removed, due to the new
  configuration management approach. The central management server no longer
  sends updates directly to agents. Instead, it notifies them through the
  `update_config` method, prompting agents to request the updated configuration
  from the management server.

### Fixed

- Corrected the release date of `0.20.0` to `2024-04-25`.

## [0.20.0] - 2024-04-25

### Added

- `AgentManager::halt` method to shut down a host.
- Add unit test for `nodeStatusList` to check ordering of nodes and edges.
- Add `validate_and_process_pagination_params` to check input valid combinations
  of first, last, before, and after and apply it to GraphQL queries with
  pagination.
- Added `LockyRansomware` detection event.
- Added GraphQL query `resetAdminPassword` to allow resetting the password for
  an existing user categorized as `SystemAdministrator` for administrators
  utilizing the local network. This feature enhances the security and
  accessibility of user accounts, providing administrators with a streamlined
  method for password management.

### Changed

- GraphQL queries `accountList`, `allowNetworkList`, `blockNetworkList`,
  `categories`, `networkList`, `qualifiers`, `samplingPolicyList`,
  `loadRoundsByModel`, `statuses`, `templateList`, `torExitNodeList`,
  `triageResponseList`, `nodeStatusList`, `clusters`, `customerList`,
  `dataSourceList`, `eventList`, `roundsByCluster`, `trustedUserAgentList`,
  `trustedDomainList`, `rankedOutliers`, `savedOutliers`, `outliers`, `models`,
  `triagePolicyList`, `nodeList` now explicitly reject user input with
  combinations of (before, after), (first, before), and (last, after)
  parameters, following the GraphQL pagination documentation guidelines. This
  enhancement ensures better consistency and adherence to best practices in
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
- Fix the `nodeStatusList` GraphQL API to return appropriate results for each
  field.
- Remove `giganto` from `NodeStatus` struct and `nodeStatusList`.
- Converted fields in the `nodeStatusList` GraphQL API response from returning
  `Option<i64>` and `Option<u64>` to using `StringNumber`, like
  `Option<StringNumber<i64>>` and `Option<StringNumber<u64>>`. This adjustment
  safeguards against potential data loss resulting from GraphQL's handling of
  `Int` types. Affected fields are `total_memory`, `used_memory`,
  `total_disk_space`, `used_disk_space`, and `ping`.

### Removed

- The implementor of `AgentManager` is now responsible for providing the
  appropriate behavior, because `AgentManager` no longer provides shared
  behavior for the following methods:
  - `broadcast_crusher_sampling_policy`
  - `get_process_list`
  - `get_resource_usage`
  - `ping`
  - `reboot`
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
- Changed the return type of `indicatorList` GraphQL query to
  `[ModelIndicator!]!`.
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
  and has been removed to streamline the codebase and enhance overall
  maintainability.

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
  - User expecting `status_id` change when `qualifier_id` is changed will need
    to specify desired `qualifier_id` while updating cluster.
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

- Added `ranked_outlier_stream` Graphql API to fetch `RankedOutlier`
  periodically.
  - Gets the id of the currently stored `Model`.
  - Generate a `RankedOutlier` iterator corresponding to the prefix of the
    `Model`'s id. If not first fetch, generate iterator since the last fetched
    key.
  - Stream through the `RankedOutlier` iterator, and repeat the behavior after a
    period of time.

### Changed

- Changed `Node` fields.
- Updated review-database to 0.22.1.
- Updated `column_statistics` according to review-database 0.21.0
  - Removed `event_range` argument.
  - Changed the `time` argument to `Vec<NaiveDateTime>`.
  - After adjustment, `column_statistics` now returns all column statistics of
    the specified `cluster` and created at the batch timestamp listed in the
    `time` argument.
  - The timestamp is now added to the return value field `batch_ts`,
    representing the batch timestamp for the specified `Statistics`.
  - The returned `Statistics` are now sorted according to `batch_ts` and
    `column_index`.

## [0.15.0] - 2023-11-15

### Changed

- Change the type of `id` in `ranked_outlier`/`saved_outlier` queries to
  `StringNumber`.
- Modified Ranked Outliers graphql query to take in a SearchFilter with `tag`
  and `remark`
- Change the distance search conditions for `ranked outliers`.
  - Start only: Search for outliers with the same distance value
  - Start/End: Search for outliers with distance values in the range.
- Change the data type of the `id` in the `RankedOutlier` structure from
  `StringNumber` to `ID`.
- Change the part about `RankedOutlierTotalCount` to count the total count
  differently depending on whether it is `saved_outliers` or `ranked_outliers`.

## [0.14.5] - 2023-11-02

### Changed

- Modified Ranked Outliers graphql query to take in a SearchFilter with distance
  range and time range

### Added

- Added new method for Ranked Outliers `load_ranked_outliers_with_filter`,
  `load_nodes_with_search_filter`, and `iter_through_search_filter_nodes` to
  load Ranked Outliers depending on new Search Filter.

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

- Modified serialization method in broadcasting of internal networks, allowlist
  and blocklist. The new implementation now uses
  `bincode::DefaultOptions::new().serialize()` instead of
  `bincode::serialize()`. This change is aimed at maintaining consistency with
  other serialized data across our system.

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
  - After a period of time, look up the `EventDb` again, find the newly added
    events, stream them, and keep repeating.

### Changed

- Updated review-database to 0.13.2.

## [0.9.1] - 2023-05-25

### Added

- The `DomainGenerationAlgorithm` event in our `GraphQL` API query now includes
  a confidence field. This field will allow users to access and gauge the
  predictive certainty of the output.
- `AgentManager` trait has been extended with three new methods.
  - `broadcast_internal_networks`: This method is responsible for broadcasting
    the customer's network details, including intranet, extranet, and gateway IP
    addresses to clients.
  - `broadcast_allow_networks`: This method sends the IP addresses that are
    always accepted as benign to the clients.
  - `broadcast_block_networks`: This method broadcasts the IP addresses that are
    always considered suspicious.
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
- If the customer networks of a node are updated, the changes are now broadcast.
  This provides an additional layer of communication to keep the system
  up-to-date with changes.

## [0.9.0] - 2023-05-22

### Changed

- Updated review-database to 0.12.0.
- Starting from this version, the policy field for TimeSeries data will be set
  to the same value as the source field. For other data types, the policy field
  will be set to null.

## [0.8.1] - 2023-05-18

### Changed

- The `update_traffic_filter_rules` function has been updated to explicitly take
  a `host_id` as an argument, replacing the previous `agent_id@host_id` argument
  format.
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

- From the GraphQL APIs `signIn` and `refreshToken`, the username field has been
  removed from the `AuthPayload` return object. This is due to redundancy as the
  caller of `signIn` or `refreshToken` already possesses knowledge of the
  username.
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

[Unreleased]: https://github.com/aicers/review-web/compare/0.27.0...main
[0.27.0]: https://github.com/aicers/review-web/compare/0.26.0...0.27.0
[0.26.0]: https://github.com/aicers/review-web/compare/0.25.0...0.26.0
[0.25.0]: https://github.com/aicers/review-web/compare/0.24.0...0.25.0
[0.24.0]: https://github.com/aicers/review-web/compare/0.23.0...0.24.0
[0.23.0]: https://github.com/aicers/review-web/compare/0.22.0...0.23.0
[0.22.0]: https://github.com/aicers/review-web/compare/0.21.0...0.22.0
[0.21.0]: https://github.com/aicers/review-web/compare/0.20.0...0.21.0
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
