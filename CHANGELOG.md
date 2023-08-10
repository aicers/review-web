# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Refactor the event processing code by separating it into protocol files.

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

- Modified serialization method in broadcasting of `internal networks,
allow/block list`. The new implementation now uses
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

[Unreleased]: https://github.com/petabi/review-web/compare/0.14.1...main
[0.14.2]: https://github.com/petabi/review-web/compare/0.14.1...0.14.2
[0.14.1]: https://github.com/petabi/review-web/compare/0.14.0...0.14.1
[0.14.0]: https://github.com/petabi/review-web/compare/0.13.1...0.14.0
[0.13.1]: https://github.com/petabi/review-web/compare/0.12.0...0.13.1
[0.13.0]: https://github.com/petabi/review-web/compare/0.12.0...0.13.0
[0.12.0]: https://github.com/petabi/review-web/compare/0.11.0...0.12.0
[0.11.0]: https://github.com/petabi/review-web/compare/0.10.0...0.11.0
[0.10.0]: https://github.com/petabi/review-web/compare/0.9.1...0.10.0
[0.9.1]: https://github.com/petabi/review-web/compare/0.9.0...0.9.1
[0.9.0]: https://github.com/petabi/review-web/compare/0.8.1...0.9.0
[0.8.1]: https://github.com/petabi/review-web/compare/0.8.0...0.8.1
[0.8.0]: https://github.com/petabi/review-web/compare/0.7.0...0.8.0
[0.7.0]: https://github.com/petabi/review-web/compare/0.6.0...0.7.0
[0.6.0]: https://github.com/petabi/review-web/compare/0.5.0...0.6.0
[0.5.0]: https://github.com/petabi/review-web/compare/0.4.1...0.5.0
[0.4.1]: https://github.com/petabi/review-web/compare/0.4.0...0.4.1
[0.4.0]: https://github.com/petabi/review-web/compare/0.3.0...0.4.0
[0.3.0]: https://github.com/petabi/review-web/compare/0.2.0...0.3.0
[0.2.0]: https://github.com/petabi/review-web/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/petabi/review-web/tree/0.1.0
