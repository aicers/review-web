# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic
Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Add `confidence` field to `DomainGenerationAlgorithm` event.

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
