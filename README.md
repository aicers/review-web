# review-web

This project aims to provide an easy-to-use interface for the REview system,
allowing users to manage and analyze events from various sensors. The web
interface is built using modern web technologies, and it exposes a GraphQL API
for flexible data querying and manipulation.

[![Coverage Status](https://codecov.io/gh/aicers/review-web/branch/main/graphs/badge.svg)](https://codecov.io/gh/aicers/review-web)

## Minireview

### Build

Build as follows:

```sh
cargo build --example minireview
```

To build with mTLS + Context JWT:

```sh
cargo build --example minireview --features auth-mtls
```

### Test

Test as follows:

```sh
target/debug/examples/minireview <path to a config file>
```

The config file has the following options:

```toml
backup_dir = "/path/to/backup"              # path to a backup directory
ca_certs = ["/path/to/cert.pem"]            # paths to CA certificate files
cert = "/path/to/cert.pem"                  # path to a certificate file
client_cert = "/path/to/client.pem"         # client cert for mTLS (optional)
client_key = "/path/to/client-key.pem"      # client key for mTLS (optional)
data_dir = "/path/to/data"                  # path to a RocksDB data directory
database_url = "postgres://id:pw@host/db"   # PostgreSQL URL
graphql_srv_addr = "127.0.0.1:8442"         # GraphQL address
htdocs_dir = "/path/to/htdocs"              # path to a directory for web files
ip2location = "/path/to/IP2LOCATON"         # path to a IP2LOCATION file
key = "/path/to/key.pem"                    # path to a key file
log_dir = "/path/to/log"                    # path to a log directory

# <SERVER_NAME>: Name of the central management server. This must match with
# the DNS name in the certificate.

[[reverse_proxies]]
base = "archive"                            # proxy name for Giganto
uri = "https://<SERVER_NAME>:8443/graphql"  # Giganto's GraphQL address

[[reverse_proxies]]
base = "ti-container"                       # proxy name for TI container
uri = "https://<SERVER_NAME>:8444/graphql"  # TI container's GraphQL address
```

## License

Copyright 2018-2023 Petabi, Inc.  
Copyright 2023-2026 ClumL Inc.

Licensed under [Apache License, Version 2.0][apache-license] (the "License");
you may not use this crate except in compliance with the License.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See [LICENSE](LICENSE) for
the specific language governing permissions and limitations under the License.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the [Apache-2.0
license][apache-license], shall be licensed as above, without any additional
terms or conditions.

[apache-license]: https://www.apache.org/licenses/LICENSE-2.0
