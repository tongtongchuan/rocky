# Rocky

Rocky is a Linux web server and reverse proxy. It serves static files, proxies HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/3 requests, and relays TCP streams. A validated configuration can take effect while traffic is active. [Architecture](docs/ARCHITECTURE.md)

## Run locally

Build with Rust 1.88 or newer on Linux with `openat2` support. Linux added `openat2` in kernel 5.6. [Linux openat2 manual](https://man7.org/linux/man-pages/man2/openat2.2.html)

```sh
cargo build --locked
target/debug/rocky check --config examples/rocky.toml
target/debug/rocky run --config examples/rocky.toml
```

In another terminal, request the example page and inspect the active configuration.

```sh
curl http://localhost:8080/
target/debug/rocky status --admin-socket .rocky/admin.sock
```

After editing the configuration, apply it through the admin socket.

```sh
target/debug/rocky reload --admin-socket .rocky/admin.sock
```

`check` reads required files without binding sockets or contacting upstreams or an ACME issuer. A rejected reload reports the active generation and leaves it serving. `SIGINT` and `SIGTERM` drain admitted work before exit. The admin socket is private to the daemon user and root. An adjacent lock protects recovery of its socket path after a crash.

## Configuration

The TOML file uses `schema_version = 1`. Relative file paths resolve from the configuration directory. A site lists the listener names on which it can be selected. Its routes use normalized path prefixes and choose exactly one of `static_root` and `upstream`.

| Setting | Purpose |
| --- | --- |
| `listeners[].protocols` | Enable `http1` for HTTP/1.x, `h2` for HTTP/2 over TLS, and `h3` for HTTP/3 over QUIC. `h2` and `h3` require `tls = true`. |
| `listeners[].default_site` | Select the site for hostless HTTP/1.0 and for TLS clients without SNI. |
| `listeners[].trusted_proxies` | Accept `Forwarded` chains from the specified proxy CIDRs. Leave empty to use the socket peer. |
| `sites[].public_https_port` and `sites[].public_quic_port` | Override inferred public ports when a gateway remaps them. |
| `sites[].routes[].index` | Serve a directory index using this filename. The default is `index.html`. An empty string disables indexes. |
| `sites[].routes[].rate_limit` | Set `requests_per_second`, `burst`, and `max_clients` for the route's per-client token buckets. |
| `upstreams.<name>` | Declare `endpoints` with origin URLs, optional `weight` and `max_connections`, and pool `protocol` of `h1` or `h2`. Set `health_path` for active probes or `trust_roots` for an HTTPS origin with a private CA. |
| `streams[]` | Give a TCP relay a `name`, `bind` address, and `upstream` host and port. `connect_timeout`, `idle_timeout`, and `max_connections` are configurable. |

For example, insert this route in a site and declare its upstream pool in the same file.

```toml
[[sites.routes]]
name = "api"
path_prefix = "/api"
upstream = "app"

[sites.routes.rate_limit]
requests_per_second = 20
burst = 40
max_clients = 10000

[upstreams.app]
protocol = "h1"
health_path = "/health"
endpoints = [
  { url = "http://127.0.0.1:9001", weight = 2 },
  { url = "http://127.0.0.1:9002", weight = 1 },
]
```

For manual HTTPS, put `tls = "manual"`, `certificate = "chain.pem"`, and `key = "key.pem"` in the site. Give the daemon access to the key through a private file and directory. Keep keys and the state directory outside document roots.

For automatic HTTPS, set the site's `tls = "acme"` and assign both a TLS listener and a plaintext HTTP/1.x listener. In `[acme]`, supply `directory_url`, `contact`, and `accept_terms = true`. The hostname must reach the plaintext listener on public TCP port 80 for HTTP-01. Set `redirect_http = true` on the site to redirect ordinary HTTP traffic once a certificate is ready. Serve the ACME challenge on HTTP while the certificate is pending. [ACME HTTP-01](https://www.rfc-editor.org/rfc/rfc8555.html#section-8.3)

Resource limits are configurable under `[limits]`, including `max_connections`, `max_requests`, `max_streams_per_connection`, `max_header_bytes`, `max_body_bytes`, `max_buffer_bytes`, and `max_file_operations`. Listener `max_connections` applies across its enabled transports. `handshake_timeout` and `request_head_timeout` default to 10 seconds. `body_idle_timeout` and the top-level `drain_timeout` default to 30 seconds. Durations are strings such as `"500ms"`, `"10s"`, or `"5m"`.

When an abandoned HTTP/2 upload stays blocked on upstream flow control through its body idle deadline, Rocky retires the upstream connection. Other exchanges sharing that connection can be interrupted.

## Verification

```sh
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

The socket tests run the daemon with loopback HTTP origins, TLS clients, a QUIC client, and a TCP echo server. To exercise issuance, live renewal, and restart recovery against a local issuer, build Rocky and provide a Pebble executable. The harness uses Python 3 and OpenSSL to make temporary credentials. [Pebble](https://github.com/letsencrypt/pebble)

```sh
python3 tests/acme_pebble.py --pebble /path/to/pebble --crash-after-finalize
```
