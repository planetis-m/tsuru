# Verification

## Run the checks

Requires a C compiler and Python 3. TLS fixtures also use OpenSSL headers,
libraries and the `openssl` command to create temporary test certificates.
All network fixtures use loopback and require no Python packages.

```sh
tests/run                          # Unit tests, seeded malformed inputs and example builds
tests/run --network                # TCP fixtures
tests/run --tls --network          # TCP and TLS fixtures
tests/run --release --network
tests/run --danger --tls --network
tests/run --tls --asan --network   # AddressSanitizer and UndefinedBehaviorSanitizer
```

Set `NIMONY=/path/to/nimony` to select a compiler.

## Checked configurations

Linux x86-64, Nimony 0.6.3, GCC, Python 3.14 and OpenSSL.

| Configuration | Result |
| --- | --- |
| Debug, TLS, AddressSanitizer + UndefinedBehaviorSanitizer | Unit/fuzz and 73 network fixtures passed |
| Release, plain | Unit/fuzz, 56 network fixtures and setup-expiry/unsupported-TLS checks passed |
| Danger, TLS | Unit/fuzz and 73 network fixtures passed |

The wire fixtures use independent Python encoders and decoders. Unit tests
cover pure codecs and HTTP heads. A facade test imports both clients together
with `tsuru` and checks shared header and deadline identities plus overloaded
operations. A seeded test supplies 100,000 malformed
inputs to the frame, UTF-8, URL and WebSocket upgrade parsers per run.
Test assertions and peer-protocol checks remain active in danger builds.

## WebSocket coverage

The WebSocket runner has 33 TCP fixtures and nine additional TLS fixtures.
It imports the `tsuru` facade, while the HTTP runner and the examples use
explicit `tsuru/websocket` and `tsuru/httpclient` imports.
Coverage includes empty and extended-length payloads, binary sequences, masking,
fragmented UTF-8, bytewise delivery, subprotocols, custom headers, malformed
frames/text, message limits, close outcomes, DNS and IPv6 literals.

| Scenario | Fixture |
| --- | --- |
| Receive expiry keeps the connection usable | `read-timeout` |
| Buffered input survives expiry | `buffered-timeout` |
| Partial frames and fragmented messages resume | `partial-timeout` |
| Control traffic does not restart deadlines | `control-timeout` |
| Paused automatic pongs resume | `control-backpressure`: 50,000 pings and stalled writes |
| Replies, events and late replies share one stream | `commands`: 33 active ids, one retired id and reverse-order replies |
| Large payloads work in both directions | `large`: 20 MiB text round trip |
| Teardown is bounded | `close-timeout`: 100 ms deadline, measured under 500 ms |
| Terminal paths release descriptors | `resources`: 15 connections with stable descriptor counts |

Other closing fixtures check interleaved messages and pings, peer code/reason,
EOF, protocol failure, immediate abort and absence of duplicate Close frames.
Resource paths include rejected upgrades, resets and setup expiry.

TLS fixtures cover trusted IP/DNS certificates, SNI, untrusted and wrong-host
rejection, stalled writes, receive expiry, fragment resumption, controls and
large payloads. Plain builds also check secure-URL rejection before TCP setup.

## HTTP coverage

The HTTP runner has 23 TCP fixtures and eight additional TLS fixtures.

| Area | Coverage |
| --- | --- |
| Heads | Informational responses, duplicate fields, HEAD/204/304 and oversized heads |
| Bodies | Content-Length, EOF, bytewise chunks, extensions, trailers and truncated messages |
| Reuse | HTTP/1.1 keep-alive, HTTP/1.0 persistence and rejection of an unread prior body |
| Limits | Fixed, chunked and EOF body limits; malformed chunks and trailers |
| Deadlines | Head/body expiry, expired requests and preservation of the original body deadline |
| Large payloads | 21 MiB binary request/response round trip |
| Resources | 17 connections with stable descriptor counts across completion, errors, expiry and close |
| TLS | Verified keep-alive with SNI, chunks, large bodies, expiry, abrupt shutdown and certificate rejection |

Setup probes check expired deadlines and HTTPS rejection without TLS.
Pure head tests cover ambiguous framing and request-header injection.

## Optional integration server

```sh
python3 tests/hashi.py --compat
```

This exercises text, binary, ping/pong and close using a temporary copy of the
sibling Hashi echo server. The checkout is unchanged. Port 8080 must be available.
To select a compiler for its original sources, set `HASHI_NIMONY` and omit
`--compat`.

## Coverage limits

Coverage excludes the Autobahn conformance suite and performance benchmarks.
Seeded malformed-input checks are deterministic, without coverage-guided fuzzing.
