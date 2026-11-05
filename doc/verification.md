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
| Debug, TLS, AddressSanitizer + UndefinedBehaviorSanitizer | Unit/fuzz and 88 network fixtures passed |
| Release, plain | Unit/fuzz, 65 network fixtures and setup-expiry/unsupported-TLS checks passed |
| Danger, TLS | Unit/fuzz and 88 network fixtures passed |

The wire fixtures use independent Python encoders and decoders. Unit tests
cover pure codecs and HTTP heads. A shared-type test imports both clients together
and checks shared header and deadline identities plus overloaded operations. A seeded test supplies 220,000 deterministic inputs per run: random
bytes for the frame, UTF-8, URL, HTTP head and WebSocket upgrade parsers,
mutated valid heads, and mostly-ASCII text whose UTF-8 verdict must match
`std/unicode.validateUtf8` at every alignment. The client's receive step
(`protocol.feed`) is driven with random bytes and with generated, mutated and
truncated frame sequences, split into random read sizes with and without
direct payload reads; its outcomes must match an independent reference
assembler.
Test assertions and peer-protocol checks remain active in danger builds.

## WebSocket coverage

The WebSocket runner has 39 TCP fixtures (including the pump example) and 12 additional TLS fixtures.
The runners and examples import `tsuru/websocket` and `tsuru/httpclient`;
unit tests import the internal codecs directly. The WebSocket runner also runs
`examples/pump` against the echo fixture: four tasks queue 100 messages that
one owning task sends between 10 ms receive slices.
Coverage includes empty and extended-length payloads, binary sequences, masking,
fragmented UTF-8, bytewise delivery, subprotocols, custom headers, malformed
frames/text, message limits, close outcomes, DNS and IPv6 literals.

| Scenario | Fixture |
| --- | --- |
| Receive expiry keeps the connection usable | `read-timeout` |
| Buffered input survives expiry | `buffered-timeout` |
| Partial frames and fragmented messages resume | `partial-timeout` |
| Expiry inside a large payload resumes; large fragments go straight into the message | `large-partial-timeout` |
| Control traffic does not restart deadlines | `control-timeout` |
| Paused automatic pongs resume | `control-backpressure`: 50,000 pings and stalled writes |
| Replies, events and late replies share one stream | `commands`: 33 active ids, one retired id and reverse-order replies |
| Large payloads work in both directions | `large`: 20 MiB text round trip |
| Teardown is bounded | `close-timeout`: 100 ms deadline, measured under 500 ms |
| Close waits up to its deadline (one second by default) | `close-slow`: peer replies after 400 ms, after a second idle |
| Invalid ping and close arguments send nothing and release | `ping-guard`, `close-guard`, `close-reason-guard` |
| Terminal paths release descriptors | `resources`: 15 connections with stable descriptor counts |

Other closing fixtures check interleaved messages and pings, peer code/reason,
EOF, protocol failure, immediate abort and absence of duplicate Close frames.
Resource paths include rejected upgrades, resets and setup expiry.

TLS fixtures cover trusted IP/DNS certificates, SNI, untrusted and wrong-host
rejection, stalled writes, receive expiry, fragment resumption, controls,
large payloads, a slow close, and a protocol failure that must send its Close
frame and then close_notify. Plain builds also check secure-URL rejection before TCP setup.

## HTTP coverage

The HTTP runner has 26 TCP fixtures and 11 additional TLS fixtures.

| Area | Coverage |
| --- | --- |
| Heads | Informational responses, duplicate fields, HEAD/204/304 and oversized heads |
| Bodies | Content-Length, EOF, bytewise chunks, extensions, discarded trailers (including obs-fold), chunks larger than the read buffer, and truncated messages |
| Reuse | HTTP/1.1 keep-alive, HTTP/1.0 persistence, rejection of an unread prior body and no reuse after unrequested bytes |
| Limits | Fixed, chunked and EOF body limits; malformed chunk sizes and chunk terminators; trailer count |
| Deadlines | Head/body expiry, expired requests and preservation of the original body deadline |
| Large payloads | 21 MiB binary request/response round trip |
| Resources | 17 connections with stable descriptor counts across completion, errors, expiry and close |
| TLS | Verified keep-alive with SNI, chunks, large bodies, expiry, abrupt shutdown and certificate rejection |

Setup probes check expired deadlines and HTTPS rejection without TLS.
Pure head tests cover status lines, field syntax, bare-LF heads, limits,
ambiguous framing, persistence tokens and request-header injection.

## Optional integration server

```sh
python3 tests/hashi.py --compat
```

This exercises text, binary, ping/pong and close using a temporary copy of the
sibling Hashi echo server. The checkout is unchanged. Port 8080 must be available.
To select a compiler for its original sources, set `HASHI_NIMONY` and omit
`--compat`.

## Benchmarks

`bench/` holds a loopback C peer (`server.c`: precomputed HTTP responses and a
WebSocket echo), a client (`bench.nim`) and `compare.py`, which interleaves
runs of several client builds and reports median time per operation:

```sh
cc -O2 -pthread -o build/bench-server bench/server.c -lcrypto
nimony c -d:release -o:build/bench bench/bench.nim
python3 bench/compare.py build/bench-server build/bench
```

Modes: `http-small` (16 B body), `http-large` (8 MiB, `readAll`),
`http-large-stream` (8 MiB, 64 KiB `readBody`), `http-chunked` (1 MiB in
4 KiB chunks), `ws-small` (16 B echo), `ws-large` (1 MiB echo) and `ws-frag`
(64 KiB echoed as 64 fragments). For instruction counts, run one mode under
`valgrind --tool=cachegrind`; `bench/irsum.py` separates the thread pool's
timing-dependent share.

## Coverage limits

Coverage excludes the Autobahn conformance suite.
Seeded malformed-input checks are deterministic, without coverage-guided fuzzing.
