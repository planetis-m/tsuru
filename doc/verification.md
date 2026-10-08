# Verification

Tested on Linux x86-64 with Nimony 0.6.3, GCC, Python 3.14 and OpenSSL.

| Configuration | Result |
| --- | --- |
| Debug, TLS, AddressSanitizer + UndefinedBehaviorSanitizer | Unit/fuzz and 42 network fixtures passed |
| Release, plain | Unit/fuzz, 33 network fixtures and unsupported-TLS check passed |
| Danger, TLS | Unit/fuzz and 42 network fixtures passed |

The independent Python fixtures exercise actual TCP and TLS connections and
decode client masking without using this library's codec. Plain tests cover
empty/short/extended-length text, binary bytes, automatic pongs, fragmented
UTF-8, bytewise frame delivery, an upgrade and frame in one write, subprotocols,
custom headers, explicit/empty/abnormal closes, malformed frames and text,
message limits, handshake/send/receive/close deadlines, closing handshakes
with interleaved messages and pings, immediate abort, peer close reasons,
EOF and protocol failure during close, absence of duplicate Close frames,
boolean write results, recorded receive outcomes, automatic descriptor release,
localhost DNS, and IPv6 literals. The plain build also checks that
`wss://` raises `UnimplementedOperation` before attempting TCP.

TLS tests cover round trips with a trusted temporary certificate for an IP and
a DNS name, SNI, rejection of an untrusted certificate, and rejection of a
trusted certificate for a different hostname, plus a send deadline while a
TLS peer stops reading. Binary sequence round trips cover extended lengths and
send-buffer reuse. Upgrade fixtures include consecutive messages to
check that receiving one preserves the next. All fixtures use loopback.
The library and its C BIO were tested with AddressSanitizer and
UndefinedBehaviorSanitizer. Tests also run in release and danger modes;
protocol validation remains enabled.

## Long-lived control connections

| Scenario | Fixture |
| --- | --- |
| Idle receive expiry keeps the connection usable | `read-timeout`: send after expiry, then receive normally |
| Buffered input survives an expired deadline | `buffered-timeout` |
| Fragments and partial frames survive expiry | `partial-timeout`: split UTF-8, ping, partial continuation, then resume |
| Controls do not restart the receive deadline | `control-timeout`: pings outlast the first deadline |
| Stalled automatic output resumes safely | `control-backpressure`: 50,000 pings, stalled pong writes, then an application send |
| Outstanding commands and late replies stay in the application | `commands`: 33 active ids, one retired id, reverse-order replies and interleaved events |
| Large text payloads work in both directions | `large`: 20 MiB round trip with a 64 MiB receive limit |
| Peer closure preserves terminal information | `fragments` and `commands`: peer code, reason and source |
| Malformed frames terminate and release | Protocol-error and size-limit fixtures |
| An unresponsive peer cannot hold teardown open | `close-timeout`: 100 ms caller deadline, measured under 500 ms |
| Descriptors are released on terminal paths | `resources`: 43 connections in one client process with stable `/proc/self/fd` counts |

The repeated-connect fixture covers peer close, rejected upgrade, malformed
frames, transport reset, close expiry, abort and setup expiry. Ordinary receive
expiry deliberately retains the descriptor. TLS also exercises receive expiry,
fragment resumption, interleaved controls and the 20 MiB text round trip.

The pure codec/handshake tests include the RFC accept-key and masking vectors,
length boundaries and malformed input. A seeded fuzz program supplies 100,000
cases to the frame, UTF-8, URL and HTTP upgrade parsers per run. This is a
deterministic malformed-input test, not a coverage-guided fuzz campaign.
The Autobahn client-role conformance suite has not been run. The fixtures test
correctness and resource cleanup; they do not establish throughput or latency.

## Optional integration server

Run `python3 tests/hashi.py --compat` to exercise text, binary, ping/pong and
close against a temporary copy of the sibling Hashi echo server. This does not
modify the checkout. To use another compiler for its original sources, set
`HASHI_NIMONY` and omit `--compat`. Port 8080 must be available.
