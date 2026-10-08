# Verification

Tested on Linux x86-64 with Nimony 0.6.3, GCC, Python 3.14 and OpenSSL.

| Configuration | Result |
| --- | --- |
| Debug, TLS, AddressSanitizer + UndefinedBehaviorSanitizer | Unit/fuzz and 26 network fixtures passed |
| Release, plain | Unit/fuzz, 21 network fixtures and unsupported-TLS check passed |
| Danger, TLS | Unit/fuzz and 26 network fixtures passed |

The independent Python fixtures exercise actual TCP and TLS connections and
decode client masking without using this library's codec. Plain tests cover
empty/short/extended-length text, binary bytes, automatic pongs, fragmented
UTF-8, bytewise frame delivery, an upgrade and frame in one write, subprotocols,
custom headers, explicit/empty/abnormal closes, malformed frames and text,
message limits, handshake/read/write/close deadlines, automatic descriptor
release, localhost DNS, and IPv6 literals. The plain build also checks that
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
