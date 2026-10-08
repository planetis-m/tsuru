# Verification

Tested on Linux x86-64 with Nimony 0.6.3, GCC, Python 3.14 and OpenSSL.

| Configuration | Result |
| --- | --- |
| Debug, TLS, AddressSanitizer + UndefinedBehaviorSanitizer | Unit/fuzz and 27 network fixtures passed |
| Release, plain | Unit/fuzz, 22 network fixtures and unsupported-TLS check passed |
| Release, TLS | Unit/fuzz and 27 network fixtures passed |
| Danger, plain | Unit/fuzz, 22 network fixtures and unsupported-TLS check passed |
| Danger, TLS | Unit/fuzz and 27 network fixtures passed |
| Hashi temporary compatibility copy, fresh caches | Echo interoperability passed |

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
TLS peer stops reading. Binary sequence round trips cross masking-buffer and
extended-length boundaries. Upgrade fixtures include consecutive messages to
check that receiving one preserves the next. All fixtures use loopback.
The library and its C BIO were tested with AddressSanitizer and
UndefinedBehaviorSanitizer. Tests also run in release and danger modes;
protocol validation remains enabled.

The pure codec/handshake tests include the RFC accept-key and masking vectors,
length boundaries and malformed input. A seeded fuzz program supplies 100,000
cases to the frame, UTF-8, URL and HTTP upgrade parsers per run. This is a
deterministic malformed-input test, not a coverage-guided fuzz campaign.
The Autobahn client-role conformance suite has not been run.

## Hashi interoperability

Run `python3 tests/hashi.py --compat` to test text, binary, ping/pong and close
against Hashi's echo server. The runner adapts a temporary source copy:

- Add `{.feature: "assumeSync".}` to copied Hashi modules, accepting their
  existing synchronization assumptions for this interoperability test.
- Replace the imported `errno` variable with `std/posix/posix.errno()`.

The test covers wire interoperability, not Hashi's concurrency. To test the
original sources, set `HASHI_NIMONY` to a compatible compiler and omit `--compat`.
Port 8080 must be available.
