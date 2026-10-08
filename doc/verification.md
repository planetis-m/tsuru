# Verification

Local verification on 2026-10-08 used the installed Nimony 0.6.3 C backend,
Linux x86-64, GCC, Python 3.14, and system OpenSSL. This repository has no
runtime dependency on Hashi.

| Configuration | Result |
| --- | --- |
| Debug, TLS, AddressSanitizer + UndefinedBehaviorSanitizer | Unit/fuzz and 26 network fixtures passed |
| Release, plain | Unit/fuzz, 22 network fixtures and unsupported-TLS check passed |
| Release, TLS | Unit/fuzz and 26 network fixtures passed |
| Danger, plain | Unit/fuzz, 22 network fixtures and unsupported-TLS check passed |
| Danger, TLS | Unit/fuzz and 26 network fixtures passed |
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
trusted certificate for a different hostname. All fixtures use loopback.
The library and its C BIO were tested with AddressSanitizer and
UndefinedBehaviorSanitizer. Tests also run in release and danger modes;
protocol validation remains enabled.

The pure codec/handshake tests include the RFC accept-key and masking vectors,
length boundaries and malformed input. A seeded fuzz program supplies 100,000
cases to the frame, UTF-8, URL and HTTP upgrade parsers per run. This is a
deterministic malformed-input test, not a coverage-guided fuzz campaign.
The Autobahn client-role conformance suite has not been run.

## Hashi interoperability

The unmodified sibling Hashi does not build with the installed compiler:
Nimony now rejects accesses to several unsynchronized configuration globals
and Hashi's direct imported `errno` variable. Its CI pins a different compiler
commit, `1f232868e254eaefbbd825f86ffc97572da65416`.

`python3 tests/hashi.py --compat` successfully runs empty, small and large text
messages, binary bytes, ping/pong and a close handshake against its echo server.
It makes these compiler adaptations in a **temporary copy**:

- Add `{.feature: "assumeSync".}` to copied Hashi modules, accepting their
  existing synchronization assumptions for this interoperability test.
- Replace the imported `errno` variable with `std/posix/posix.errno()`.

Hashi's source checkout is untouched. This validates client/server wire
interoperability; it does not validate Hashi's concurrency or port it to the
new compiler. To test its original sources, supply a compatible server compiler
via `HASHI_NIMONY` and omit `--compat`. Port 8080 must be available.

## Compiler observations

Nimony 0.6.3 misgenerated C for non-passive raising functions returning values
when called directly inside this client's passive procedures. The client uses
small synchronous helpers with output parameters for those boundaries.
Nimony also dropped a raise nested inside `when` in a passive procedure;
TLS availability is now checked by a synchronous helper.

A bound error variable in the outer catch of the synchronous handshake test
produced an undeclared C variable in release mode; that catch reports a fixed
failure message instead. The passive application example still reports errors.

Builds emit an integer-to-pointer cast warning from Nimony's own generated
I/O backend C. The tested operations complete successfully; no sanitizer
diagnostics were emitted in the verified network runs.
