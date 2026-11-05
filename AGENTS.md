# Working on Tsuru

## Language and contracts

This is a Nimony library. Read installed stdlib declarations before using them.
Read [runtime](doc/runtime.md), [WebSocket](doc/api.md) and [HTTP](doc/http.md)
for public contracts.

WebSocket setup raises ErrorCode. Live sends return bool, receive returns
Opt[Message], and close returns a terminal Message. Receive expiry preserves
the connection and partial state.

HTTP operations raise ErrorCode; failures during an exchange release the
connection. Connect and request take explicit absolute deadlines. Body reads
inherit that instant and may tighten it, never renew it.

## Module ownership

| Module | Responsibility |
| --- | --- |
| `tsuru/websocket` | Public: WebSocket options, connection state and passive operations |
| `tsuru/httpclient` | Public: request deadlines, keep-alive and body sequencing |
| `tsuru/internal/frame` | Wire codec and masking |
| `tsuru/internal/protocol` | Receive progress, message assembly, UTF-8 and close decisions |
| `tsuru/internal/handshake` | Opening requests and HTTP upgrade validation |
| `tsuru/internal/http` | Shared `Header`/`HttpResponse`, pure HTTP heads and request serialization |
| `tsuru/internal/endpoint` | Shared URL parsing |
| `tsuru/internal/head` | One-pass response head tokenizer for HTTP and the upgrade |
| `tsuru/internal/net`, `tsuru/internal/tls` | Socket and OpenSSL declarations |
| `tsuru/internal/transport` | Resources and passive I/O |
| `tsuru/internal/buffer` | Bulk string operations |
| `tsuru/internal/input` | Read-ahead input shared by both clients |

Only `tsuru/websocket` and `tsuru/httpclient` are public; both re-export the
shared `Header`, `HttpResponse`, `header` and `Deadline`. Everything under
`internal/` may change freely; tests import it directly.
Keep pure protocol decisions independent of socket operations. Source comments
describe current contracts and invariants.

## Ownership and I/O

Each connection belongs to one task. Do not introduce concurrent access to an
OpenSSL session or bypass certificate verification. Concurrent send during a
parked recv is unsupported; the documented pattern is the single-owner pump in
`examples/pump.nim`. Do not add locks. The transport is move-only;
public connections are reference handles. Custom ownership hooks belong only
on resources the compiler cannot release.

Start parking call chains with `submit(delay(task(...)))`; every caller in the
chain must be passive. Scheduler entry points take owned values. Borrowed
parameters may span a normal passive call. The application owns pool shutdown.

Use strings for owned wire buffers and payloads, and byte sequences when they
avoid caller conversions. Use openArray views for byte operations and
beginStore/endStore for writable strings. Keep raw pointers at FFI and bulk-store
boundaries.

Check peer lengths before allocating or indexing. Trust outgoing payloads and
document their preconditions. Validate incoming framing, text and upgrade
responses. Every outgoing WebSocket frame needs a fresh random mask.

Preserve one absolute deadline across fragments, controls and partial writes.
Keep pending control bytes and their cursor intact across receive expiry;
finish them before encoding another frame. Application write failure releases
the connection. WebSocket close discards messages while awaiting the peer until
its deadline (one second by default); abort releases immediately.

Keep connection state private and retained-memory costs explicit in API docs.

## Checks

Build and check with `tests/run --network`. Test TLS changes with
`tests/run --tls --network` and resource/I/O changes with
`tests/run --tls --asan --network`. Release and danger configurations must keep
protocol checks active; testkit assertions remain enabled in danger.

Use `tests/hashi.py --compat` for optional integration against the sibling
server. It uses a temporary copy; do not change that checkout.
Measure performance changes with `bench/` (see verification) against the
previous build, interleaved, and with cachegrind for per-byte paths.
