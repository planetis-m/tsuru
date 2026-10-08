# Hashi and Tsuru WebSocket implementation

| Choice | Hashi | Tsuru |
| --- | --- | --- |
| Delivered payload | `WsMessage.data: string` | `Message.data: string` |
| Parsed frame payload | `Frame.payload: string` | `Frame.payload: string` |
| Text send | `wsSend(string, binary = false)` | `send(string, binary = false)` |
| Binary send | String with `binary = true`, or `seq[byte]` with binary default | Same overloads and defaults |
| Read storage | Connection-owned `array[4096, byte]` | Same |
| Unconsumed wire bytes | Connection-owned string; consume each parsed prefix in place | Same; no separate consumed-offset state |
| Fragment storage | One protocol state owning the unfinished message string | Same |
| Send storage | Reusable `seq[byte]`, grown to the largest header plus payload | Same; payload masked after copying |
| Data writes | Coalesce header and payload; offer all remaining bytes; retry partial writes | Same |
| Small-message latency | `TCP_NODELAY` enabled by default | Enabled on connected sockets |
| Mask implementation | Private aligned 64-bit XOR loop with byte tail; byte fallback on big endian | Same word loop, with an alignment prefix for client headers |
| String bulk access | `readRawData`, `beginStore`, `endStore` | Same |
| Default receive limits | 64 MiB for frames and assembled messages | 64 MiB for both, configured by `maxMessage` |
| Peer text validation | Strict RFC 3629 after message assembly | Same |
| Outgoing payloads | Caller supplies valid text and control payloads | Same; no outgoing UTF-8 scan or receive-limit check |
| Control frames | Immediate ping/pong and close handling, including between fragments | Same |
| Extended lengths | Accept non-minimal encodings; reject oversized lengths before allocation | Same |

## Module responsibilities

| Hashi | Tsuru | Responsibility |
| --- | --- | --- |
| [`ws/frame`](../../hashi/src/hashi/ws/frame.nim) | [`frame`](../src/tsuru/frame.nim) | Frame headers, parsing and mask kernel |
| [`ws/protocol`](../../hashi/src/hashi/ws/protocol.nim) | [`protocol`](../src/tsuru/protocol.nim) | Fragment assembly, text validation and close decisions |
| [`ws/session`](../../hashi/src/hashi/ws/session.nim) and [`ws/session_io`](../../hashi/src/hashi/ws/session_io.nim) | [`tsuru`](../src/tsuru.nim) | Connection state and passive operations |
| [`buffer`](../../hashi/src/hashi/buffer.nim) | [`internal/buffer`](../src/tsuru/internal/buffer.nim) | Bulk string and byte-buffer operations |
| Server connection and upgrade driver | [`handshake`](../src/tsuru/handshake.nim), [`internal/transport`](../src/tsuru/internal/transport.nim) | HTTP upgrade and socket lifetime |

Tsuru keeps its connection fields private in the module that drives them.
The pure codec and protocol modules perform no socket operations. Transport
owns the descriptor and optional TLS resources; the connection owns wire bytes,
fragment state and the recorded close result. Socket and OpenSSL declarations
live in `internal/net` and `internal/tls`.

## Differences

Tsuru is a sequential client. It masks every outgoing frame with a fresh key
and rejects masked server frames; Hashi receives masked client frames and sends
unmasked frames. Tsuru checks the server's HTTP upgrade response and verifies
TLS certificates when TLS is enabled.

Hashi supports server handler registration, output queues, write guards,
nonblocking peek/skip, keepalive clocks and server telemetry. Tsuru gives one
task ownership of a connection, with an absolute deadline for each operation.
It does not need the corresponding queue, lock or registry state.

Tsuru preserves and echoes a valid peer close payload, including its status
and reason, and records why the connection ended. Hashi's protocol action
normalizes valid peer closes to 1000. Tsuru also accepts close statuses
1012–1014; Hashi's allowlist stops at 1011.

Both parsers require a valid start offset and nonnegative limit from the caller.
Tsuru's message limit covers both single-frame and fragmented messages; Hashi
exposes separate frame and assembly limits. Peer lengths are checked before
allocation. Outgoing application payloads are not revalidated.
