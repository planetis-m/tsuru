# API contracts

| Import | Responsibility |
| --- | --- |
| `tsuru` | Connection handles, options, messages and passive operations |
| `tsuru/frame` | Pure frame parsing, headers and masking |
| `tsuru/protocol` | Message assembly, UTF-8 and close handling; re-exports the codec |
| `tsuru/handshake` | URL parsing, request construction and upgrade validation |

Application code normally needs only `import tsuru`.

`buildRequest` expects the endpoint returned by `parseEndpoint` and a base64 nonce.
`handleFrame` expects a frame accepted by `parseFrame`.
`frameHeader` includes the four-byte mask key; `maskInto` applies that key to
payload chunks, with `offset` measured from the start of the frame payload.
Its destination is a mutable `openArray[char]` of at least `source.len` bytes.
Use a fresh
cryptographic mask for each frame. `encodeFrame` builds a complete wire string
when a standalone encoded frame is needed.

A `WebSocket` is a reference handle: aliases refer to the same connection.
Use it from one owning task, one operation at a time. No application locks are
needed when each task owns its own connection. Do not abort a connection from
another task while an operation is suspended. The handle releases its transport
when its last reference goes away; explicit `abort` gives deterministic cleanup.
The library never shuts down the shared worker pool.

`send(string, binary = false, dl)` sends text by default; `binary = true` sends
the string's bytes unchanged as binary. `send(seq[byte], dl)` always sends a
binary message and avoids a sequence-to-string conversion. Both send a single
frame using bounded masked chunks, retaining only an 8 KiB scratch buffer in
addition to the caller's payload. Splitting a write into chunks does not split
the WebSocket message. The header shares the first chunk with the payload.

`recv` releases consumed wire data before returning a message and retains any
following frames for the next call. Returned payloads own their data.

Socket calls, address layouts, OpenSSL bindings and bulk buffer operations live
in `tsuru/internal`. The transport owns descriptors and TLS handles; the client
owns unconsumed wire bytes, fragment state and the recorded close outcome.

A default `WebSocket()` is closed and owns no descriptor. Create live connections
with `connectWebSocket`.

`WebSocketOptions` must be constructed with `initWebSocketOptions`; an empty
object has invalid zero limits. The library validates these fields at connect:

- `maxMessage`: positive maximum received or sent message bytes.
- `timeoutMs`: positive per-operation time budget.
- `protocols`: distinct HTTP tokens; the server may select one or none.
- `origin` and `headers`: control characters and protected fields are rejected.
- `caFile`: optional PEM trust file when TLS is enabled.

Each operation accepts an absolute `Deadline` as `dl`. Its effective deadline
is the earlier of that instant and `afterMs(options.timeoutMs)`. Deadlines start
fresh for each call, including preparation and buffered receive processing.
An expired deadline closes a live connection even when the complete message is
already buffered. The close handshake is also capped at five seconds.

For a quiet connection, choose a receive budget that fits the application's
expected idle periods. Incoming pings and pongs do not restart that budget.
`recv` may suspend while reading fragments or writing a pong or close reply;
`send`, `ping`, `close` and `connectWebSocket` may also suspend. `abort`, `state`,
`open` and `protocol` never suspend. Calling `ping` does not start a background
reader; pong replies are consumed during subsequent receives.

The [receive example](../examples/receive.nim) combines authentication,
subprotocol negotiation, optional custom CA trust and a five-minute receive
budget. Its connection setup has a separate ten-second deadline.

`recv` returns `Message(kind, data, code)`. `code` is meaningful for `wmClose`.
Empty text/binary messages are normal messages, distinct from closure. After a
close, repeated receives return the recorded result. `closeSource` distinguishes
`csPeer`, `csEof`, `csLocal`, `csProtocolError` and `csTransportError`. Only `csPeer`
reports a close received from the peer. A local protocol failure records the
locally selected close code; abort, EOF and transport failure use 1006.
An idempotent abort preserves an already recorded result.

| ErrorCode | Typical cause | Connection effect |
| --- | --- | --- |
| `ValueError` | Invalid URL/options; bad text/close arguments | No connection created, or live connection retained |
| `ValueError` | Rejected upgrade or malformed peer frame/text | Closed; protocol close attempted for frame errors |
| `ContentTooLong` | Oversized outgoing message/control payload | Retained |
| `ContentTooLong` | Oversized handshake, peer frame or fragmented message | Closed; frame/message violations attempt close 1009 |
| `BadOperation` | Send or ping after closing | Remains closed |
| `TimeoutError` | Deadline exhausted | Closed |
| `EndOfStreamError` | Peer disappeared during HTTP upgrade | Closed |
| `IOError` | Socket, randomness, trust-file or TLS I/O failure | Closed if a connection was created |
| `PermissionDenied` | TLS negotiation/certificate verification rejected | Closed |
| `NameNotFound` | DNS name not found | No established connection |
| `UnimplementedOperation` | `wss://` without `-d:tsuruTls` | No connection created |

A normal transport EOF during `recv` produces `wmClose` with code 1006.
Malformed close payloads and frames trigger close 1002; malformed UTF-8 triggers
1007. Ping and close replies use fresh masks from Linux `getrandom`, as do all
application frames. Failure to obtain randomness fails the operation.

The HTTP response must be HTTP/1.1 status 101 with the required upgrade tokens
and the exact accept key. Duplicate accept/subprotocol fields, unsolicited
extensions and unoffered subprotocols are rejected. Bytes following the HTTP
head are retained for the frame parser, including an immediate first message.

Timeouts wait on socket readiness, not on kernel reads into application memory.
A timed-out operation therefore cannot leave an outstanding read writing into
its former buffer. Plain sends and the optional OpenSSL BIO suppress SIGPIPE
per send without changing the application's signal handlers.
