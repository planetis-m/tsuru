# API contracts

`import tsuru` exposes the application API. `tsuru/protocol` contains the
independent codec and state machine; `tsuru/handshake` contains URI parsing and
upgrade validation.

`buildRequest` expects the endpoint returned by `parseEndpoint` and a base64 nonce.
`handleFrame` expects a frame accepted by `parseFrame`.

A `WebSocket` is a reference handle: aliases refer to the same connection.
Use it from one owning task, one operation at a time. No application locks are
needed when each task owns its own connection. Do not abort a connection from
another task while an operation is suspended. The handle releases its transport
when its last reference goes away; explicit `abort` gives deterministic cleanup.
The library never shuts down the shared worker pool.

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
