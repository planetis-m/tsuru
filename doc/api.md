# API contracts

| Import | Responsibility |
| --- | --- |
| `tsuru` | Connection handles, options, messages and passive operations |
| `tsuru/frame` | Pure frame parsing, headers and masking |
| `tsuru/protocol` | Message assembly, UTF-8 and close handling |
| `tsuru/handshake` | URL parsing, request construction and upgrade validation |

Application code normally needs only `import tsuru`.

`buildRequest` expects the endpoint returned by `parseEndpoint` and a base64 nonce.
`handleFrame` expects a frame accepted by `parseFrame`.
`parseFrame` expects `0 <= start <= data.len` and a nonnegative payload limit;
`handleFrame` expects a nonnegative message limit.
`frameHeader` includes the four-byte mask key. `encodeFrame` returns a complete
wire string; its `var string` overload reuses caller-owned storage and accepts
character or byte views. Its input must not alias the output string. Encoding
copies and masks the payload in one pass. Use a fresh cryptographic mask for
each frame.

A `WebSocket` is a reference handle: aliases refer to the same connection.
Use it from one owning task, one operation at a time. No application locks are
needed when each task owns its own connection. Do not abort a connection from
another task while an operation is suspended. The handle releases its transport
when its last reference goes away; explicit `abort` gives deterministic cleanup.
The library never shuts down the shared worker pool.

`send(string, binary = false, dl)` sends text by default; `binary = true` sends
the string's bytes unchanged as binary. `send(seq[byte], dl)` sends binary and
avoids a sequence-to-string conversion. Both send one frame, coalescing its
header and masked payload in a reusable connection-owned string. The buffer
grows to the largest frame sent and is released on closure. This retains a
wire copy in addition to the caller's payload. Small encoded frames can use
inline string storage.
Writes offer the whole remaining frame and retry only on partial writes or
socket backpressure.

Callers supply valid UTF-8 when sending text, ping payloads of at most 125 bytes,
and valid close codes with a UTF-8 reason of at most 123 bytes. Outgoing payloads
are not revalidated or constrained by the receive limit.

`recv` discards consumed wire bytes in place and retains following frames for
the next call. Its buffer capacity is reused until closure. Returned payloads
own their data.

Socket calls, address layouts, OpenSSL bindings and bulk buffer operations live
in `tsuru/internal`. The transport owns descriptors and TLS handles; the client
owns unconsumed wire bytes, fragment state and the recorded close outcome.
The encoder builds wire bytes without I/O. The protocol updates fragment state
and returns messages or control actions. The client owns connection-state
transitions and applies those actions; only the transport performs socket and
TLS operations.

A default `WebSocket()` is closed and owns no descriptor. Create live connections
with `connectWebSocket`.

`WebSocketOptions` must be constructed with `initWebSocketOptions`; an empty
object has invalid zero limits. The library validates these fields at connect:

- `maxMessage`: positive maximum received message bytes.
- `timeoutMs`: positive per-operation time budget.
- `protocols`: distinct HTTP tokens; the server may select one or none.
- `origin` and `headers`: control characters and protected fields are rejected.
- `caFile`: optional PEM trust file when TLS is enabled.

Each operation accepts an absolute `Deadline` as `dl`. Its effective deadline
is the earlier of that instant and `afterMs(options.timeoutMs)`. Deadlines start
fresh for each call, including preparation and buffered receive processing.
An expired deadline closes a live connection even when the complete message is
already buffered.

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
locally selected close code; a successful local close records its supplied code
and reason. Abort, EOF and transport failure use 1006. An idempotent abort
preserves an already recorded result.

`send` and `ping` return true after writing their frame, or false when already
closed or when a write fails. `close` writes its frame and releases the socket
without waiting for the peer's reply. It returns true on success or when already
closed, and false on write failure. Successful writes mean the transport accepted
the frame, not that the peer acknowledged it.

Live operations do not raise `ErrorCode`. Read failures and timeouts return
`wmClose` with code 1006 and `csTransportError`; write failures return false.
Both release the connection. Malformed peer frames and close payloads return
`wmClose` with code 1002, malformed UTF-8 with 1007, and exceeded receive limits
with 1009. These use `csProtocolError` and attempt a close frame before release.
If a peer close or protocol failure was already recorded, a failed close reply
preserves that outcome.

`connectWebSocket` raises `ErrorCode` on setup failure and releases any resources
it acquired:

| ErrorCode | Typical cause | Connection effect |
| --- | --- | --- |
| `ValueError` | Invalid URL/options or rejected upgrade | No established connection |
| `ContentTooLong` | Oversized HTTP upgrade response | Closed |
| `TimeoutError` | Setup deadline exhausted | Closed if a connection was created |
| `EndOfStreamError` | Peer disappeared during HTTP upgrade | Closed |
| `IOError` | Socket, randomness, trust-file or TLS I/O failure | Closed if a connection was created |
| `PermissionDenied` | TLS negotiation/certificate verification rejected | Closed |
| `NameNotFound` | DNS name not found | No established connection |
| `UnimplementedOperation` | `wss://` without `-d:tsuruTls` | No connection created |

A normal transport EOF during `recv` produces `wmClose` with code 1006 and
`csEof`. Ping and close replies use fresh masks from Linux `getrandom`, as do all
application frames. Failure to obtain randomness fails the write and releases
the connection.

The HTTP response must be HTTP/1.1 status 101 with the required upgrade tokens
and the exact accept key. Duplicate accept/subprotocol fields, unsolicited
extensions and unoffered subprotocols are rejected. Bytes following the HTTP
head are retained for the frame parser, including an immediate first message.

Timeouts wait on socket readiness, not on kernel reads into application memory.
A timed-out operation therefore cannot leave an outstanding read writing into
its former buffer. Plain sends and the optional OpenSSL BIO suppress SIGPIPE
per send without changing the application's signal handlers.
