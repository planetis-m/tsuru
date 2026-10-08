# API contracts

| Import | Responsibility |
| --- | --- |
| `tsuru` | Connection handles, options, messages and passive operations |
| `tsuru/frame` | Pure frame parsing, headers and masking |
| `tsuru/protocol` | Message assembly, UTF-8 and close handling |
| `tsuru/handshake` | URL parsing, request construction and upgrade validation |

Application code uses `import tsuru` and `import std/opt` to match receive results.

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
Start a parking call chain with `submit(delay(task(...)))` on the worker pool.
Every caller in that chain must be passive so its local values survive suspension.
Regular helpers may prepare buffers or validate data without parking.

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
owns unconsumed wire bytes, fragment state, pending control output and the
recorded close outcome. An output cursor records how many encoded bytes were
written; the encoded string remains unchanged until that frame is complete.
The encoder builds wire bytes without I/O. The protocol updates fragment state
and returns messages or control actions. The client owns connection-state
transitions and applies those actions; only the transport performs socket and
TLS operations.

A default `WebSocket()` is closed and owns no descriptor. Create live connections
with `connectWebSocket`. Receiving on a default handle returns `Some(wmClose)` with
1006, an empty reason and `csLocal`: the handle has no live connection. This does
not imply a peer exchange or a failed connection attempt. Setup failures are
reported by `connectWebSocket`.

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
Receive expiry returns `None` and keeps the connection open, including
when a message is partially assembled or a complete frame is already buffered.
Input and fragment state are preserved for the next call. A paused automatic
pong retains its wire bytes and output cursor; the next receive or send finishes
that frame before encoding another. Partial application sends cannot be retried
safely, so send/ping expiry releases the connection and returns false.
Close caps its I/O deadline at 250 ms and releases on expiry.

For a quiet connection, choose a receive budget that fits the application's
expected idle periods. Incoming pings and pongs do not restart that budget.
`recv` may suspend while reading fragments or writing a pong or close reply;
`send`, `ping`, `close` and `connectWebSocket` may also suspend.
`abort`, `state`, `open` and `protocol` never suspend. Calling `ping` does not start a background
reader; pong replies are consumed during subsequent receives.

The [receive example](../examples/receive.nim) combines authentication,
subprotocol negotiation, optional custom CA trust and a five-minute receive
budget. Its connection setup has a separate ten-second deadline.

`recv` returns `Opt[Message]` using Nimony's native `std/opt` sum type. Match it
with `case result`, `of Some(message)` and `of None()`; both cases are non-raising.
`Some` contains a complete text/binary message or terminal close, and `None`
means the receive deadline expired. `Message.code` is meaningful for `wmClose`.
Empty text/binary messages are normal messages, distinct from closure. After a
close, repeated receives return the recorded result. `closeSource` distinguishes
`csPeer`, `csEof`, `csLocal`, `csProtocolError`, `csTransportError` and `csTimeout`.
Only `csPeer` reports a close received from the peer. A local protocol failure records the
locally selected close code. A successful closing handshake records the peer's
code and reason. Abort, EOF, transport failure and timeout use 1006. An idempotent
abort preserves an already recorded result.

`None` is a nonterminal receive result. Continue sending or receiving on the
same connection with a new deadline. A single receive deadline covers buffered work, partial frames,
fragment assembly and interleaved controls; none restart it. Expiry does not
discard bytes or retire an application command. The application owns command
ids, outstanding-command tables, retirement and late-reply handling.
An already expired deadline returns `None` even when a complete frame is buffered;
input remains available to a later call. `afterMs(0)` is an expired deadline,
not a nonblocking polling operation.

`send` and `ping` return true after writing their frame. They return false if the
connection is closed, or a write fails. A write failure releases the connection;
the next receive returns its recorded terminal outcome. Successful writes mean
the transport accepted the frame, not that the peer acknowledged it.

`close` writes one Close frame and awaits the peer's Close frame. Its whole I/O
deadline is the earliest of 250 ms from the call, the
configured operation budget, and `dl`. It discards application messages while
waiting, answers pings, and releases on every outcome. It returns a terminal
`Message` directly. `csPeer` reports the peer's code and reason;
`csTimeout`, `csEof`, `csProtocolError` and `csTransportError` identify why the
exchange ended. Calling close on a closed handle returns the recorded outcome.
Repeated calls do not send another frame. Use `abort` for immediate teardown.

Public state is `wsOpen` or `wsClosed`. One private connection phase records
whether a Close frame was sent, preventing a second Close reply. The owning task
remains inside `close` until release, and close owns receive processing until
termination. To await a peer-initiated close, continue calling `recv`, matching
`Some(message)` and `None()` under the application's absolute deadline policy.

Teardown requires one close call or one abort call. No application drain loop,
background task or worker-pool join is needed. The library does not correlate
requests and replies or introduce locks, threads, queues or callbacks.

Live operations do not raise `ErrorCode`. Read I/O failures return `Some(wmClose)`
with code 1006 and `csTransportError`. Send and close expiry record
code 1006 and `csTimeout`; ordinary receive expiry returns `None`.
Write failures return false. Terminal outcomes release the connection; a receive
expiry retains its descriptor deliberately. Malformed peer frames
and close payloads return
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
