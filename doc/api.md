# WebSocket client

Import `tsuru/websocket` for the client and `std/opt` to match receive results.
The `tsuru` package root is a facade re-exporting this module together with
`tsuru/httpclient`. Use one owning passive task for each connection.
See [runtime](runtime.md) for scheduling, TLS and connection ownership.

## Operations

| Operation | Result |
| --- | --- |
| `connectWebSocket(url, options = initWebSocketOptions(), dl = never)` | Connected `WebSocket`; raises on setup failure |
| `ws.send(data: string, binary = false, dl = never)` | Write success as `bool`; text by default |
| `ws.send(data: seq[byte], dl = never)` | Binary write success as `bool` |
| `ws.recv(dl = never)` | `Opt[Message]`: complete message, terminal close, or expiry |
| `ws.ping(data = "", dl = never)` | Ping write success as `bool` |
| `ws.close(code = 1000, reason = "", dl = never)` | Terminal `Message` after a bounded closing handshake |
| `ws.abort()` | Immediate, idempotent release |
| `ws.open` | Whether application messages may be sent, as `bool` |
| `ws.state` | `wsOpen` or `wsClosed` |
| `ws.protocol` | Negotiated subprotocol, or `""` |

Connect, send, receive, ping and close may suspend. Abort and the status
accessors never suspend. Live operations return outcomes without raising
`ErrorCode`.

## Options

Construct options with `initWebSocketOptions`; default-constructed options have
invalid zero limits.

| Field | Default | Contract |
| --- | --- | --- |
| `maxMessage` | 16 MiB | Positive limit on received messages, including assembled fragments |
| `timeoutMs` | 30,000 | Positive per-operation budget in milliseconds |
| `origin` | `""` | Optional Origin value |
| `protocols` | Empty | Distinct HTTP tokens; the peer may select one or none |
| `headers` | Empty | Additional handshake headers |
| `caFile` | `""` | System TLS trust, or a custom PEM file |

```nim
var options = initWebSocketOptions(maxMessage = 64 * 1024 * 1024, timeoutMs = 10_000)
options.origin = "https://example.com"
options.protocols = @["chat.v1"]
options.headers = @[Header(name: "Authorization", value: "Bearer token")]
```

Header names must be HTTP tokens; values reject control characters except tabs.
Custom headers cannot replace Host, Connection, Upgrade, Origin,
Content-Length, Transfer-Encoding or Sec-WebSocket fields.

The [receive example](../examples/receive.nim) accepts `TSURU_TOKEN`,
`TSURU_PROTOCOL` and `TSURU_CA_FILE`, with a ten-second setup deadline and
five-minute receive budget.

## Sending

Each send writes one complete masked frame. A successful write means the
transport accepted the bytes; it does not acknowledge peer processing.
Send and ping return false on a closed connection or write failure.
Write failure releases the connection; the next receive returns its terminal
outcome.

Callers supply valid UTF-8 for text, ping payloads of at most 125 bytes, and
valid close codes with a UTF-8 reason of at most 123 bytes. Outgoing payloads
are not revalidated or restricted by the receive limit.

Sends copy and mask into a reusable wire buffer. Sending a byte sequence avoids
a sequence-to-string conversion. The client retains its largest send and
receive buffer capacities until closure; returned messages own their payloads.

## Receiving

```nim
case ws.recv(dl = afterMs(100))
of Some(message):
  case message.kind
  of wmText, wmBinary: discard message.data
  of wmClose: discard message.code
of None(): discard
```

| Field | Meaning |
| --- | --- |
| `kind` | `wmText`, `wmBinary` or `wmClose` |
| `data` | Complete payload, or close reason |
| `code` | Close status; meaningful for `wmClose` |
| `closeSource` | Cause of termination; meaningful for `wmClose` |

Empty text and binary messages are valid deliveries. Incoming fragments are
assembled, text is validated, and ping frames receive automatic pongs.
Pong replies are consumed internally. Continue calling receive to process
control traffic.

Messages arrive in wire order. Command ids, pending tables, per-command
deadlines and late-reply handling belong to the application.

## Deadlines

An operation uses the earlier of `dl` and `afterMs(options.timeoutMs)`.
One deadline covers preparation, buffered processing, partial I/O, fragments
and interleaved controls. Control traffic does not restart it.

Receive expiry returns `None` and keeps the connection open. Buffered frames,
partial input, fragment state and pending automatic output are preserved.
A subsequent receive or send completes a paused pong before writing another
frame.

An already expired deadline returns `None` even when a complete frame is
buffered. `afterMs(0)` is therefore not a nonblocking message poll.
Send and ping expiry are terminal and return false.

## Closing and terminal outcomes

Close sends one Close frame, answers pings and waits for the peer's Close.
Application messages arriving during that wait are discarded. The whole
handshake is bounded by the earliest of 250 ms from the call, the configured
operation budget and `dl`. Close always releases and returns the terminal
message. Abort releases immediately without a handshake.

```nim
let outcome = ws.close(1000, "done", dl = afterMs(100))
if outcome.closeSource != csPeer:
  discard outcome.code
```

| Source | Meaning |
| --- | --- |
| `csPeer` | Peer Close; preserves its code and reason |
| `csEof` | Transport EOF without a Close frame |
| `csLocal` | Local abort or a default closed handle |
| `csProtocolError` | Malformed peer frame, text or close payload, or exceeded receive limit |
| `csTransportError` | Socket, TLS or output failure |
| `csTimeout` | Send, ping or close deadline expired |

Code 1005 means a peer Close omitted its status. Abort, EOF, transport failure
and timeout use 1006. Protocol failures use 1002 for malformed frames or close
payloads, 1007 for invalid UTF-8 and 1009 for exceeded receive limits. Protocol
failures attempt a Close before release. A failed close reply preserves any
peer or protocol outcome already recorded.

After termination, receive returns `Some(wmClose)` repeatedly and close returns
the recorded outcome. Repeated close or abort calls preserve that outcome.
A default `WebSocket()` is closed; receive returns code 1006, an empty reason
and `csLocal`.

To wait for peer-initiated closure, continue receiving under the application's
deadline policy. Local teardown needs one close or abort call.

## Setup errors

Connection setup covers DNS, TCP, TLS and the HTTP upgrade under one deadline.
All setup failures release acquired resources.

| ErrorCode | Typical cause |
| --- | --- |
| `ValueError` | Invalid URL/options or rejected upgrade |
| `ContentTooLong` | Oversized upgrade head |
| `TimeoutError` | Setup deadline exhausted |
| `EndOfStreamError` | Peer disappeared during upgrade |
| `IOError` | Socket, randomness, trust-file or TLS I/O failure |
| `PermissionDenied` | TLS negotiation or certificate verification rejected |
| `NameNotFound` | DNS name not found |
| `UnimplementedOperation` | Secure URL in a build without TLS |

The upgrade response must be HTTP/1.1 status 101 with upgrade tokens and the
exact accept key. Duplicate accept/subprotocol fields, unsolicited extensions
and unoffered subprotocols are rejected. Bytes following the head are retained
for receive.

Compression, proxy support, automatic reconnect and background heartbeats are
unsupported.

## Pure protocol modules

| Import | Contents |
| --- | --- |
| `tsuru/frame` | Frame parsing, headers and masking |
| `tsuru/protocol` | Message assembly, UTF-8 and close handling |
| `tsuru/handshake` | Endpoint parsing, opening request construction and upgrade validation |

`tsuru/handshake` exports `Endpoint`. `parseEndpoint` returns its host,
authority, encoded target, port and TLS selection. `buildRequest` takes that
value and a base64 nonce.

`parseFrame` requires `0 <= start <= data.len` and a nonnegative payload limit.
`handleFrame` takes a parsed frame and a nonnegative message limit.
`frameHeader` includes the four-byte mask key. `encodeFrame` returns an owned
wire string; its `var string` overload reuses storage and accepts character or
byte views. Input must not alias the output. Supply a fresh cryptographic mask
and valid outgoing payload for every frame.
