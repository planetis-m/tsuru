# Tsuru (鶴)

A WebSocket and HTTP/1.1 client library for **Nimony**, with sequential `.passive`
I/O on the standard library's worker pool. Connect to a WebSocket server,
send text or binary messages, and receive complete messages while the client
handles fragmentation, ping/pong, masking, and close handshakes.

```nim
import std/opt
import tsuru

proc chat() {.passive.} =
  try:
    let ws = connectWebSocket("ws://127.0.0.1:8080/")
    defer: ws.abort()
    if not ws.send("Hello from Nimony"): return
    case ws.recv()
    of Some(message): discard message.data
    of None(): discard # Receive deadline expired; the connection stays open.
    discard ws.close()
  except ErrorCode as e:
    discard e # Handle connection setup errors here.
```

Start the passive task on `std/threadpool` with `submit(delay chat())`.
Every caller of an operation that may suspend must also be passive. The complete
[echo example](examples/echo.nim) includes scheduler startup, the main-thread
reactor pump, error reporting, and shutdown.

## Run

Requires Nimony **0.6.3** and a C compiler. Linux is the supported platform.
Plain `ws://` has no dependencies beyond Nimony's standard library.

With a WebSocket echo server listening on port 8080, run:

```sh
nimony c -r examples/echo.nim
```

To choose another echo endpoint:

```sh
nimony c -o:build/echo examples/echo.nim
build/echo ws://localhost:8080/chat
```

To import the library in another Nimony project,
add a relative path to `tsuru/src` to that project's `nimony.paths`, or compile
with `--path:/path/to/tsuru/src`.

## Secure WebSockets

Compile with `-d:tsuruTls` to enable `wss://`. This requires the system OpenSSL
headers and libraries (`openssl-devel` on Fedora, `libssl-dev` on Debian/Ubuntu).

```sh
nimony c -d:tsuruTls -o:build/echo examples/echo.nim
build/echo wss://your-echo-server.example/chat
```

TLS verifies the certificate chain and DNS hostname or IP address. DNS names
also use SNI. System trust paths are the default; set `options.caFile` to trust
a specific CA file. Certificate verification is always enabled. A build
without TLS support rejects `wss://` with `UnimplementedOperation`.

## Options and API

```nim
var options = initWebSocketOptions(maxMessage = 64 * 1024 * 1024, timeoutMs = 10_000)
options.origin = "https://example.com"
options.protocols = @["chat.v1"]
options.headers = @[Header(name: "Authorization", value: "Bearer token")]
let ws = connectWebSocket("ws://localhost:8080/chat", options)
```

Connection setup requires a passive procedure inside `try`, or `{.raises.}`
to propagate setup errors. Live operations return their outcome directly.
Custom headers cannot replace handshake fields or add an HTTP request body.

| Operation | Behavior |
| --- | --- |
| `connectWebSocket(url, options, dl)` | TCP/TLS connection and validated HTTP upgrade |
| `ws.send(data, binary = false, dl)` | One masked message; returns success as a bool |
| `ws.send(bytes: seq[byte], dl)` | Binary message without converting bytes to a string; returns bool |
| `ws.recv(dl)` | `Opt[Message]`: `Some` text/binary/close, or `None` on receive expiry |
| `ws.ping(data = "", dl)` | Send a ping; returns bool; `recv` consumes pongs |
| `ws.close(code = 1000, reason = "", dl)` | Exchange Close frames and release; deadline capped at 250 ms; returns terminal `Message` |
| `ws.abort()` | Release resources immediately; idempotent |
| `ws.open`, `ws.state`, `ws.protocol` | Connection status and negotiated subprotocol |

`dl` defaults to `never`; the options still impose a 30 second budget by
default. Pass `afterMs(1000)` to tighten a single operation's deadline.
The connection budget covers DNS, TCP, TLS and HTTP together. Receive budgets
cover the whole message, including all fragments and interleaved controls.
Receive limits default to 16 MiB and also bound assembled fragments.

For a long-lived control connection, compute the next absolute deadline from
the application's pending commands and pass it to `recv`. Expiry is ordinary:

```nim
case ws.recv(dl = afterMs(100))
of Some(message):
  case message.kind
  of wmText, wmBinary: discard message.data # Dispatch a reply or event by its id.
  of wmClose: discard message.code # Terminal; data holds the reason, closeSource the cause.
of None(): discard # Retire expired commands; the connection stays open.
```

Command ids, pending tables, per-command deadlines and late replies belong to
the application. The client delivers messages in wire order and does not
correlate commands with replies. Each send is one complete call. Receive expiry
preserves partial frames, fragmented messages and any pending automatic pong;
a subsequent receive or send resumes safely. Configure `maxMessage` for large
payloads, as in the 64 MiB example above.

Binary sequences can be sent directly:

```nim
if not ws.send(@[0'u8, 255'u8, 128'u8]): return
```

Sends copy and mask the payload in one pass into a reusable wire string, then
write the coalesced frame. Receive processing consumes wire bytes in place.
Both buffers retain their largest capacity until closure: repeated traffic
reuses storage, while an occasional large message leaves that storage allocated.

For a connection that can be quiet for several minutes, increase
`options.timeoutMs` to match that receive budget. The
[receive example](examples/receive.nim) listens until the peer closes, reports
the close reason, and accepts optional authentication, subprotocol and CA settings:

```sh
nimony c -d:tsuruTls -o:build/receive examples/receive.nim
TSURU_PROTOCOL=events.v1 build/receive wss://your-server.example/events
```

Set `TSURU_TOKEN` for a bearer token and `TSURU_CA_FILE` for a custom PEM trust
file. The example gives connection setup ten seconds and each receive five
minutes; controls do not extend a receive's deadline.

Own a connection from **one task**, with sequential calls. Concurrent readers
or writers on the same handle are unsupported. Keep calling `recv` while
waiting for inbound messages so pings are answered. There is no background
heartbeat, automatic reconnect, compression, proxy support, or HTTP redirect
following. Outgoing messages use one frame; incoming fragments are assembled.
DNS uses Nimony's IPv4 resolver; IPv6 literals such as `ws://[::1]:8080/` work.
All network operations require the C backend.

On peer close, `recv` returns its code and reason and echoes its close payload.
Code `1005` means the peer omitted a status; `1006` means closure without a
close status. `message.closeSource` identifies peer closure, EOF, local abort,
protocol failure, transport failure or timeout. Live operations release the
socket on failure: send and ping return false, and receive returns `Some(wmClose)`.
An ordinary receive expiry returns `None` and keeps the socket open. An already
expired deadline, including `afterMs(0)`, preserves buffered input and returns
`None`; it does not poll for messages.

`close` sends one Close frame, awaits the peer's Close frame, and releases in
every case. It returns the terminal `Message`, including the peer's close status
or the reason the exchange ended. Calling close again returns the recorded
outcome. Its whole I/O deadline is the earliest of 250 ms from the call, the
configured operation budget, and `dl`:

```nim
let outcome = ws.close(1000, "done", dl = afterMs(100))
if outcome.closeSource != csPeer:
  discard outcome.code # Timeout, EOF, protocol failure or transport failure.
```

The recorded terminal outcome remains available through `recv`. Send or close
expiry uses code 1006 and `csTimeout`. `abort` releases immediately without a
handshake. Continue receiving to await a peer-initiated close, handling `None`
according to the application's deadline policy.
Callers supply valid outgoing text and control payloads. More detail:
[API and error contracts](doc/api.md).

## HTTP client

Import `tsuru/httpclient` for HTTP and verified HTTPS. Requests take an explicit
absolute deadline; that same instant bounds sending, the response head and all
body reads. Connections support sequential keep-alive requests.

```nim
import tsuru/httpclient

proc fetch() {.passive, raises.} =
  let deadline = afterMs(10_000)
  let c = connectHttp("https://example.com/data", deadline)
  defer: c.close()
  let response = c.request(deadline)
  let body = c.readAll()
  discard response.status
  discard body
```

Use `readBody` with caller-owned storage to stream large responses. Complete the
current body before requesting again, or close. Content-Length, chunks,
trailers, bodyless responses and EOF framing are handled automatically.
HTTP failures raise ErrorCode and release an active exchange; status codes are
returned normally. HTTPS uses the same `-d:tsuruTls` flag and verified transport.

Run `nimony c -d:tsuruTls -r examples/http_get.nim https://example.com/`.
See [HTTP contracts and deadlines](doc/http.md) for limits, headers and streaming.

## Verify

```sh
tests/run                          # unit tests, 100,000 seeded fuzz cases, example builds
tests/run --network                # independent local wire fixtures
tests/run --tls --network          # plus trusted TLS, untrusted CA and wrong-host rejection
tests/run --release --network
tests/run --danger --network
tests/run --tls --asan --network   # AddressSanitizer and UndefinedBehaviorSanitizer
python3 tests/hashi.py --compat    # optional integration test with a local Hashi server
```

Set `NIMONY=/path/to/nimony` to select a compiler. Python 3 is needed for network
fixtures; TLS fixtures also use the `openssl` command to generate a temporary
test certificate. Network tests use loopback only and require no Python packages.

See [test coverage](doc/verification.md) for details.

Protocol references: [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455),
[OpenSSL hostname verification](https://docs.openssl.org/3.5/man3/SSL_set1_host/),
[OpenSSL nonblocking errors](https://docs.openssl.org/3.5/man3/SSL_get_error/).

MIT licensed.
