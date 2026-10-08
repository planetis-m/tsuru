# Tsuru (鶴)

A WebSocket client for **Nimony**, with sequential `.passive` I/O on the
standard library's worker pool. Connect to a WebSocket server,
send text or binary messages, and receive complete messages while the client
handles fragmentation, ping/pong, masking, and close handshakes.

```nim
import tsuru

proc chat() {.passive.} =
  try:
    let ws = connectWebSocket("ws://127.0.0.1:8080/")
    defer: ws.abort()
    if not ws.send("Hello from Nimony"): return
    let message = ws.recv()
    # message.kind is wmText, wmBinary, wmTimeout, or wmClose.
    discard ws.close()
  except ErrorCode as e:
    discard e # Handle connection setup errors here.
```

Run the task on `std/threadpool` with `submit(delay chat())`. The complete
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
| `ws.recv(dl)` | Complete text/binary message, nonterminal `wmTimeout`, or terminal `wmClose` |
| `ws.ping(data = "", dl)` | Send a ping; returns bool; `recv` consumes pongs |
| `ws.close(code = 1000, reason = "", dl)` | Exchange Close frames and release; deadline capped at 250 ms; returns bool |
| `ws.waitClose(dl)` | Await peer closure, discarding messages; deadline capped at 250 ms; returns `wmClose` |
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
let message = ws.recv(dl = afterMs(100))
case message.kind
of wmText: discard message.data # Decode and dispatch a reply or event by its id.
of wmBinary: discard message.data
of wmTimeout: discard           # Retire expired commands; the connection stays open.
of wmClose: discard message.code # Terminal; data holds the reason, closeSource the cause.
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
socket on failure: send and ping return false, and receive returns `wmClose`.
An ordinary receive expiry returns `wmTimeout` and keeps the socket open.

`close` sends one Close frame, awaits the peer's Close frame, and releases in
every case. It returns true after the exchange or if already closed, and false
on failure, EOF without a Close frame, or expiry. Its whole I/O deadline is the
earliest of 250 ms from the call, the configured operation budget, and `dl`:

```nim
discard ws.close(1000, "done", dl = afterMs(100))
```

The recorded terminal outcome remains available through `recv`. Send or close
expiry uses code 1006 and `csTimeout`. `abort` releases immediately without a
handshake. `waitClose` can await a peer-initiated close under the same short
bound; it discards messages, releases on expiry, and returns `wmClose`.
Callers supply valid outgoing text and control payloads. More detail:
[API and error contracts](doc/api.md).

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
