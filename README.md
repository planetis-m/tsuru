# Tsuru (鶴)

A WebSocket client for **Nimony**, with sequential `.passive` I/O on the
standard library's worker pool. Connect to Hashi or another WebSocket server,
send text or binary messages, and receive complete messages while the client
handles fragmentation, ping/pong, masking, and close handshakes.

```nim
import tsuru

proc chat() {.passive.} =
  try:
    let ws = connectWebSocket("ws://127.0.0.1:8080/")
    defer: ws.abort()
    ws.send("Hello from Nimony")
    let message = ws.recv()
    # message.kind is wmText, wmBinary, or wmClose; message.data holds its payload.
    ws.close()
  except ErrorCode as e:
    discard e # Handle connection, handshake, protocol, or timeout errors here.
```

Run the task on `std/threadpool` with `submit(delay chat())`. The complete
[echo example](examples/echo.nim) includes scheduler startup, the main-thread
reactor pump, error reporting, and shutdown.

## Run against Hashi

Requires Nimony **0.6.3** and a C compiler. Linux is the supported platform.
Plain `ws://` has no dependencies beyond Nimony's standard library.

Start Hashi's `examples/ws_echo.nim` on port 8080, then from this repository:

```sh
nimony c -r examples/echo.nim
```

To choose another echo endpoint:

```sh
nimony c -o:build/echo examples/echo.nim
build/echo ws://localhost:8080/chat
```

The library is independent of Hashi. To import it in another Nimony project,
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
var options = initWebSocketOptions(maxMessage = 4 * 1024 * 1024, timeoutMs = 10_000)
options.origin = "https://example.com"
options.protocols = @["chat.v1"]
options.headers = @[Header(name: "Authorization", value: "Bearer token")]
let ws = connectWebSocket("ws://localhost:8080/chat", options)
```

Call from a passive procedure inside `try`, or propagate errors with `{.raises.}`.
Custom headers cannot replace handshake fields or add an HTTP request body.

| Operation | Behavior |
| --- | --- |
| `connectWebSocket(url, options, dl)` | TCP/TLS connection and validated HTTP upgrade |
| `ws.send(data, binary = false, dl)` | One masked message; text must be valid UTF-8 |
| `ws.recv(dl)` | Complete text/binary message or `wmClose`; answers pings automatically |
| `ws.ping(data = "", dl)` | Ping payload of at most 125 bytes; `recv` consumes pongs |
| `ws.close(code = 1000, reason = "", dl)` | Send close and wait up to five seconds for the peer |
| `ws.abort()` | Release resources immediately; idempotent |
| `ws.open`, `ws.state`, `ws.protocol` | Connection status and negotiated subprotocol |

`dl` defaults to `never`; the options still impose a 30 second budget by
default. Pass `afterMs(1000)` to tighten a single operation's deadline.
The connection budget covers DNS, TCP, TLS and HTTP together. Receive budgets
cover the whole message, including all fragments and interleaved controls.
Message limits default to 16 MiB and also bound assembled fragments.

Own a connection from **one task**, with sequential calls. Concurrent readers
or writers on the same handle are unsupported. Keep calling `recv` while
waiting for inbound messages so pings are answered. There is no background
heartbeat, automatic reconnect, compression, proxy support, or HTTP redirect
following. Outgoing messages use one frame; incoming fragments are assembled.
DNS uses Nimony's IPv4 resolver; IPv6 literals such as `ws://[::1]:8080/` work.
All network operations require the C backend.

On peer close, `recv` returns its code and reason and echoes its close payload.
Code `1005` means the peer omitted a status; `1006` means EOF without a close
frame. `message.closeSource` identifies peer closure, EOF, local abort, local
protocol failure or transport failure. Transport errors and timeouts raise
`ErrorCode` and release the socket.
Invalid arguments leave a live connection intact. More detail:
[API and error contracts](doc/api.md).

## Verify

```sh
tests/run                          # unit tests, 100,000 seeded fuzz cases, example builds
tests/run --network                # independent local wire fixtures
tests/run --tls --network          # plus trusted TLS, untrusted CA and wrong-host rejection
tests/run --release --network
tests/run --danger --network
tests/run --tls --asan --network   # AddressSanitizer and UndefinedBehaviorSanitizer
python3 tests/hashi.py             # sibling Hashi echo server on port 8080
```

Set `NIMONY=/path/to/nimony` to select a compiler. Python 3 is needed for network
fixtures; TLS fixtures also use the `openssl` command to generate a temporary
test certificate. Network tests use loopback only and require no Python packages.

Set `HASHI_NIMONY=/path/to/nimony` to choose Hashi's compiler, or use
`python3 tests/hashi.py --compat` to test a temporary compatibility copy.
See [test coverage](doc/verification.md) for details.

Protocol references: [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455),
[OpenSSL hostname verification](https://docs.openssl.org/3.5/man3/SSL_set1_host/),
[OpenSSL nonblocking errors](https://docs.openssl.org/3.5/man3/SSL_get_error/).

MIT licensed.
