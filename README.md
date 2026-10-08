# Tsuru (鶴)

WebSocket and HTTP/1.1 clients for **Nimony**, using sequential `.passive` I/O.
WebSockets deliver complete text or binary messages with automatic fragmentation
and ping/pong handling. HTTP supports streaming response bodies and keep-alive.
Both clients support verified TLS and absolute deadlines.

## Setup

Requires Linux, Nimony **0.6.3** and a C compiler.

Add a relative path to `tsuru/src` to your project's `nimony.paths`, or compile
with `--path:/path/to/tsuru/src`.

Compile with `-d:tsuruTls` for `wss://` and `https://`. TLS requires OpenSSL
headers and libraries: `openssl-devel` on Fedora or `libssl-dev` on Debian/Ubuntu.

## WebSocket

```nim
import std/[opt, syncio]
import tsuru

proc chat() {.passive, raises.} =
  let ws = connectWebSocket("ws://127.0.0.1:8080/")
  defer: ws.abort()
  if not ws.send("Hello from Nimony"): return
  case ws.recv()
  of Some(message): echo message.data
  of None(): echo "Receive deadline expired"
  discard ws.close()
```

Start the task with `submit(delay chat())` on `std/threadpool`.
Every caller of a suspending operation must also be passive.
The [echo example](examples/echo.nim) includes scheduler startup and error handling:

```sh
nimony c -o:build/echo examples/echo.nim
build/echo ws://localhost:8080/chat
```

Receive expiry returns `None` and keeps the connection usable. Configure limits,
authentication and subprotocols through `initWebSocketOptions`.
See the [WebSocket guide](doc/api.md) and [receive example](examples/receive.nim).

## HTTP

```nim
import std/syncio
import tsuru/httpclient

proc fetch() {.passive, raises.} =
  let deadline = afterMs(10_000)
  let c = connectHttp("https://example.com/data", deadline)
  defer: c.close()
  let response = c.request(deadline)
  echo response.status
  echo c.readAll()
```

One request deadline covers sending, response headers and body reads.
Use `readBody` with caller-owned storage for large responses. Finish the body
before the next request, or close immediately.

The [HTTP example](examples/http_get.nim) includes scheduler startup and error handling:

```sh
nimony c -d:tsuruTls -o:build/http_get examples/http_get.nim
build/http_get https://example.com/
```

See the [HTTP guide](doc/http.md) for headers, framing, limits and errors.

## Documentation

| Guide | Contents |
| --- | --- |
| [Runtime](doc/runtime.md) | Passive tasks, connection ownership, deadlines, TLS and platform support |
| [WebSocket](doc/api.md) | Options, messages, receive expiry, closing and API contracts |
| [HTTP](doc/http.md) | Requests, response streaming, headers, keep-alive and errors |
| [Verification](doc/verification.md) | Test commands, configurations and fixture coverage |

## Tests

```sh
tests/run --network
tests/run --tls --asan --network
```

Tests use local fixtures. See [verification](doc/verification.md) for requirements
and optimized builds.

MIT licensed.
