# Runtime

## Passive tasks

Run network operations inside a passive task submitted to `std/threadpool`:

```nim
submit(delay task())
```

Every caller of an operation that may suspend must also be passive. Ordinary
helpers can prepare payloads or validate data without suspending. Scheduler
entry points take owned values so their inputs remain alive across suspension.

The [echo](../examples/echo.nim) and [HTTP](../examples/http_get.nim) examples
include `initIoRing`, task submission, the reactor pump and pool shutdown.
The application owns the scheduler lifecycle.

## Connection ownership

Each connection belongs to one task, with sequential calls. Aliases refer to
the same connection; concurrent reads, writes or teardown are unsupported.
The last reference releases the transport. Use `ws.abort()` or `c.close()`
for deterministic immediate cleanup, including error paths.

Received WebSocket payloads and HTTP headers own their data. HTTP `readBody`
copies bytes into caller-owned storage.

## Deadlines

Both client modules, `tsuru/websocket` and `tsuru/httpclient`, export
`Deadline`, `afterMs` and `never`; the `tsuru` facade re-exports both modules.
A deadline is an absolute monotonic instant; `afterMs(1000)` creates one a
second from now. Compute the deadline once to bound several operations together.

WebSocket operations use the earlier of the supplied `dl` and the configured
per-call budget. HTTP connect and request require an explicit deadline; body
reads inherit the request deadline and may tighten it. See the
[WebSocket](api.md#deadlines) and [HTTP](http.md#deadlines) guides for expiry behavior.

Pass `never` explicitly to allow an unbounded HTTP operation. On WebSockets,
`dl = never` leaves the configured operation budget in effect.

## TLS

Compile with `-d:tsuruTls` to enable `wss://` and `https://`.
OpenSSL headers and libraries are required: `openssl-devel` on Fedora or
`libssl-dev` on Debian/Ubuntu.

TLS verifies certificate chains and the DNS hostname or IP address. DNS names
also use SNI. System trust paths are the default; set `options.caFile` to use
a custom PEM trust file. Certificate verification is always enabled.

Without TLS support, secure URLs raise `UnimplementedOperation` before TCP
connection setup.

## Platform support

Linux and the C backend are required. Plain connections need only Nimony's
standard library. DNS uses its IPv4 resolver; IPv6 literals such as
`ws://[::1]:8080/` and `http://[::1]:8080/` are supported.

Socket operations are nonblocking and suspend on readiness. Plain and TLS sends
suppress SIGPIPE without changing application signal handlers.

## References

- [RFC 6455: WebSocket](https://www.rfc-editor.org/rfc/rfc6455)
- [RFC 9112: HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112)
- [OpenSSL hostname verification](https://docs.openssl.org/3.5/man3/SSL_set1_host/)
- [OpenSSL nonblocking errors](https://docs.openssl.org/3.5/man3/SSL_get_error/)
