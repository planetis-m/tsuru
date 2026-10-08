# HTTP client

Import `tsuru/httpclient`. Each client belongs to one passive task and handles
one HTTP/1.1 request at a time. Complete the response body before the next
request, or close immediately. The final reference releases the transport;
explicit close gives deterministic cleanup. Start the owning task using
`submit(delay(task(...)))`.

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

The complete [HTTP example](../examples/http_get.nim) supplies scheduler startup
and error handling. HTTPS requires `-d:tsuruTls` and uses the shared verified
transport; `HttpOptions.caFile` supplies custom CA trust.

| Operation | Contract |
| --- | --- |
| `connectHttp(url, dl, options)` | Connect TCP/TLS under an explicit absolute deadline |
| `request(dl, meth = "GET", target = "", body = "", headers = @[])` | Send the complete request and return its final response head |
| `readBody(dest, dl = never)` | Copy body bytes into caller-owned character storage; zero means completion for nonempty storage |
| `readAll(dl = never)` | Collect the current body in an owned string |
| `close()` | Release immediately, including an unread body; idempotent |
| `open` | Whether the connection is live; never suspends |

An empty target uses the URL's encoded path/query. Other targets are encoded
origin-form paths, or `*`. Request bodies are strings of arbitrary bytes and
are written without a second body buffer. The client generates Host,
Content-Length and a default `Accept-Encoding: identity`. Caller headers cannot
replace Host, Connection, framing, Upgrade or Expect fields.

`HttpResponse` carries status and owned header records. Names are lowercased
once, values remain strings, and duplicate fields stay in wire order.
`response.header(name, default)` returns the first value; iterate headers for
fields such as Set-Cookie. Status codes including 4xx/5xx are ordinary responses;
redirect responses are returned for the caller to act on.

Response framing follows [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3):
HEAD, informational, 204 and 304 responses have no body; other responses use a
content length, chunks or EOF. Informational heads are consumed before the final
response. Chunk extensions and trailers are consumed without changing response
headers. Ambiguous framing is rejected. HTTP/1.1 connections are reused after
complete bodies; HTTP/1.0 requires keep-alive. Connection: close and EOF bodies
release on completion.

`initHttpOptions` defaults to a 64 MiB response payload limit, enforced for both
streaming and collected bodies. Configure a larger limit for large downloads.
Streaming uses a small reusable read buffer, compacted at fill boundaries;
heads use the stdlib's 16 KiB limit. `tsuru/http` owns pure head decisions,
`httpclient` owns body sequencing, and the transport owns TCP/TLS and partial I/O.

One request deadline covers preparation, writes, informational responses, head
and every body read. Body calls can only tighten that stored instant via
`earlier`; a later deadline cannot renew it. Setup takes its own explicit
deadline. Pass the same instant to connect and request to bound them together.
Passing `never` explicitly chooses an unbounded operation.

HTTP failures raise ErrorCode: incomplete messages use EndOfStreamError,
malformed framing SyntaxError, limits ContentTooLong and expiry TimeoutError.
Socket/TLS failures use IOError; an abrupt TLS shutdown is a transport failure.
Exchange failures release the connection. Invalid caller inputs and requesting
before consuming the prior body are rejected before I/O, leaving it usable.

WebSocket receive expiry remains `None` with state preserved; a command's
deadline does not end its message stream. HTTP expiry ends the active exchange.
The transport makes direct nonblocking calls and parks only on readiness, so
expiry leaves no kernel read holding caller storage. Scheduling and cancellation
remain in `std/ioring`.

Body bytes retain their content coding; decompression belongs to the caller.
HTTP/2, CONNECT tunnels, protocol upgrades and transfer codings other than
chunked are unsupported. One task chooses when to create or release its
connection; there are no automatic retries or connection pools.
