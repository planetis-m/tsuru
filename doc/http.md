# HTTP client

Import `tsuru/httpclient`. The `tsuru` package root is a facade re-exporting
this module together with `tsuru/websocket`. Each client belongs to one passive
task and handles one request at a time. Finish the response body before
requesting again, or close immediately. See [runtime](runtime.md) for
scheduling, TLS and ownership.

## Connect and request

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

The [complete example](../examples/http_get.nim) includes scheduler startup
and error handling.

| Operation | Contract |
| --- | --- |
| `connectHttp(url, dl, options = initHttpOptions())` | Connect TCP/TLS under an explicit deadline |
| `c.request(dl, meth = "GET", target = "", body = "", headers = @[])` | Send the complete request and return its final `HttpResponse` head |
| `c.readBody(dest, dl = never)` | Copy body bytes into caller-owned character storage |
| `c.readAll(dl = never)` | Collect the current body in an owned string |
| `c.close()` | Immediate, idempotent release, including an unread response |
| `c.open` | Whether the connection is live; never suspends |

Network operations are passive and raise `ErrorCode` on failure.
Close never suspends.

`initHttpOptions(maxBody = 64 * 1024 * 1024)` sets the response payload limit.
`options.caFile` selects a custom PEM trust file; `""` uses system trust.
HTTPS requires `-d:tsuruTls`.

## Request targets and headers

An empty target uses the URL's encoded path/query. Other targets are encoded
origin-form paths beginning with `/`, or `*`. Request bodies are strings of
arbitrary bytes, written without a second body buffer.

```nim
let response = c.request(deadline, meth = "POST", target = "/jobs",
  body = payload, headers = @[
    Header(name: "Content-Type", value: "application/json"),
    Header(name: "Authorization", value: "Bearer token")])
```

The client generates Host, Content-Length and a default
`Accept-Encoding: identity`. Caller headers cannot replace Host, Connection,
Content-Length, Transfer-Encoding, Upgrade or Expect. Header names must be HTTP
tokens; values reject control characters except tabs.

## Response headers

`HttpResponse` carries `status` and `headers: seq[Header]`.
Names are lowercase, values remain strings, and duplicate fields stay in wire
order. HTTP status codes, including 4xx/5xx, are ordinary responses.

`response.header(name, default = "")` returns the first matching value.
With the default fallback, missing and empty values both return `""`.
Iterate the records when presence or repeated values such as Set-Cookie matter.

## Response bodies

`readBody` returns the number of bytes copied. With nonempty storage, zero
means completion. Empty storage is a no-op. Body bytes retain their content
coding; decompression belongs to the caller.

```nim
proc consumeBody(c: HttpClient) {.passive, raises.} =
  var chunk = default(array[8192, char])
  var total = 0
  while true:
    let n = c.readBody(chunk)
    if n == 0: break
    total += n
  echo "Received ", total, " bytes"
```

Use `readAll` for a collected string and `readBody` for bounded-memory
streaming. Both enforce `maxBody`, which defaults to 64 MiB.
Response heads are limited to 16 KiB.

HEAD, informational, 204 and 304 responses have no body. Other responses use
Content-Length, chunked framing or EOF. Informational heads are consumed before
the final response. Chunk extensions and trailers are consumed without changing
response headers. Ambiguous framing is rejected.

## Keep-alive and retries

HTTP/1.1 connections can be reused after a complete body; HTTP/1.0 requires
keep-alive. Connection: close and EOF bodies release on completion.

A server may close an idle connection between requests. A failed exchange
releases the connection and raises. Requests are not retried automatically.
Failure may occur after request bytes reached the peer; the caller decides
whether to reconnect and retry.

## Deadlines

Connect and request require explicit absolute deadlines. Pass the same instant
to both to bound setup and the exchange together.

One request deadline covers preparation, writes, informational heads, the final
head and every body read. Body calls can tighten it with `dl`; a later deadline
cannot renew it. Pass `never` explicitly for an unbounded operation.
Reuse the original deadline across retry attempts to keep their total budget
bounded.

## Errors

All failures during an exchange release the connection. Invalid caller inputs
and requests made before consuming the previous body are rejected before I/O;
the connection remains usable.

| ErrorCode | Typical cause |
| --- | --- |
| `TimeoutError` | Setup or exchange deadline expired |
| `EndOfStreamError` | Incomplete response or request on a closed handle |
| `SyntaxError` | Malformed or ambiguous response framing |
| `ContentTooLong` | Response payload or head exceeds its limit |
| `ValueError` | Invalid URL/options/request fields, or an unfinished prior body |
| `IOError` | Socket or TLS I/O failure, including abrupt TLS shutdown |
| `PermissionDenied` | TLS negotiation or certificate verification rejected |
| `NameNotFound` | DNS name not found |
| `UnimplementedOperation` | Unsupported secure transport, transfer coding, upgrade or tunnel |

Redirects are returned for the caller to handle. HTTP/2, CONNECT tunnels,
protocol upgrades, transfer codings other than chunked, automatic decompression
and connection pools are unsupported.

`tsuru/http` provides pure head parsing, request serialization and the response
record types. Response framing follows
[RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3).
