# Changelog

## Unreleased

### Performance

Patterns taken from Nimony's `std/streamio`, `std/http/httpparse` and
`std/websocket`:

- Socket reads go straight into the input string's spare capacity; the 8 KiB
  staging arrays are gone from `HttpClient` and `WebSocket`. Input is consumed
  with a cursor and compacted once per read instead of after every WebSocket
  frame. Reads start at 1 KiB and double to 16 KiB while the peer keeps up.
- HTTP response heads and the WebSocket upgrade response are tokenized once, in
  place, by one shared scanner built on the `std/http/httpparse` primitives: no
  `split`, `strip` or per-line strings, and validation is a by-product of
  tokenizing.
- Chunk sizes, chunk terminators and trailers are parsed on the input view.
- `readAll` allocates a Content-Length body once; with nothing buffered, body
  reads of at least 16 KiB go from the socket straight into the destination.
  Request bodies up to 16 KiB share one write with the head, and larger bodies
  are written without an intermediate copy.
- WebSocket payloads are appended straight into the message under assembly and
  the finished message is moved out; large payloads with nothing buffered are
  read straight into it. Frame headers are written in place.
- UTF-8 validation skips ASCII 32 or 8 bytes at a time; masking handles
  32 bytes per step.

Loopback benchmark (`bench/`, median of 7 interleaved runs, same machine):

| Mode | Before | After |
| --- | --- | --- |
| `ws-large`, 1 MiB echo | 1647 µs | 773 µs |
| `ws-frag`, 64 KiB as 64 fragments | 139 µs | 87 µs |
| `http-large`, 8 MiB `readAll` | 3967 µs | 1316 µs |
| `http-large-stream`, 8 MiB `readBody` | 2006 µs | 974 µs |
| `http-chunked`, 1 MiB in 4 KiB chunks | 386 µs | 267 µs |
| `http-small`, `ws-small` | 11.3 µs, 11.5 µs | unchanged within noise |

Cachegrind instructions: `ws-large` ×20 259 M → 33 M, `ws-frag` ×50
55 M → 15 M, `http-small` ×2000 64 M → 21 M, `http-large` ×5 39 M → 2.6 M.

### Validation

Checks required by RFC 9112 and RFC 6455 are unchanged. Removed:

- Trailer fields are no longer parsed or validated before being discarded
  (RFC 9112 §7.1.2); their count (16) and size (16 KiB) stay bounded.
- The per-field 8 KiB value limit, already implied by the 16 KiB head limit.
- The 16 KiB limit on the client's own request and upgrade heads:
  `requestHead` and `buildRequest` no longer raise `ContentTooLong`.
- A second message-size check per data frame, the token check of a selected
  subprotocol that must equal an offered token, and deadline checks that
  discarded a head or upgrade already received.

Relaxed, as RFC 9112 permits and the stdlib does: response heads may end lines
with a bare LF (§2.2), and the upgrade response's reason phrase is optional.

### API

Source compatible. `parseResponseHead`, `hasToken`, `validateResponse` and
`validUtf8` take `openArray[char]` (strings still work). New pure helpers:
`FrameHeader`, `parseFrameHeader` and `isControl` in `tsuru/frame`;
`startData`, `payload`, `finishMessage`, `handleControl` and `handleClose` in
`tsuru/protocol`. `MaxHandshake` now bounds only the received upgrade head.

### Tests

New fixtures: `large-partial-timeout` (WebSocket, also over TLS),
`chunked-large` and `bad-chunk-end` (HTTP); `bad-trailer` became
`trailer-limit`. The seeded test grew to 200,000 inputs, with UTF-8 checked
against `std/unicode` and mutated HTTP heads. `bench/` holds the benchmark.
Compatibility: qualified `setNoDelay`, which current Nimony's `std/ioring` also
exports.
