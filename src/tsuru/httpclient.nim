## Sequential HTTP/1.1 requests over the shared TCP/TLS transport.
## Own a client from one passive task. Each request's absolute deadline spans
## its writes, informational responses, final head and all body reads.
import std/ioring
from std/http/httpparse import HeadScanner, findHeadEnd, parseChunkSize,
  parseCrLf, ParseBad, ParseIncomplete, MaxHeadLen, MaxTrailerCount
import tsuru/http
import tsuru/internal/[transport, input, endpoint]
export http.Header, http.HttpResponse, http.header
export ioring.Deadline, ioring.never, ioring.afterMs

const
  SmallBody = 16 * 1024
    ## Request bodies up to this size share one write with the head.

type
  HttpOptions* = object
    maxBody*: int ## Maximum response payload bytes, also enforced for streaming reads.
    caFile*: string ## Empty uses system trust; HTTPS requires -d:tsuruTls.
  BodyPhase = enum
    hpClosed, hpReady, hpLength, hpChunkHead, hpChunkData, hpChunkEnd, hpEof
  HttpClient* = ref object
    transport: Transport
    authority, target: string
    maxBody: int
    phase: BodyPhase
    deadline: Deadline
    keepAlive: bool
    remaining: int ## Bytes left in a Content-Length body or the current chunk.
    received: int ## Declared chunk bytes, or EOF-body bytes, counted against maxBody.
    input: Input

proc initHttpOptions*(maxBody: Positive = 64 * 1024 * 1024): HttpOptions =
  ## Default to a 64 MiB response limit. Streaming does not allocate the whole body.
  HttpOptions(maxBody: maxBody)

proc open*(c: HttpClient): bool {.inline.} =
  ## Whether the connection is live; does not suspend.
  c.phase != hpClosed

proc close*(c: HttpClient) =
  ## Release immediately, including an unread response. Idempotent; never suspends.
  close(c.transport)
  c.phase = hpClosed
  clear(c.input)
  c.remaining = 0

proc connectHttp*(url: string; dl: Deadline; options = initHttpOptions()): HttpClient
    {.passive, raises.} =
  ## Connect HTTP or verified HTTPS under dl. Setup failure releases all resources.
  ## The URL's encoded path/query is the default request target.
  let ep = parseEndpoint(url, "http", "https")
  if options.maxBody <= 0 or '\0' in options.caFile: raise ValueError
  checkDeadline(dl)
  result = HttpClient(authority: ep.authority, target: ep.target,
                      maxBody: options.maxBody, input: initInput())
  try:
    open(result.transport, ep.host, ep.port, ep.secure, options.caFile, dl)
    result.phase = hpReady
  except ErrorCode as e:
    close(result)
    raise e

proc needMore(c: HttpClient; dl: Deadline) {.passive, raises.} =
  if fill(c.input, c.transport, dl) == 0: raise EndOfStreamError

proc readHead(c: HttpClient; meth: string; dl: Deadline): ResponseHead {.passive, raises.} =
  ## Parse the head in place once findHeadEnd has seen its blank line.
  var scan = HeadScanner()
  while true:
    let n = findHeadEnd(scan, unread(c.input))
    if n == ParseBad: raise ContentTooLong
    if n >= 0:
      result = parseResponseHead(
        toOpenArray(c.input.data, c.input.pos, c.input.pos + n - 1), meth)
      c.input.pos += n
      return
    needMore(c, dl)

proc finishBody(c: HttpClient) =
  ## Keep the connection only if the server allows it and sent nothing beyond
  ## this response: unrequested bytes must not be read as the next response.
  c.phase = hpReady
  if not c.keepAlive or buffered(c.input) > 0: close(c)

proc request*(c: HttpClient; dl: Deadline; meth = "GET"; target = "";
              body = ""; headers: seq[Header] = @[]): HttpResponse {.passive, raises.} =
  ## Send one complete request and return its final head. Consume the body before
  ## requesting again, or close. HTTP status codes, including errors, are responses.
  ## Failures during the exchange release the connection and raise ErrorCode.
  ## Invalid request inputs are rejected before I/O, preserving an idle connection.
  if c.phase == hpClosed: raise EndOfStreamError
  if c.phase != hpReady: raise ValueError
  var head = requestHead(c.authority, meth,
    (if target.len == 0: c.target else: target), body.len, headers)
  if body.len <= SmallBody: head.add body
  c.deadline = dl
  c.received = 0
  try:
    checkDeadline(dl)
    writeAll(c.transport, toOpenArray(head, 0, head.len - 1), dl)
    if body.len > SmallBody:
      writeAll(c.transport, toOpenArray(body, 0, body.len - 1), dl)
    var parsed = readHead(c, meth, dl)
    while parsed.response.status < 200:
      parsed = readHead(c, meth, dl)
    c.keepAlive = parsed.keepAlive
    case parsed.framing
    of bodyNone: finishBody(c)
    of bodyLength:
      if parsed.length > c.maxBody: raise ContentTooLong
      c.remaining = parsed.length
      if c.remaining == 0: finishBody(c)
      else: c.phase = hpLength
    of bodyChunked: c.phase = hpChunkHead
    of bodyEof: c.phase = hpEof
    result = parsed.response
  except ErrorCode as e:
    close(c)
    raise e

proc skipTrailers(c: HttpClient; dl: Deadline) {.passive, raises.} =
  ## Consume the trailer section and its blank line. Trailers are discarded
  ## (RFC 9112 §7.1.2), so only their count and size are bounded; each byte is
  ## examined once, even when the peer sends one byte at a time.
  var lines = 0
  var bytes = 0
  var inLine = false
  while true:
    if inLine:
      let stop = c.input.data.len
      var i = c.input.pos
      while i < stop and c.input.data[i] != '\n': inc i
      inLine = i == stop
      if not inLine: inc i
      bytes += i - c.input.pos
      c.input.pos = i
      if bytes > MaxHeadLen: raise ContentTooLong
      if inLine: needMore(c, dl)
    else:
      let blank = parseCrLf(unread(c.input))
      if blank >= 0:
        c.input.pos += blank
        return
      if blank == ParseIncomplete:
        needMore(c, dl)
      else:
        inc lines
        if lines > MaxTrailerCount: raise ContentTooLong
        inLine = true

proc consumed(c: HttpClient; n: int) {.raises.} =
  ## Account for n delivered body bytes. Declared lengths and chunk sizes were
  ## checked against maxBody when announced; only EOF bodies are checked here.
  if c.phase == hpEof:
    if n > c.maxBody - c.received: raise ContentTooLong
    c.received += n
  else:
    c.remaining -= n
    if c.remaining == 0:
      if c.phase == hpLength: finishBody(c)
      else: c.phase = hpChunkEnd

proc endOfStream(c: HttpClient) {.raises.} =
  ## EOF completes only an EOF-delimited body.
  if c.phase != hpEof: raise EndOfStreamError
  close(c)

proc copyBody(c: HttpClient; dest: var openArray[char]; dl: Deadline): int
    {.passive, raises.} =
  ## Length, chunk-data or EOF bytes: buffered input first, then large reads
  ## straight into dest, otherwise one buffered read.
  var limit = dest.len
  if c.phase != hpEof: limit = min(limit, c.remaining)
  result = 0
  if buffered(c.input) == 0:
    if limit >= DirectRead:
      result = readSome(c.transport, toOpenArray(dest, 0, limit - 1), dl)
      if result == 0: endOfStream(c)
      else: consumed(c, result)
      return
    if fill(c.input, c.transport, dl) == 0:
      endOfStream(c)
      return
  result = min(limit, buffered(c.input))
  copyMem(addr dest[0], readRawData(c.input.data, c.input.pos), result)
  c.input.pos += result
  consumed(c, result)

proc readBody*(c: HttpClient; dest: var openArray[char]; dl = never): int
    {.passive, raises.} =
  ## Copy the next body bytes into caller-owned storage. With a nonempty dest,
  ## zero means the body ended. dl can tighten the request deadline, never widen it.
  ## Chunk framing and trailers are consumed automatically; content coding is raw.
  result = 0
  if dest.len == 0 or c.phase in {hpReady, hpClosed}: return
  let deadline = earlier(c.deadline, dl)
  try:
    checkDeadline(deadline)
    while true:
      case c.phase
      of hpClosed, hpReady: return
      of hpChunkHead:
        var n = 0
        let used = parseChunkSize(unread(c.input), n)
        if used == ParseBad: raise SyntaxError
        if used == ParseIncomplete:
          needMore(c, deadline)
        else:
          c.input.pos += used
          if n > c.maxBody - c.received: raise ContentTooLong
          if n == 0:
            skipTrailers(c, deadline)
            finishBody(c)
            return
          c.received += n
          c.remaining = n
          c.phase = hpChunkData
      of hpChunkEnd:
        let used = parseCrLf(unread(c.input))
        if used == ParseBad: raise SyntaxError
        if used == ParseIncomplete:
          needMore(c, deadline)
        else:
          c.input.pos += used
          c.phase = hpChunkHead
      of hpLength, hpChunkData, hpEof:
        return copyBody(c, dest, deadline)
  except ErrorCode as e:
    close(c)
    raise e

proc readAll*(c: HttpClient; dl = never): string {.passive, raises.} =
  ## Collect the current body within maxBody and the original request deadline.
  ## A Content-Length body is allocated once and read straight into the result.
  ## Use readBody for large bodies that should stay out of memory.
  result = ""
  while c.phase notin {hpReady, hpClosed}:
    let step = if c.phase in {hpLength, hpChunkData}: max(c.remaining, MinRead)
               else: MaxRead
    let old = result.len
    var n = 0
    var spare = toOpenArray(beginStore(result, old + step, old), 0, step - 1)
    try:
      n = readBody(c, spare, dl)
    finally:
      endStore(result)
      result.setLen(old + n)
    if n == 0: return
