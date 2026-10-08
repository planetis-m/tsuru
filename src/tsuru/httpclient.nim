## Sequential HTTP/1.1 requests over the shared TCP/TLS transport.
## Own a client from one passive task. Each request's absolute deadline spans
## its writes, informational responses, final head and all body reads.
import std/[ioring, strutils]
from std/http/httpparse import HeadScanner, findHeadEnd, parseChunkSize,
  ParseBad, MaxHeadLen, MaxChunkSizeDigits, MaxChunkExtLen,
  MaxTrailerCount
import tsuru/http
import tsuru/internal/[transport, buffer, endpoint]
export http.Header, http.HttpResponse, http.header
export ioring.Deadline, ioring.never, ioring.afterMs

type
  HttpOptions* = object
    maxBody*: int ## Maximum response payload bytes, also enforced for streaming reads.
    caFile*: string ## Empty uses system trust; HTTPS requires -d:tsuruTls.
  BodyPhase = enum
    hpClosed, hpReady, hpLength, hpChunkHead, hpChunkData, hpChunkEnd, hpTrailers, hpEof
  HttpClient* = ref object
    transport: Transport
    endpoint: Endpoint
    options: HttpOptions
    phase: BodyPhase
    deadline: Deadline
    keepAlive: bool
    remaining: int
    received: int
    input: string
    pos: int
    readBuffer: array[8192, char]

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
  c.input = ""
  c.pos = 0
  c.remaining = 0

proc prepareEndpoint(url: string; ep: var Endpoint) {.raises.} =
  ep = parseEndpoint(url, "http", "https")

proc prepareHead(authority, meth, target: string; length: int;
                 headers: seq[Header]; head: var string) {.raises.} =
  head = requestHead(authority, meth, target, length, headers)

proc decodeHead(head, meth: string; parsed: var ResponseHead) {.raises.} =
  parsed = parseResponseHead(head, meth)

proc connectHttp*(url: string; dl: Deadline; options = initHttpOptions()): HttpClient
    {.passive, raises.} =
  ## Connect HTTP or verified HTTPS under dl. Setup failure releases all resources.
  ## The URL's encoded path/query is the default request target.
  var ep = Endpoint()
  prepareEndpoint(url, ep)
  if options.maxBody <= 0 or '\0' in options.caFile: raise ValueError
  checkDeadline(dl)
  result = HttpClient(endpoint: ep, options: options)
  try:
    open(result.transport, ep.host, ep.port, ep.secure, options.caFile, dl)
    checkDeadline(dl)
    result.phase = hpReady
  except ErrorCode as e:
    close(result)
    raise e

proc fill(c: HttpClient; dl: Deadline): int {.passive, raises.} =
  if c.pos > 0:
    dropPrefix(c.input, c.pos)
    c.pos = 0
  result = readSome(c.transport, c.readBuffer, dl)
  appendBytes(c.input, toOpenArray(c.readBuffer, 0, result - 1))

proc readHead(c: HttpClient; meth: string; dl: Deadline): ResponseHead {.passive, raises.} =
  result = ResponseHead()
  var scan = HeadScanner()
  while true:
    checkDeadline(dl)
    let n = findHeadEnd(scan,
      toOpenArray(readRawData(c.input, c.pos), 0, c.input.len - c.pos - 1))
    if n == ParseBad or n > MaxHeadLen: raise ContentTooLong
    if n >= 0:
      decodeHead(c.input[c.pos..<c.pos + n], meth, result)
      checkDeadline(dl)
      c.pos += n
      return
    if fill(c, dl) == 0: raise EndOfStreamError

proc finishBody(c: HttpClient) =
  if c.keepAlive: c.phase = hpReady
  else: close(c)

proc request*(c: HttpClient; dl: Deadline; meth = "GET"; target = "";
              body = ""; headers: seq[Header] = @[]): HttpResponse {.passive, raises.} =
  ## Send one complete request and return its final head. Consume the body before
  ## requesting again, or close. HTTP status codes, including errors, are responses.
  ## Failures during the exchange release the connection and raise ErrorCode.
  ## Invalid request inputs are rejected before I/O, preserving an idle connection.
  if c.phase == hpClosed: raise EndOfStreamError
  if c.phase != hpReady: raise ValueError
  var head = ""
  prepareHead(c.endpoint.authority, meth,
    (if target.len == 0: c.endpoint.target else: target), body.len, headers, head)
  c.deadline = dl
  c.received = 0
  try:
    checkDeadline(dl)
    writeAll(c.transport, toOpenArray(readRawDataStable(head), 0, head.len - 1), dl)
    if body.len > 0:
      var payload = body
      writeAll(c.transport, toOpenArray(readRawDataStable(payload), 0, payload.len - 1), dl)
    var parsed = readHead(c, meth, dl)
    while parsed.response.status < 200:
      parsed = readHead(c, meth, dl)
    c.keepAlive = parsed.keepAlive
    case parsed.framing
    of bodyNone: finishBody(c)
    of bodyLength:
      if parsed.length > c.options.maxBody: raise ContentTooLong
      c.remaining = parsed.length
      if c.remaining == 0: finishBody(c)
      else: c.phase = hpLength
    of bodyChunked: c.phase = hpChunkHead
    of bodyEof: c.phase = hpEof
    result = parsed.response
  except ErrorCode as e:
    close(c)
    raise e

proc readLine(c: HttpClient; limit: int; dl: Deadline): string {.passive, raises.} =
  var scanned = 0
  while true:
    checkDeadline(dl)
    let available = c.input.len - c.pos
    while scanned < available:
      if c.input[c.pos + scanned] == '\n':
        if scanned == 0 or c.input[c.pos + scanned - 1] != '\r': raise SyntaxError
        if scanned + 1 > limit: raise ContentTooLong
        result = c.input[c.pos..<c.pos + scanned + 1]
        c.pos += scanned + 1
        return
      inc scanned
    if available >= limit: raise ContentTooLong
    if fill(c, dl) == 0: raise EndOfStreamError

proc readBody*(c: HttpClient; dest: var openArray[char]; dl = never): int
    {.passive, raises.} =
  ## Copy the next body bytes into caller-owned storage. With a nonempty dest,
  ## zero means the body ended. dl can tighten the request deadline, never widen it.
  ## Chunk framing and trailers are consumed automatically; content coding is raw.
  result = 0
  if dest.len == 0 or c.phase in [hpReady, hpClosed]: return
  let deadline = earlier(c.deadline, dl)
  try:
    while true:
      checkDeadline(deadline)
      case c.phase
      of hpClosed, hpReady: return
      of hpChunkHead:
        let line = readLine(c, MaxChunkSizeDigits + MaxChunkExtLen + 2, deadline)
        var n = 0
        if parseChunkSize(line, n) < 0: raise SyntaxError
        if n > c.options.maxBody - c.received: raise ContentTooLong
        c.remaining = n
        c.phase = if n == 0: hpTrailers else: hpChunkData
      of hpChunkEnd:
        if readLine(c, 2, deadline) != "\r\n": raise SyntaxError
        c.phase = hpChunkHead
      of hpTrailers:
        var count = 0
        var bytes = 0
        while true:
          let line = readLine(c, MaxHeadLen - bytes, deadline)
          bytes += line.len
          if line == "\r\n": break
          inc count
          if count > MaxTrailerCount: raise ContentTooLong
          let colon = line.find(':')
          if colon <= 0 or not validToken(line[0..<colon]) or
              not cleanValue(line[colon + 1..<line.len - 2]): raise SyntaxError
        finishBody(c)
        return
      of hpLength, hpChunkData, hpEof:
        if c.pos == c.input.len:
          if fill(c, deadline) == 0:
            if c.phase != hpEof: raise EndOfStreamError
            close(c)
            return
        var n = min(dest.len, c.input.len - c.pos)
        if c.phase != hpEof: n = min(n, c.remaining)
        if n > c.options.maxBody - c.received: raise ContentTooLong
        copyMem(addr dest[0], readRawData(c.input, c.pos), n)
        c.pos += n
        c.received += n
        if c.phase != hpEof:
          c.remaining -= n
          if c.remaining == 0:
            if c.phase == hpLength: finishBody(c)
            else: c.phase = hpChunkEnd
        return n
  except ErrorCode as e:
    close(c)
    raise e

proc readAll*(c: HttpClient; dl = never): string {.passive, raises.} =
  ## Collect the current body within maxBody and the original request deadline.
  ## Use readBody for large bodies that should stay out of memory.
  result = ""
  var bytes = default(array[8192, char])
  while true:
    let n = readBody(c, bytes, dl)
    if n == 0: return
    appendBytes(result, toOpenArray(bytes, 0, n - 1))
