## HTTP/1.x heads and request serialization, independent of I/O.
import std/strutils
from std/http/httpparse import MaxHeadLen, MaxHeaderCount
import ./[head, buffer]

type
  Header* = object
    name*, value*: string
  HttpResponse* = object
    status*: int
    headers*: seq[Header] ## Wire order, with lowercase names; duplicate fields preserved.
  BodyFraming* = enum
    bodyNone, bodyLength, bodyChunked, bodyEof
  ResponseHead* = object
    response*: HttpResponse
    framing*: BodyFraming
    length*: int
    keepAlive*: bool

const ReservedRequestHeaders = ["host", "content-length", "transfer-encoding",
  "connection", "upgrade", "expect"]

proc header*(response: HttpResponse; name: string; default = ""): string =
  ## First matching value, or default. Iterate headers to retain duplicate values.
  for h in response.headers:
    if sameIgnoreCase(h.name, name): return h.value
  result = default

proc contentLength(s: openArray[char]; n: var int): bool =
  ## RFC 9112 §6.3: digits only and no overflow; anything else is unrecoverable.
  if s.len == 0: return false
  n = 0
  for c in s:
    if c notin {'0'..'9'}: return false
    let d = ord(c) - ord('0')
    if n > (high(int) - d) div 10: return false
    n = n * 10 + d
  result = true

proc parseResponseHead*(head: openArray[char]; meth: string): ResponseHead {.raises.} =
  ## Parse a complete head in one pass. HEAD, informational, 204 and 304
  ## responses have no body. Reject ambiguous framing; unsupported transfers and
  ## upgrades cannot be reused. Lines may end in CRLF or a bare LF (RFC 9112 §2.2).
  result = ResponseHead()
  if head.len > MaxHeadLen: raise ContentTooLong
  var status = 0
  var minor = 0
  var pos = parseStatusLine(head, status, minor)
  if pos < 0: raise SyntaxError
  result.response.status = status
  var length = -1
  var seenTransfer = false
  var chunked = false
  var close = false
  var keepAlive = false
  while true:
    let blank = parseHeadEnd(toOpenArray(head, pos, head.len - 1))
    if blank >= 0:
      pos += blank
      break
    if result.response.headers.len == MaxHeaderCount: raise ContentTooLong
    var f = Field()
    let n = parseField(toOpenArray(head, pos, head.len - 1), f)
    if n < 0: raise SyntaxError
    let name = copyLower(toOpenArray(head, pos, pos + f.nameLen - 1))
    let first = pos + f.valueStart
    let last = first + f.valueLen - 1
    case name
    of "content-length":
      if length >= 0 or not contentLength(toOpenArray(head, first, last), length):
        raise SyntaxError
    of "transfer-encoding":
      if seenTransfer: raise SyntaxError
      seenTransfer = true
      chunked = equalsLower(toOpenArray(head, first, last), "chunked")
    of "connection":
      close = close or hasToken(toOpenArray(head, first, last), "close")
      keepAlive = keepAlive or hasToken(toOpenArray(head, first, last), "keep-alive")
    else: discard
    result.response.headers.add Header(name: name, value: copyBytes(toOpenArray(head, first, last)))
    pos += n
  if pos != head.len: raise SyntaxError
  if seenTransfer and length >= 0: raise SyntaxError
  result.keepAlive = not close and (minor == 1 or keepAlive)
  if status == 101 or (meth == "CONNECT" and status in 200..299):
    raise UnimplementedOperation
  if meth == "HEAD" or status < 200 or status == 204 or status == 304:
    result.framing = bodyNone
  elif seenTransfer:
    if not chunked or minor != 1: raise UnimplementedOperation
    result.framing = bodyChunked
  elif length >= 0:
    result.framing = bodyLength
    result.length = length
  else:
    result.framing = bodyEof
    result.keepAlive = false

proc reservedRequestHeader(name: string): bool =
  result = false
  for reserved in ReservedRequestHeaders:
    if equalsLower(name, reserved): return true

proc requestHead*(authority, meth, target: string; length: int;
                  headers: seq[Header]): string {.raises.} =
  ## Build HTTP/1.1 framing for a complete in-memory request body.
  ## The client owns Host and body framing. Targets are already percent-encoded.
  ## Caller fields are checked for injection; the head itself is not size-limited.
  if not validToken(meth) or target.len == 0 or
      (target[0] != '/' and target != "*") or
      target.find({'\0'..' ', '\x7f', '#'}) >= 0:
    raise ValueError
  if meth == "CONNECT": raise UnimplementedOperation
  var size = meth.len + target.len + authority.len + 80
  var encoding = false
  for h in headers:
    if not validToken(h.name) or not cleanValue(h.value) or reservedRequestHeader(h.name):
      raise ValueError
    if equalsLower(h.name, "accept-encoding"): encoding = true
    size += h.name.len + h.value.len + 4
  result = newStringOfCap(size)
  result.add meth
  result.add ' '
  result.add target
  result.add " HTTP/1.1\r\nHost: "
  result.add authority
  result.add "\r\nContent-Length: "
  result.addInt length
  result.add "\r\n"
  for h in headers:
    result.add h.name
    result.add ": "
    result.add h.value
    result.add "\r\n"
  if not encoding: result.add "Accept-Encoding: identity\r\n"
  result.add "\r\n"
