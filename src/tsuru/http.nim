## HTTP/1.x heads and request serialization, independent of I/O.
import std/strutils
from std/http/httpparse import parseToken, parseStatus, parseReason,
  MaxHeadLen, MaxHeaderCount, MaxValueLen

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

proc validToken*(s: string): bool =
  s.len > 0 and parseToken(toOpenArray(s, 0, s.len - 1)) == s.len

proc cleanValue*(s: string): bool =
  s.find({'\0'..'\x1f', '\x7f'} - {'\t'}) == -1

proc hasToken*(value, token: string): bool =
  result = false
  for part in value.split(','):
    if part.strip().toLowerAscii() == token: return true

proc header*(response: HttpResponse; name: string; default = ""): string =
  ## First matching value, or default. Iterate headers to retain duplicate values.
  for h in response.headers:
    if h.name.cmpIgnoreCase(name) == 0: return h.value
  result = default

proc decimal(s: string): int {.raises.} =
  if s.len == 0: raise SyntaxError
  result = 0
  for c in s:
    if c notin {'0'..'9'}: raise SyntaxError
    let d = ord(c) - ord('0')
    if result > (high(int) - d) div 10: raise SyntaxError
    result = result * 10 + d

proc parseResponseHead*(head, meth: string): ResponseHead {.raises.} =
  ## Parse a complete head. HEAD, informational, 204 and 304 responses have no body.
  ## Reject ambiguous framing; unsupported transfers and upgrades cannot be reused.
  result = ResponseHead()
  if head.len > MaxHeadLen: raise ContentTooLong
  if not head.endsWith("\r\n\r\n"): raise SyntaxError
  let lines = head.split("\r\n")
  let line = lines[0]
  if line.len < 12 or line[0..7] notin ["HTTP/1.0", "HTTP/1.1"] or line[8] != ' ':
    raise SyntaxError
  var status = 0
  if parseStatus(toOpenArray(line, 9, line.len - 1), status) != 3: raise SyntaxError
  if line.len > 12:
    if line[12] != ' ' or parseReason(toOpenArray(head, 13, line.len + 1)) != line.len - 13:
      raise SyntaxError
  result.response.status = status
  if lines.len - 3 > MaxHeaderCount: raise ContentTooLong
  var length = -1
  var transfer = ""
  var seenTransfer = false
  var connection = ""
  for i in 1..<lines.len - 2:
    let colon = lines[i].find(':')
    if colon <= 0: raise SyntaxError
    let name = lines[i][0..<colon].toLowerAscii()
    let value = lines[i][colon + 1..^1].strip(chars = {' ', '\t'})
    if not validToken(name) or not cleanValue(value): raise SyntaxError
    if value.len > MaxValueLen: raise ContentTooLong
    result.response.headers.add Header(name: name, value: value)
    case name
    of "content-length":
      if length >= 0: raise SyntaxError
      length = decimal(value)
    of "transfer-encoding":
      if seenTransfer: raise SyntaxError
      seenTransfer = true
      transfer = value.toLowerAscii()
    of "connection": connection.add "," & value
    else: discard
  if seenTransfer and length >= 0: raise SyntaxError
  result.keepAlive = not hasToken(connection, "close") and
    (line[7] == '1' or hasToken(connection, "keep-alive"))
  if status == 101 or (meth == "CONNECT" and status in 200..299):
    raise UnimplementedOperation
  if meth == "HEAD" or status < 200 or status in [204, 304]:
    result.framing = bodyNone
  elif seenTransfer:
    if transfer != "chunked" or line[7] != '1': raise UnimplementedOperation
    result.framing = bodyChunked
  elif length >= 0:
    result.framing = bodyLength
    result.length = length
  else:
    result.framing = bodyEof
    result.keepAlive = false

proc requestHead*(authority, meth, target: string; length: int;
                  headers: seq[Header]): string {.raises.} =
  ## Build HTTP/1.1 framing for a complete in-memory request body.
  ## The client owns Host and body framing. Targets are already percent-encoded.
  if not validToken(meth) or target.len == 0 or
      (target[0] != '/' and target != "*") or
      target.find({'\0'..' ', '\x7f', '#'}) >= 0:
    raise ValueError
  if meth == "CONNECT": raise UnimplementedOperation
  result = meth & " " & target & " HTTP/1.1\r\nHost: " & authority &
    "\r\nContent-Length: " & $length & "\r\n"
  var encoding = false
  for h in headers:
    if not validToken(h.name) or not cleanValue(h.value): raise ValueError
    let name = h.name.toLowerAscii()
    if name in ["host", "content-length", "transfer-encoding", "connection", "upgrade", "expect"]:
      raise ValueError
    if name == "accept-encoding": encoding = true
    result.add h.name & ": " & h.value & "\r\n"
  if not encoding: result.add "Accept-Encoding: identity\r\n"
  result.add "\r\n"
  if result.len > MaxHeadLen: raise ContentTooLong
