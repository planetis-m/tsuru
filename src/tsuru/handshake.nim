## WebSocket opening request construction and HTTP upgrade validation.
import std/[strutils, sha1, base64]
from std/http/httpparse import MaxHeadLen
from tsuru/http import Header
import tsuru/internal/[endpoint, head, buffer]
export Header
from tsuru/frame import DefaultMaxMessage

const MaxHandshake* = MaxHeadLen
  ## Limit on the upgrade response head.

type
  WebSocketOptions* = object
    ## Limits and handshake fields. Construct with initWebSocketOptions.
    maxMessage*: int
    timeoutMs*: int
      ## Per-operation budget, including all fragments/control frames in recv.
    origin*: string
    protocols*: seq[string]
    headers*: seq[Header]
    caFile*: string
      ## Optional CA file for TLS; empty uses OpenSSL's system trust paths.

const ReservedHandshakeHeaders = ["host", "connection", "upgrade", "origin",
  "content-length", "transfer-encoding"]

proc initWebSocketOptions*(maxMessage: Positive = DefaultMaxMessage;
                           timeoutMs: Positive = 30_000): WebSocketOptions =
  ## Default to a 16 MiB message limit and a 30 second operation budget.
  WebSocketOptions(maxMessage: maxMessage, timeoutMs: timeoutMs)

proc acceptKey*(key: string): string =
  ## Expected Sec-WebSocket-Accept for a client nonce.
  var ctx = newSha1State()
  ctx.update(key)
  ctx.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
  result = encode(ctx.finalize())

proc parseEndpoint*(url: string): Endpoint {.raises.} =
  ## Parse ws/wss URLs, preserving the encoded request target.
  endpoint.parseEndpoint(url, "ws", "wss")

proc reservedHandshakeHeader(name: string): bool =
  if name.len >= 14 and sameIgnoreCase(toOpenArray(name, 0, 13), "sec-websocket-"):
    return true
  result = false
  for reserved in ReservedHandshakeHeaders:
    if equalsLower(name, reserved): return true

proc validateOptions*(options: WebSocketOptions) {.raises.} =
  ## Reject invalid limits and fields that could alter the upgrade request.
  ## Offered subprotocols must be distinct tokens (RFC 6455 §4.1).
  if options.maxMessage <= 0 or options.timeoutMs <= 0 or not cleanValue(options.origin):
    raise ValueError
  if '\0' in options.caFile: raise ValueError
  for i in 0..<options.protocols.len:
    if not validToken(options.protocols[i]): raise ValueError
    for j in 0..<i:
      if options.protocols[i] == options.protocols[j]: raise ValueError
  for h in options.headers:
    if not validToken(h.name) or not cleanValue(h.value) or
        reservedHandshakeHeader(h.name):
      raise ValueError

proc buildRequest*(e: Endpoint; key: string; options: WebSocketOptions): string {.raises.} =
  ## Build the HTTP/1.1 upgrade request. Pass a parseEndpoint result and a base64 nonce.
  validateOptions(options)
  result = newStringOfCap(160 + e.target.len + e.authority.len + options.origin.len)
  result.add "GET "
  result.add e.target
  result.add " HTTP/1.1\r\nHost: "
  result.add e.authority
  result.add "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
  result.add "Sec-WebSocket-Key: "
  result.add key
  result.add "\r\n"
  if options.origin.len > 0:
    result.add "Origin: "
    result.add options.origin
    result.add "\r\n"
  if options.protocols.len > 0:
    result.add "Sec-WebSocket-Protocol: "
    result.add options.protocols.join(", ")
    result.add "\r\n"
  for h in options.headers:
    result.add h.name
    result.add ": "
    result.add h.value
    result.add "\r\n"
  result.add "\r\n"

proc validateResponse*(head: openArray[char]; key: string; offered: seq[string]): string
    {.raises.} =
  ## Require 101, upgrade tokens, the exact accept key, and an offered subprotocol
  ## (RFC 6455 §4.1). Returns the negotiated subprotocol, or empty. Extensions are
  ## unsupported. The head is tokenized once by the shared HTTP scanner.
  if head.len > MaxHandshake: raise ValueError
  var status = 0
  var minor = 0
  var pos = parseStatusLine(head, status, minor)
  if pos < 0 or status != 101 or minor != 1: raise ValueError
  var upgrade = false
  var connection = false
  var accept = false
  var seenProtocol = false
  result = ""
  let expected = acceptKey(key)
  while true:
    let blank = parseHeadEnd(toOpenArray(head, pos, head.len - 1))
    if blank >= 0:
      pos += blank
      break
    var f = Field()
    let n = parseField(toOpenArray(head, pos, head.len - 1), f)
    if n < 0: raise ValueError
    let name = toOpenArray(head, pos, pos + f.nameLen - 1)
    let value = toOpenArray(head, pos + f.valueStart, pos + f.valueStart + f.valueLen - 1)
    if equalsLower(name, "upgrade"):
      upgrade = upgrade or hasToken(value, "websocket")
    elif equalsLower(name, "connection"):
      connection = connection or hasToken(value, "upgrade")
    elif equalsLower(name, "sec-websocket-accept"):
      if accept: raise ValueError
      accept = true
      if not equals(value, expected): raise ValueError
    elif equalsLower(name, "sec-websocket-protocol"):
      if seenProtocol: raise ValueError
      seenProtocol = true
      result = copyBytes(value)
    elif equalsLower(name, "sec-websocket-extensions"):
      raise ValueError
    pos += n
  if pos != head.len or not upgrade or not connection or not accept: raise ValueError
  if seenProtocol and result notin offered: raise ValueError
