## URI parsing and HTTP upgrade validation for the client opening handshake.
import std/[strutils, sha1, base64]
from std/http/httpparse import MaxHeadLen
from tsuru/http import Header, validToken, cleanValue, hasToken
import tsuru/internal/endpoint
export Header, endpoint.Endpoint
from tsuru/frame import DefaultMaxMessage

const MaxHandshake* = MaxHeadLen

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

proc validateOptions*(options: WebSocketOptions) {.raises.} =
  ## Reject invalid limits and fields that could alter the upgrade request.
  if options.maxMessage <= 0 or options.timeoutMs <= 0 or not cleanValue(options.origin):
    raise ValueError
  if '\0' in options.caFile: raise ValueError
  for i in 0..<options.protocols.len:
    if not validToken(options.protocols[i]): raise ValueError
    for j in 0..<i:
      if options.protocols[i] == options.protocols[j]: raise ValueError
  for h in options.headers:
    if not validToken(h.name) or not cleanValue(h.value): raise ValueError
    let name = h.name.toLowerAscii()
    if name in ["host", "connection", "upgrade", "origin", "content-length",
        "transfer-encoding"] or name.startsWith("sec-websocket-"):
      raise ValueError

proc buildRequest*(e: Endpoint; key: string; options: WebSocketOptions): string {.raises.} =
  ## Build a bounded HTTP/1.1 request. Pass a parseEndpoint result and a base64 nonce.
  validateOptions(options)
  result = "GET " & e.target & " HTTP/1.1\r\nHost: " & e.authority &
    "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n" &
    "Sec-WebSocket-Key: " & key & "\r\n"
  if options.origin.len > 0: result.add "Origin: " & options.origin & "\r\n"
  if options.protocols.len > 0:
    result.add "Sec-WebSocket-Protocol: " & options.protocols.join(", ") & "\r\n"
  for h in options.headers: result.add h.name & ": " & h.value & "\r\n"
  result.add "\r\n"
  if result.len > MaxHandshake: raise ContentTooLong

proc validateResponse*(head, key: string; offered: seq[string]): string {.raises.} =
  ## Require 101, upgrade tokens, the exact accept key, and an offered subprotocol.
  ## Returns the negotiated subprotocol, or empty. Extensions are unsupported.
  if head.len > MaxHandshake or not head.endsWith("\r\n\r\n"): raise ValueError
  let lines = head.split("\r\n")
  if lines.len < 4: raise ValueError
  let status = lines[0]
  if status.len < 13 or status[0..<13] != "HTTP/1.1 101 ": raise ValueError
  if not cleanValue(status): raise ValueError
  var upgrade = ""
  var connection = ""
  var accept = ""
  var protocol = ""
  var seenAccept = false
  var seenProtocol = false
  for i in 1..<lines.len - 2:
    let line = lines[i]
    let colon = line.find(':')
    if colon <= 0: raise ValueError
    let name = line[0..<colon]
    let value = line[colon + 1..^1].strip(chars = {' ', '\t'})
    if not validToken(name) or not cleanValue(value): raise ValueError
    case name.toLowerAscii()
    of "upgrade": upgrade.add "," & value
    of "connection": connection.add "," & value
    of "sec-websocket-accept":
      if seenAccept: raise ValueError
      seenAccept = true
      accept = value
    of "sec-websocket-protocol":
      if seenProtocol or not validToken(value): raise ValueError
      seenProtocol = true
      protocol = value
    of "sec-websocket-extensions": raise ValueError
    else: discard
  if not hasToken(upgrade, "websocket") or not hasToken(connection, "upgrade") or
      accept != acceptKey(key): raise ValueError
  if seenProtocol and protocol notin offered: raise ValueError
  result = protocol
