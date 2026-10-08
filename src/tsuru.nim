## A sequential, passive WebSocket client for Nimony on Linux.
##
## Own each connection from one task. recv automatically answers ping frames and
## assembles fragmented messages. send, ping and close report success as a bool;
## recv reports ordinary deadline expiry as wmTimeout and termination as wmClose.
## close completes a bounded handshake. Connection setup raises ErrorCode on failure.
## Callers supply valid outgoing text and control payloads.
import std/[ioring, base64, strutils]
import tsuru/[frame, protocol, handshake]
import tsuru/internal/[transport, entropy, buffer]
export handshake.Header, handshake.WebSocketOptions, handshake.initWebSocketOptions
export ioring.Deadline, ioring.never, ioring.afterMs

const CloseWaitMs = 250

type
  WebSocketState* = enum
    wsClosed, wsOpen, wsClosing
  MessageKind* = enum
    wmText, wmBinary, wmClose, wmTimeout
  CloseSource* = enum
    csLocal, csPeer, csEof, csProtocolError, csTransportError, csTimeout
      ## Why the connection ended; only meaningful for wmClose.
  Message* = object
    kind*: MessageKind
    data*: string ## Message payload, or a close reason.
    code*: int ## Peer or locally generated protocol status; 1006 means abnormal closure or abort.
    closeSource*: CloseSource
  CloseInfo = object
    code: int
    reason: string
    source: CloseSource
  WebSocket* = ref object
    ## A connection handle with shared identity; operations require one owning task.
    transport: Transport
    maxMessage: int
    timeoutMs: int
    status: WebSocketState
    selectedProtocol: string
    buffer: string
    readBuffer: array[8192, byte]
    sendBuffer: string
    sent: int
    fragments: MessageState
    closure: CloseInfo

proc state*(ws: WebSocket): WebSocketState {.inline.} =
  ## Current state of the connection; does not suspend.
  ws.status

proc open*(ws: WebSocket): bool {.inline.} =
  ## Whether application messages may be sent; does not suspend.
  ws.status == wsOpen

proc protocol*(ws: WebSocket): string {.inline.} =
  ## Negotiated subprotocol, or empty if none was selected; does not suspend.
  ws.selectedProtocol

proc release(ws: WebSocket) =
  close(ws.transport)
  ws.status = wsClosed
  ws.buffer = ""
  ws.sendBuffer = ""
  ws.sent = 0
  ws.fragments = MessageState()

proc terminate(ws: WebSocket; source: CloseSource; code = 1006; reason = "") =
  ws.closure = CloseInfo(code: code, reason: reason, source: source)
  release(ws)

proc closedMessage(ws: WebSocket): Message =
  Message(kind: wmClose, data: ws.closure.reason,
    code: (if ws.closure.code == 0: 1006 else: ws.closure.code),
    closeSource: ws.closure.source)

proc abort*(ws: WebSocket) =
  ## Release immediately without a close handshake. Preserve an existing close result.
  if ws.status != wsClosed: terminate(ws, csLocal)
  else: release(ws)

proc transportFailed(ws: WebSocket; error: ErrorCode) =
  if ws.closure.code == 0:
    terminate(ws, (if error == TimeoutError: csTimeout else: csTransportError))
  else: release(ws)

proc budget(ws: WebSocket; dl: Deadline): Deadline =
  earlier(afterMs(ws.timeoutMs), dl)

proc fill(ws: WebSocket; dl: Deadline): bool {.passive, raises.} =
  let n = readSome(ws.transport, ws.readBuffer, dl)
  appendBytes(ws.buffer, toOpenArray(ws.readBuffer, 0, n - 1))
  result = n > 0

proc flush(ws: WebSocket; dl: Deadline) {.passive, raises.} =
  if ws.sent < ws.sendBuffer.len:
    writeAll(ws.transport,
      toOpenArray(readRawData(ws.sendBuffer), 0, ws.sendBuffer.len - 1), ws.sent, dl)

proc queueFrame[T: char | byte](ws: WebSocket; op: Opcode; data: openArray[T]) {.raises.} =
  var key = default(array[4, uint8])
  fillRandom(key)
  encodeFrame(ws.sendBuffer, op, data, key)
  ws.sent = 0

proc emit(ws: WebSocket; op: Opcode; data: string; dl: Deadline): bool {.passive.} =
  try:
    checkDeadline(dl)
    flush(ws, dl)
    queueFrame(ws, op, data)
    flush(ws, dl)
    result = true
  except ErrorCode as e:
    transportFailed(ws, e)
    result = false

proc emit(ws: WebSocket; op: Opcode; data: seq[byte]; dl: Deadline): bool {.passive.} =
  try:
    checkDeadline(dl)
    flush(ws, dl)
    queueFrame(ws, op, data)
    flush(ws, dl)
    result = true
  except ErrorCode as e:
    transportFailed(ws, e)
    result = false

proc prepareHandshake(url: string; options: WebSocketOptions; endpoint: var Endpoint;
                      key, request: var string) {.raises.} =
  endpoint = parseEndpoint(url)
  key = encode(randomBytes(16))
  request = buildRequest(endpoint, key, options)

proc checkHandshake(head, key: string; protocols: seq[string]; selected: var string) {.raises.} =
  selected = validateResponse(head, key, protocols)

proc connectWebSocket*(url: string; options = initWebSocketOptions(); dl = never): WebSocket
    {.passive, raises.} =
  ## Complete TCP, optional TLS and HTTP upgrade within a single operation budget.
  ## TLS requires -d:tsuruTls; unsupported wss raises UnimplementedOperation.
  var endpoint = Endpoint()
  var key = ""
  var request = ""
  let deadline = earlier(afterMs(options.timeoutMs), dl)
  prepareHandshake(url, options, endpoint, key, request)
  checkDeadline(deadline)
  result = WebSocket(maxMessage: options.maxMessage, timeoutMs: options.timeoutMs)
  try:
    open(result.transport, endpoint.host, endpoint.port, endpoint.secure,
         options.caFile, deadline)
    writeAll(result.transport, request, deadline)
    var endHead = -1
    while endHead < 0:
      if not fill(result, deadline): raise EndOfStreamError
      endHead = result.buffer.find("\r\n\r\n")
      if (endHead < 0 and result.buffer.len > MaxHandshake) or
          endHead > MaxHandshake - 4:
        raise ContentTooLong
    let head = result.buffer[0 .. endHead + 3]
    checkHandshake(head, key, options.protocols, result.selectedProtocol)
    checkDeadline(deadline)
    dropPrefix(result.buffer, endHead + 4)
    result.status = wsOpen
  except ErrorCode as e:
    terminate(result, csTransportError)
    raise e

proc send*(ws: WebSocket; data: string; binary = false; dl = never): bool {.passive.} =
  ## Send one masked message. The caller supplies valid UTF-8 for text messages.
  ## Return false unless open, or on a failed write; failures release it.
  if ws.status != wsOpen: return false
  result = emit(ws, (if binary: opBinary else: opText), data, budget(ws, dl))

proc send*(ws: WebSocket; data: seq[byte]; dl = never): bool {.passive.} =
  ## Send one binary message without converting bytes to a string.
  ## Return false unless open, or on a failed write; failures release it.
  if ws.status != wsOpen: return false
  result = emit(ws, opBinary, data, budget(ws, dl))

proc ping*(ws: WebSocket; data = ""; dl = never): bool {.passive.} =
  ## Send a ping of at most 125 bytes. recv consumes pong replies.
  ## Return false unless open, or on a failed write; failures release it.
  if ws.status != wsOpen: return false
  result = emit(ws, opPing, data, budget(ws, dl))

proc failProtocol(ws: WebSocket; code: int; dl: Deadline): Message {.passive.} =
  ws.closure = CloseInfo(code: code, source: csProtocolError)
  if ws.status == wsClosing or emit(ws, opClose, closeBody(code), dl): release(ws)
  result = closedMessage(ws)

proc recv*(ws: WebSocket; dl = never): Message {.passive.} =
  ## Receive a complete message, wmTimeout, or terminal wmClose.
  ## One deadline spans fragments and pings. Expiry preserves the live connection,
  ## partial input and pending control output for the next operation.
  ## Peer close, EOF, protocol failure and I/O failure all release the socket.
  if ws.status == wsClosed: return closedMessage(ws)
  let deadline = budget(ws, dl)
  try:
    while true:
      checkDeadline(deadline)
      flush(ws, deadline)
      var frame = Frame()
      let parsed = parseFrame(ws.buffer, 0, frame, max(ws.maxMessage, 125))
      case parsed.status
      of psIncomplete:
        if not fill(ws, deadline):
          terminate(ws, csEof)
          return closedMessage(ws)
      of psError: return failProtocol(ws, 1002, deadline)
      of psTooLarge: return failProtocol(ws, 1009, deadline)
      of psOk:
        checkDeadline(deadline)
        dropPrefix(ws.buffer, parsed.consumed)
        let action = handleFrame(ws.fragments, frame, ws.maxMessage)
        case action.kind
        of akNone: discard
        of akPong:
          queueFrame(ws, opPong, action.data)
          flush(ws, deadline)
        of akMessage:
          return Message(kind: (if action.binary: wmBinary else: wmText), data: action.data)
        of akError: return failProtocol(ws, action.code, deadline)
        of akClose:
          ws.closure = CloseInfo(code: action.code, reason: action.data, source: csPeer)
          if ws.status == wsClosing or emit(ws, opClose, frame.payload, deadline): release(ws)
          return closedMessage(ws)
  except ErrorCode as e:
    if e == TimeoutError:
      result = Message(kind: wmTimeout)
    else:
      transportFailed(ws, e)
      result = closedMessage(ws)

proc close*(ws: WebSocket; code = 1000; reason = ""; dl = never): bool {.passive.} =
  ## Send Close and await its reply within 250 ms, the operation budget and dl.
  ## Always release. Return true on a peer Close or if already closed, false on failure.
  ## abort releases immediately without a handshake.
  if ws.status == wsClosed: return true
  let deadline = earlier(afterMs(min(ws.timeoutMs, CloseWaitMs)), dl)
  if ws.status == wsOpen:
    if not emit(ws, opClose, closeBody(code, reason), deadline): return false
    ws.status = wsClosing
  result = waitClose(ws, deadline).closeSource == csPeer

proc waitClose*(ws: WebSocket; dl = never): Message {.passive.} =
  ## Receive until wmClose, discarding application messages and answering pings.
  ## Bound the wait by 250 ms, the operation budget and dl. Do not initiate close.
  ## Return the recorded result if closed; timeout releases with code 1006 and csTimeout.
  if ws.status == wsClosed: return closedMessage(ws)
  let deadline = earlier(afterMs(min(ws.timeoutMs, CloseWaitMs)), dl)
  while true:
    let message = recv(ws, deadline)
    if message.kind == wmClose: return message
    if message.kind == wmTimeout:
      terminate(ws, csTimeout)
      return closedMessage(ws)
