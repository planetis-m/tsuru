## A sequential, passive WebSocket client for Nimony on Linux.
##
## Own each connection from one task. recv automatically answers ping frames and
## assembles fragmented messages. send and ping report success as a bool;
## recv returns an optional message, with None on ordinary deadline expiry.
## close completes a bounded handshake and returns its terminal message.
## Connection setup raises ErrorCode on failure.
## Run parking operations in a passive task submitted to the application's pool.
## Callers supply valid outgoing text and control payloads.
import std/[ioring, base64, strutils, opt]
import tsuru/[frame, protocol, handshake]
import tsuru/internal/[transport, entropy, buffer]
export handshake.Header, handshake.WebSocketOptions, handshake.initWebSocketOptions
export ioring.Deadline, ioring.never, ioring.afterMs

const
  CloseWaitMs = 250
  AbnormalClosure = 1006

type
  WebSocketState* = enum
    wsClosed, wsOpen
  ConnectionPhase = enum
    connClosed, connOpen, connClosing
  MessageKind* = enum
    wmText, wmBinary, wmClose
  CloseSource* = enum
    csLocal, csPeer, csEof, csProtocolError, csTransportError, csTimeout
      ## Why the connection ended; only meaningful for wmClose.
  Message* = object
    kind*: MessageKind
    data*: string ## Message payload, or a close reason.
    code*: int ## Peer or locally generated protocol status; 1006 means abnormal closure or abort.
    closeSource*: CloseSource
  CloseInfo = object
    code: int ## Zero means no terminal outcome has been recorded.
    reason: string
    source: CloseSource
  WebSocket* = ref object
    ## A connection handle with shared identity; operations require one owning task.
    transport: Transport
    maxMessage: int
    timeoutMs: int
    status: ConnectionPhase
    selectedProtocol: string
    buffer: string
    readBuffer: array[8192, byte]
    sendBuffer: string
    sent: int ## Bytes written from sendBuffer; a paused pong preserves both across recv expiry.
    fragments: MessageState
    closure: CloseInfo

proc state*(ws: WebSocket): WebSocketState {.inline.} =
  ## Current state of the connection; does not suspend.
  if ws.status == connClosed: wsClosed else: wsOpen

proc open*(ws: WebSocket): bool {.inline.} =
  ## Whether application messages may be sent; does not suspend.
  ws.status == connOpen

proc protocol*(ws: WebSocket): string {.inline.} =
  ## Negotiated subprotocol, or empty if none was selected; does not suspend.
  ws.selectedProtocol

proc release(ws: WebSocket) =
  close(ws.transport)
  ws.status = connClosed
  ws.buffer = ""
  ws.sendBuffer = ""
  ws.sent = 0
  ws.fragments = MessageState()

proc terminate(ws: WebSocket; source: CloseSource; code = AbnormalClosure; reason = "") =
  ws.closure = CloseInfo(code: code, reason: reason, source: source)
  release(ws)

proc closedMessage(ws: WebSocket): Message =
  Message(kind: wmClose, data: ws.closure.reason,
    code: (if ws.closure.code == 0: AbnormalClosure else: ws.closure.code),
    closeSource: ws.closure.source)

proc abort*(ws: WebSocket) =
  ## Release immediately without a close handshake. Preserve an existing close result.
  if ws.status != connClosed: terminate(ws, csLocal)

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

proc prepareFrame[T: char | byte](ws: WebSocket; op: Opcode; data: openArray[T]) {.raises.} =
  ## Replace a fully flushed frame. Keep its bytes unchanged until flush completes.
  var key = default(array[4, uint8])
  fillRandom(key)
  encodeFrame(ws.sendBuffer, op, data, key)
  ws.sent = 0

proc emit(ws: WebSocket; op: Opcode; data: string; dl: Deadline): bool {.passive.} =
  try:
    checkDeadline(dl)
    flush(ws, dl)
    prepareFrame(ws, op, data)
    flush(ws, dl)
    result = true
  except ErrorCode as e:
    transportFailed(ws, e)
    result = false

proc emit(ws: WebSocket; op: Opcode; data: seq[byte]; dl: Deadline): bool {.passive.} =
  try:
    checkDeadline(dl)
    flush(ws, dl)
    prepareFrame(ws, op, data)
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
    writeAll(result.transport,
      toOpenArray(readRawDataStable(request), 0, request.len - 1), deadline)
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
    result.status = connOpen
  except ErrorCode as e:
    terminate(result, csTransportError)
    raise e

proc send*(ws: WebSocket; data: string; binary = false; dl = never): bool {.passive.} =
  ## Send one masked message. The caller supplies valid UTF-8 for text messages.
  ## Return false unless open, or on a failed write; failures release it.
  if ws.status != connOpen: return false
  result = emit(ws, (if binary: opBinary else: opText), data, budget(ws, dl))

proc send*(ws: WebSocket; data: seq[byte]; dl = never): bool {.passive.} =
  ## Send one binary message without converting bytes to a string.
  ## Return false unless open, or on a failed write; failures release it.
  if ws.status != connOpen: return false
  result = emit(ws, opBinary, data, budget(ws, dl))

proc ping*(ws: WebSocket; data = ""; dl = never): bool {.passive.} =
  ## Send a ping of at most 125 bytes. recv consumes pong replies.
  ## Return false unless open, or on a failed write; failures release it.
  if ws.status != connOpen: return false
  result = emit(ws, opPing, data, budget(ws, dl))

proc failProtocol(ws: WebSocket; code: int; dl: Deadline): Message {.passive.} =
  ws.closure = CloseInfo(code: code, source: csProtocolError)
  if ws.status == connClosing or emit(ws, opClose, closeBody(code), dl): release(ws)
  result = closedMessage(ws)

proc recv*(ws: WebSocket; dl = never): Opt[Message] {.passive.} =
  ## Receive Some(complete message or terminal wmClose), or None on deadline expiry.
  ## One deadline spans fragments and pings. Expiry preserves the live connection,
  ## partial input and pending control output for the next operation.
  ## Peer close, EOF, protocol failure and I/O failure all release the socket.
  if ws.status == connClosed: return some(closedMessage(ws))
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
          return some(closedMessage(ws))
      of psError: return some(failProtocol(ws, 1002, deadline))
      of psTooLarge: return some(failProtocol(ws, 1009, deadline))
      of psOk:
        checkDeadline(deadline)
        dropPrefix(ws.buffer, parsed.consumed)
        let action = handleFrame(ws.fragments, frame, ws.maxMessage)
        case action.kind
        of akNone: discard
        of akPong:
          prepareFrame(ws, opPong, action.data)
          flush(ws, deadline)
        of akMessage:
          return some(Message(kind: (if action.binary: wmBinary else: wmText), data: action.data))
        of akError: return some(failProtocol(ws, action.code, deadline))
        of akClose:
          ws.closure = CloseInfo(code: action.code, reason: action.data, source: csPeer)
          if ws.status == connClosing or emit(ws, opClose, frame.payload, deadline): release(ws)
          return some(closedMessage(ws))
  except ErrorCode as e:
    if e == TimeoutError:
      result = none[Message]()
    else:
      transportFailed(ws, e)
      result = some(closedMessage(ws))

proc close*(ws: WebSocket; code = 1000; reason = ""; dl = never): Message {.passive.} =
  ## Send Close and await its reply within 250 ms, the operation budget and dl.
  ## Always release and return the terminal outcome; csPeer means a peer Close arrived.
  ## Return the recorded outcome if already closed.
  ## abort releases immediately without a handshake.
  if ws.status == connClosed: return closedMessage(ws)
  let deadline = earlier(afterMs(min(ws.timeoutMs, CloseWaitMs)), dl)
  if ws.status == connOpen:
    if not emit(ws, opClose, closeBody(code, reason), deadline): return closedMessage(ws)
    ws.status = connClosing
  while true:
    case recv(ws, deadline)
    of Some(message):
      if message.kind == wmClose: return message
    of None():
      terminate(ws, csTimeout)
      return closedMessage(ws)
