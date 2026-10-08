## A sequential, passive WebSocket client for Nimony on Linux.
##
## Own each connection from one task. recv automatically answers ping frames and
## assembles fragmented messages. Transport errors and timeouts close the socket
## and raise ErrorCode. Callers supply valid outgoing text and control payloads.
import std/[ioring, base64, strutils]
import tsuru/[frame, protocol, handshake]
import tsuru/internal/[transport, entropy, buffer]
export handshake.Header, handshake.WebSocketOptions, handshake.initWebSocketOptions
export ioring.Deadline, ioring.never, ioring.afterMs

type
  WebSocketState* = enum
    wsClosed, wsOpen, wsClosing
  MessageKind* = enum
    wmText, wmBinary, wmClose
  CloseSource* = enum
    csLocal, csPeer, csEof, csProtocolError, csTransportError
      ## Why the connection ended; only meaningful for wmClose.
  Message* = object
    kind*: MessageKind
    data*: string
      ## Message payload, or a close reason.
    code*: int
      ## Peer or locally generated protocol status; 1006 means abnormal/local closure.
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
    readBuffer: array[4096, byte]
    sendBuffer: seq[byte]
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
  ws.sendBuffer = @[]
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

proc transportFailed(ws: WebSocket) =
  if ws.closure.code == 0: terminate(ws, csTransportError)
  else: release(ws)

proc budget(ws: WebSocket; dl: Deadline): Deadline =
  earlier(afterMs(ws.timeoutMs), dl)

proc fill(ws: WebSocket; dl: Deadline): bool {.passive, raises.} =
  let n = readSome(ws.transport, ws.readBuffer, dl)
  appendBytes(ws.buffer, toOpenArray(ws.readBuffer, 0, n - 1))
  result = n > 0

proc fillSendBuf(ws: WebSocket; op: Opcode; data: string; key: array[4, uint8]): int =
  ## Coalesce the header and masked payload in the connection's reusable buffer.
  let head = frameHeader(op, data.len, key)
  let total = head.len + data.len
  if ws.sendBuffer.len < total:
    ws.sendBuffer.setLen(total)
  copyOut(toOpenArray(ws.sendBuffer, 0, head.len - 1), head)
  copyOut(toOpenArray(ws.sendBuffer, head.len, total - 1), data)
  maskPayload(toOpenArray(ws.sendBuffer, head.len, total - 1), key)
  result = total

proc fillSendBuf(ws: WebSocket; op: Opcode; data: openArray[byte];
                 key: array[4, uint8]): int =
  let head = frameHeader(op, data.len, key)
  let total = head.len + data.len
  if ws.sendBuffer.len < total:
    ws.sendBuffer.setLen(total)
  copyOut(toOpenArray(ws.sendBuffer, 0, head.len - 1), head)
  if data.len > 0:
    copyMem(addr ws.sendBuffer[head.len], addr data[0], data.len)
  maskPayload(toOpenArray(ws.sendBuffer, head.len, total - 1), key)
  result = total

proc emit(ws: WebSocket; op: Opcode; data: string; dl: Deadline) {.passive, raises.} =
  checkDeadline(dl)
  var key = default(array[4, uint8])
  fillRandom(key)
  let total = fillSendBuf(ws, op, data, key)
  writeAll(ws.transport, toOpenArray(ws.sendBuffer, 0, total - 1), dl)

proc emit(ws: WebSocket; op: Opcode; data: seq[byte]; dl: Deadline) {.passive, raises.} =
  checkDeadline(dl)
  var key = default(array[4, uint8])
  fillRandom(key)
  let total = fillSendBuf(ws, op, data, key)
  writeAll(ws.transport, toOpenArray(ws.sendBuffer, 0, total - 1), dl)

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

proc send*(ws: WebSocket; data: string; binary = false; dl = never) {.passive, raises.} =
  ## Send one masked message. The caller supplies valid UTF-8 for text messages.
  if ws.status != wsOpen: raise BadOperation
  let deadline = budget(ws, dl)
  try:
    emit(ws, (if binary: opBinary else: opText), data, deadline)
  except ErrorCode as e:
    transportFailed(ws)
    raise e

proc send*(ws: WebSocket; data: seq[byte]; binary = true; dl = never) {.passive, raises.} =
  ## Send bytes without converting to a string; binary by default, text if requested.
  if ws.status != wsOpen: raise BadOperation
  let deadline = budget(ws, dl)
  try:
    emit(ws, (if binary: opBinary else: opText), data, deadline)
  except ErrorCode as e:
    transportFailed(ws)
    raise e

proc ping*(ws: WebSocket; data = ""; dl = never) {.passive, raises.} =
  ## Send a ping of at most 125 bytes. recv consumes pong replies.
  if ws.status != wsOpen: raise BadOperation
  let deadline = budget(ws, dl)
  try:
    emit(ws, opPing, data, deadline)
  except ErrorCode as e:
    transportFailed(ws)
    raise e

proc failProtocol(ws: WebSocket; code: int; dl: Deadline) {.passive, raises.} =
  if ws.status == wsOpen:
    try: emit(ws, opClose, closeBody(code), dl)
    except ErrorCode: discard
  terminate(ws, csProtocolError, code)
  if code == 1009: raise ContentTooLong
  raise ValueError

proc recv*(ws: WebSocket; dl = never): Message {.passive, raises.} =
  ## Receive a complete message or wmClose. One deadline spans fragments and pings.
  ## A valid peer close is echoed exactly and releases the socket. EOF returns 1006.
  if ws.status == wsClosed: return closedMessage(ws)
  let deadline = budget(ws, dl)
  try:
    while ws.status != wsClosed:
      checkDeadline(deadline)
      var frame = Frame()
      let parsed = parseFrame(ws.buffer, 0, frame, max(ws.maxMessage, 125))
      case parsed.status
      of psIncomplete:
        if not fill(ws, deadline):
          terminate(ws, csEof)
          return closedMessage(ws)
      of psError: failProtocol(ws, 1002, deadline)
      of psTooLarge: failProtocol(ws, 1009, deadline)
      of psOk:
        dropPrefix(ws.buffer, parsed.consumed)
        let action = handleFrame(ws.fragments, frame, ws.maxMessage)
        checkDeadline(deadline)
        case action.kind
        of akNone: discard
        of akPong: emit(ws, opPong, action.data, deadline)
        of akMessage:
          if ws.status == wsOpen:
            return Message(kind: (if action.binary: wmBinary else: wmText), data: action.data)
        of akError: failProtocol(ws, action.code, deadline)
        of akClose:
          ws.closure = CloseInfo(code: action.code, reason: action.data, source: csPeer)
          if ws.status == wsOpen: emit(ws, opClose, frame.payload, deadline)
          release(ws)
          return closedMessage(ws)
    result = closedMessage(ws)
  except ErrorCode as e:
    transportFailed(ws)
    raise e

proc close*(ws: WebSocket; code = 1000; reason = ""; dl = never) {.passive, raises.} =
  ## Send close and await the peer's close, bounded by five seconds and dl.
  ## Idempotent once closed; abort releases the socket without waiting.
  if ws.status == wsClosed: return
  let deadline = earlier(budget(ws, dl), afterMs(5000))
  try:
    if ws.status == wsOpen:
      emit(ws, opClose, closeBody(code, reason), deadline)
      ws.status = wsClosing
    while ws.status != wsClosed: discard recv(ws, deadline)
  except ErrorCode as e:
    transportFailed(ws)
    raise e
