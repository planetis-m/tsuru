## A sequential, passive WebSocket client for Nimony on Linux.
##
## Own each connection from one task. recv automatically answers ping frames and
## assembles fragmented messages. Transport errors and timeouts close the socket
## and raise ErrorCode; argument validation errors leave the connection intact.
import std/[ioring, base64, strutils]
import tsuru/[protocol, handshake, transport]
export handshake.Header, handshake.WebSocketOptions, handshake.initWebSocketOptions
export ioring.Deadline, ioring.never, ioring.afterMs

type
  WebSocketState* = enum
    wsOpen, wsClosing, wsClosed
  MessageKind* = enum
    wmText, wmBinary, wmClose
  Message* = object
    kind*: MessageKind
    data*: string
      ## Message payload, or a close reason.
    code*: int
      ## Close status; 1005 means no status, 1006 means EOF without a close frame.
  WebSocket* = ref object
    ## A connection handle with shared identity; operations require one owning task.
    transport: Transport
    options: WebSocketOptions
    status: WebSocketState
    selectedProtocol: string
    buffer: string
    offset: int
    fragments: MessageState
    lastClose: Message

proc state*(ws: WebSocket): WebSocketState {.inline.} = ws.status
proc open*(ws: WebSocket): bool {.inline.} = ws.status == wsOpen
proc protocol*(ws: WebSocket): string {.inline.} = ws.selectedProtocol

proc abort*(ws: WebSocket) =
  ## Release the transport immediately without a close handshake. Idempotent.
  close(ws.transport)
  ws.status = wsClosed
  ws.buffer = ""
  ws.fragments = MessageState()

proc budget(ws: WebSocket; dl: Deadline): Deadline =
  earlier(afterMs(ws.options.timeoutMs), dl)

proc compact(ws: WebSocket) =
  if ws.offset > 0:
    if ws.offset == ws.buffer.len: ws.buffer = ""
    else: ws.buffer = ws.buffer[ws.offset..^1]
    ws.offset = 0

proc fill(ws: WebSocket; dl: Deadline): bool {.passive, raises.} =
  compact(ws)
  var buf = default(array[8192, char])
  let n = readSome(ws.transport, buf, dl)
  for i in 0..<n: ws.buffer.add buf[i]
  result = n > 0

proc clientFrame(op: Opcode; data: string; frame: var string) {.raises.} =
  let bytes = randomBytes(4)
  var key = default(array[4, uint8])
  for i in 0..3: key[i] = uint8(ord(bytes[i]))
  frame = encodeFrame(op, data, key)

proc emit(ws: WebSocket; op: Opcode; data: string; dl: Deadline) {.passive, raises.} =
  var frame = ""
  clientFrame(op, data, frame)
  writeAll(ws.transport, frame, dl)

proc prepareHandshake(url: string; options: WebSocketOptions; endpoint: var Endpoint;
                      key, request: var string) {.raises.} =
  endpoint = parseEndpoint(url)
  validateOptions(options)
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
  prepareHandshake(url, options, endpoint, key, request)
  let deadline = earlier(afterMs(options.timeoutMs), dl)
  result = WebSocket(transport: initTransport(), options: options, status: wsClosed,
    lastClose: Message(kind: wmClose, code: 1006))
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
    result.offset = endHead + 4
    result.status = wsOpen
  except ErrorCode as e:
    abort(result)
    raise e

proc send*(ws: WebSocket; data: string; binary = false; dl = never) {.passive, raises.} =
  ## Send one complete masked text/binary message. Text must be valid UTF-8.
  if ws.status != wsOpen: raise BadOperation
  if data.len > ws.options.maxMessage: raise ContentTooLong
  if not binary and not validUtf8(data): raise ValueError
  try:
    emit(ws, (if binary: opBinary else: opText), data, budget(ws, dl))
  except ErrorCode as e:
    abort(ws)
    raise e

proc ping*(ws: WebSocket; data = ""; dl = never) {.passive, raises.} =
  ## Send a ping of at most 125 bytes. recv consumes pong replies.
  if ws.status != wsOpen: raise BadOperation
  if data.len > 125: raise ContentTooLong
  try:
    emit(ws, opPing, data, budget(ws, dl))
  except ErrorCode as e:
    abort(ws)
    raise e

proc failProtocol(ws: WebSocket; code: int; dl: Deadline) {.passive, raises.} =
  if ws.status == wsOpen:
    try: emit(ws, opClose, closeBody(code), dl)
    except ErrorCode: discard
  ws.lastClose = Message(kind: wmClose, code: code)
  abort(ws)
  if code == 1009: raise ContentTooLong
  raise ValueError

proc recv*(ws: WebSocket; dl = never): Message {.passive, raises.} =
  ## Receive a complete message or wmClose. One deadline spans fragments and pings.
  ## A valid peer close is echoed exactly and releases the socket. EOF returns 1006.
  if ws.status == wsClosed: return ws.lastClose
  let deadline = budget(ws, dl)
  try:
    while ws.status != wsClosed:
      var frame = Frame()
      let parsed = parseFrame(ws.buffer, ws.offset, frame, max(ws.options.maxMessage, 125))
      case parsed.status
      of psIncomplete:
        if not fill(ws, deadline):
          ws.lastClose = Message(kind: wmClose, code: 1006)
          abort(ws)
          return ws.lastClose
      of psError: failProtocol(ws, 1002, deadline)
      of psTooLarge: failProtocol(ws, 1009, deadline)
      of psOk:
        ws.offset += parsed.consumed
        let action = handleFrame(ws.fragments, frame, ws.options.maxMessage)
        case action.kind
        of akNone: discard
        of akPong: emit(ws, opPong, action.data, deadline)
        of akMessage:
          if ws.status == wsOpen:
            return Message(kind: (if action.binary: wmBinary else: wmText), data: action.data)
        of akError: failProtocol(ws, action.code, deadline)
        of akClose:
          ws.lastClose = Message(kind: wmClose, data: action.data, code: action.code)
          if ws.status == wsOpen: emit(ws, opClose, frame.payload, deadline)
          abort(ws)
          return ws.lastClose
    result = ws.lastClose
  except ErrorCode as e:
    abort(ws)
    raise e

proc close*(ws: WebSocket; code = 1000; reason = ""; dl = never) {.passive, raises.} =
  ## Send close and await the peer's close, bounded by five seconds and dl.
  ## Idempotent once closed; abort releases the socket without waiting.
  if ws.status == wsClosed: return
  if not validCloseCode(code) or reason.len > 123 or not validUtf8(reason): raise ValueError
  let deadline = earlier(budget(ws, dl), afterMs(5000))
  try:
    if ws.status == wsOpen:
      emit(ws, opClose, closeBody(code, reason), deadline)
      ws.status = wsClosing
    while ws.status != wsClosed: discard recv(ws, deadline)
  except ErrorCode as e:
    abort(ws)
    raise e
