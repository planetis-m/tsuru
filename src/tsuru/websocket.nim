## A sequential, passive WebSocket client for Nimony on Linux.
##
## Own each connection from one task. recv automatically answers ping frames and
## assembles fragmented messages. send and ping report success as a bool;
## recv returns an optional message, with None on ordinary deadline expiry.
## close completes a bounded handshake and returns its terminal message.
## Connection setup raises ErrorCode on failure.
## Run parking operations in a passive task submitted to the application's pool.
## Callers supply valid outgoing text and control payloads.
import std/[ioring, base64, opt]
from std/http/httpparse import HeadScanner, findHeadEnd, ParseBad
import tsuru/[frame, protocol, handshake]
import tsuru/internal/[transport, entropy, buffer, input]
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
    input: Input
    frameLeft: int ## Payload bytes of the current data frame not yet assembled.
    frameFin: bool
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
  clear(ws.input)
  ws.frameLeft = 0
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
  ## One buffered read; false at end of stream.
  fill(ws.input, ws.transport, dl) > 0

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

proc emit[T: char | byte](ws: WebSocket; op: Opcode; data: openArray[T]; dl: Deadline): bool
    {.passive.} =
  try:
    checkDeadline(dl)
    flush(ws, dl)
    prepareFrame(ws, op, data)
    flush(ws, dl)
    result = true
  except ErrorCode as e:
    transportFailed(ws, e)
    result = false

proc connectWebSocket*(url: string; options = initWebSocketOptions(); dl = never): WebSocket
    {.passive, raises.} =
  ## Complete TCP, optional TLS and HTTP upgrade within a single operation budget.
  ## TLS requires -d:tsuruTls; unsupported wss raises UnimplementedOperation.
  let deadline = earlier(afterMs(options.timeoutMs), dl)
  let endpoint = parseEndpoint(url)
  let key = encode(randomBytes(16))
  let request = buildRequest(endpoint, key, options)
  checkDeadline(deadline)
  result = WebSocket(maxMessage: options.maxMessage, timeoutMs: options.timeoutMs,
                     input: initInput())
  try:
    open(result.transport, endpoint.host, endpoint.port, endpoint.secure,
         options.caFile, deadline)
    writeAll(result.transport, toOpenArray(request, 0, request.len - 1), deadline)
    var scan = HeadScanner()
    var headLen = -1
    while headLen < 0:
      if not fill(result, deadline): raise EndOfStreamError
      headLen = findHeadEnd(scan, result.input.data)
      if headLen == ParseBad: raise ContentTooLong
    result.selectedProtocol = validateResponse(
      toOpenArray(result.input.data, 0, headLen - 1), key, options.protocols)
    result.input.pos = headLen
    result.status = connOpen
  except ErrorCode as e:
    terminate(result, csTransportError)
    raise e

proc send*(ws: WebSocket; data: string; binary = false; dl = never): bool {.passive.} =
  ## Send one masked message. The caller supplies valid UTF-8 for text messages.
  ## Return false unless open, or on a failed write; failures release it.
  if ws.status != connOpen: return false
  result = emit(ws, (if binary: opBinary else: opText), toOpenArray(data, 0, data.len - 1),
                budget(ws, dl))

proc send*(ws: WebSocket; data: seq[byte]; dl = never): bool {.passive.} =
  ## Send one binary message without converting bytes to a string.
  ## Return false unless open, or on a failed write; failures release it.
  if ws.status != connOpen: return false
  result = emit(ws, opBinary, toOpenArray(data, 0, data.len - 1), budget(ws, dl))

proc ping*(ws: WebSocket; data = ""; dl = never): bool {.passive.} =
  ## Send a ping of at most 125 bytes. recv consumes pong replies.
  ## Return false unless open, or on a failed write; failures release it.
  if ws.status != connOpen: return false
  result = emit(ws, opPing, toOpenArray(data, 0, data.len - 1), budget(ws, dl))

proc failProtocol(ws: WebSocket; code: int; dl: Deadline): Message {.passive.} =
  ws.closure = CloseInfo(code: code, source: csProtocolError)
  let body = closeBody(code)
  if ws.status == connClosing or emit(ws, opClose, toOpenArray(body, 0, body.len - 1), dl):
    release(ws)
  result = closedMessage(ws)

proc assembleBuffered(ws: WebSocket) =
  ## Append the buffered part of the current data frame to the message.
  let n = min(buffered(ws.input), ws.frameLeft)
  appendBytes(ws.fragments.payload,
    toOpenArray(ws.input.data, ws.input.pos, ws.input.pos + n - 1))
  ws.input.pos += n
  ws.frameLeft -= n

proc readPayload(ws: WebSocket; dl: Deadline): bool {.passive, raises.} =
  ## With nothing buffered, read a large payload remainder straight into the
  ## message, otherwise refill the input. False at EOF.
  if ws.frameLeft >= DirectRead:
    let n = readInto(ws.transport, ws.fragments.payload, ws.frameLeft, dl)
    ws.frameLeft -= n
    result = n > 0
  else:
    result = fill(ws, dl)

proc peerClosed(ws: WebSocket; action: Action; payload: string; dl: Deadline): Message
    {.passive.} =
  ws.closure = CloseInfo(code: action.code, reason: action.data, source: csPeer)
  if ws.status == connClosing or emit(ws, opClose, toOpenArray(payload, 0, payload.len - 1), dl):
    release(ws)
  result = closedMessage(ws)

proc recv*(ws: WebSocket; dl = never): Opt[Message] {.passive.} =
  ## Receive Some(complete message or terminal wmClose), or None on deadline expiry.
  ## One deadline spans fragments and pings. Expiry preserves the live connection,
  ## partial input and pending control output for the next operation.
  ## Peer close, EOF, protocol failure and I/O failure all release the socket.
  if ws.status == connClosed: return some(closedMessage(ws))
  let deadline = budget(ws, dl)
  try:
    checkDeadline(deadline)
    while true:
      flush(ws, deadline)
      if ws.frameLeft > 0:
        if buffered(ws.input) > 0:
          assembleBuffered(ws)
        elif not readPayload(ws, deadline):
          terminate(ws, csEof)
          return some(closedMessage(ws))
        if ws.frameLeft == 0 and ws.frameFin:
          let action = finishMessage(ws.fragments)
          if action.kind == akError: return some(failProtocol(ws, action.code, deadline))
          return some(Message(kind: (if action.binary: wmBinary else: wmText),
                              data: action.data))
        continue
      var h = FrameHeader()
      let parsed = parseFrameHeader(unread(ws.input), h,
                                    max(ws.maxMessage, 125))
      case parsed.status
      of psIncomplete:
        if not fill(ws, deadline):
          terminate(ws, csEof)
          return some(closedMessage(ws))
      of psError: return some(failProtocol(ws, 1002, deadline))
      of psTooLarge: return some(failProtocol(ws, 1009, deadline))
      of psOk:
        if h.opcode.isControl:
          let first = ws.input.pos + parsed.consumed
          if h.length > ws.input.data.len - first:
            if not fill(ws, deadline):
              terminate(ws, csEof)
              return some(closedMessage(ws))
            continue
          ws.input.pos = first + h.length
          let action = handleControl(h.opcode,
            toOpenArray(ws.input.data, first, first + h.length - 1))
          case action.kind
          of akPong:
            prepareFrame(ws, opPong, toOpenArray(action.data, 0, action.data.len - 1))
            flush(ws, deadline)
          of akClose:
            let payload = ws.input.data.substr(first, first + h.length - 1)
            return some(peerClosed(ws, action, payload, deadline))
          of akError: return some(failProtocol(ws, action.code, deadline))
          of akNone, akMessage: discard
        else:
          let code = startData(ws.fragments, h, ws.maxMessage)
          if code != 0: return some(failProtocol(ws, code, deadline))
          ws.input.pos += parsed.consumed
          ws.frameLeft = h.length
          ws.frameFin = h.fin
          if h.length == 0 and h.fin:
            let action = finishMessage(ws.fragments)
            if action.kind == akError: return some(failProtocol(ws, action.code, deadline))
            return some(Message(kind: (if action.binary: wmBinary else: wmText),
                                data: action.data))
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
    let body = closeBody(code, reason)
    if not emit(ws, opClose, toOpenArray(body, 0, body.len - 1), deadline):
      return closedMessage(ws)
    ws.status = connClosing
  while true:
    case recv(ws, deadline)
    of Some(message):
      if message.kind == wmClose: return message
    of None():
      terminate(ws, csTimeout)
      return closedMessage(ws)
