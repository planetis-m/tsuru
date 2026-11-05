## A sequential, passive WebSocket client for Nimony on Linux.
##
## Own each connection from one task. recv automatically answers ping frames and
## assembles fragmented messages. send and ping report success as a bool;
## recv returns an optional message, with None on ordinary deadline expiry.
## close completes a bounded handshake and returns its terminal message.
## Connection setup raises ErrorCode on failure.
## Run parking operations in a passive task submitted to the application's pool.
## Callers supply valid UTF-8 for text messages.
##
## Concurrent operations on one connection are unsupported, including a send
## while another task is parked in recv. Let one task own the connection and
## receive in short slices, sending queued messages between them; see
## examples/pump.nim.
import std/[ioring, base64, opt]
from std/http/httpparse import HeadScanner, findHeadEnd, ParseBad
import tsuru/internal/[frame, protocol, handshake, http, transport, entropy, input]
export http.Header, http.HttpResponse, http.header
export ioring.Deadline, ioring.never, ioring.afterMs

const
  DefaultConnectMs* = 10_000
    ## How long connectWebSocket waits for TCP, TLS and the upgrade by default.
  DefaultMaxMessage = 16 * 1024 * 1024
  AbnormalClosure = 1006
  MaxControlPayload = 125
  MaxCloseReason = MaxControlPayload - 2

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
    live: bool ## Open for application messages; false once released.
    selectedProtocol: string
    input: Input
    sendBuffer: string
    sent: int ## Bytes written from sendBuffer; a paused pong preserves both across recv expiry.
    message: MessageState ## Frame progress and the message under assembly.
    closure: CloseInfo

proc initWebSocketOptions*(maxMessage: Positive = DefaultMaxMessage;
                           timeoutMs: Positive = 30_000): WebSocketOptions =
  ## Default to a 16 MiB message limit and a 30 second operation budget.
  WebSocketOptions(maxMessage: maxMessage, timeoutMs: timeoutMs)

proc open*(ws: WebSocket): bool {.inline.} =
  ## Whether application messages may be sent; does not suspend.
  ws.live

proc protocol*(ws: WebSocket): string {.inline.} =
  ## Negotiated subprotocol, or empty if none was selected; does not suspend.
  ws.selectedProtocol

proc release(ws: WebSocket) =
  close(ws.transport)
  ws.live = false
  clear(ws.input)
  ws.sendBuffer = ""
  ws.sent = 0
  ws.message = MessageState()

proc terminate(ws: WebSocket; source: CloseSource; code = AbnormalClosure; reason = "") =
  ws.closure = CloseInfo(code: code, reason: reason, source: source)
  release(ws)

proc closedMessage(ws: WebSocket): Message =
  Message(kind: wmClose, data: ws.closure.reason,
    code: (if ws.closure.code == 0: AbnormalClosure else: ws.closure.code),
    closeSource: ws.closure.source)

proc abort*(ws: WebSocket) =
  ## Release immediately without a close handshake. Preserve an existing close result.
  if ws.live: terminate(ws, csLocal)

proc transportFailed(ws: WebSocket; error: ErrorCode) =
  if ws.closure.code == 0:
    terminate(ws, (if error == TimeoutError: csTimeout else: csTransportError))
  else: release(ws)

proc budget(ws: WebSocket; dl: Deadline): Deadline =
  earlier(afterMs(ws.timeoutMs), dl)

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

proc connectWebSocket*(url: string; dl = afterMs(DefaultConnectMs);
                       options = initWebSocketOptions()): WebSocket {.passive, raises.} =
  ## Complete TCP, optional TLS and HTTP upgrade within the options' operation
  ## budget, tightened by dl (ten seconds from the call by default).
  ## TLS requires -d:tsuruTls; unsupported wss raises UnimplementedOperation.
  if options.maxMessage <= 0 or options.timeoutMs <= 0 or '\0' in options.caFile:
    raise ValueError
  let deadline = earlier(afterMs(options.timeoutMs), dl)
  let endpoint = parseEndpoint(url)
  let key = encode(randomBytes(16))
  let request = buildRequest(endpoint, key, options.origin, options.protocols, options.headers)
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
      if fill(result.input, result.transport, deadline) == 0: raise EndOfStreamError
      headLen = findHeadEnd(scan, result.input.data)
      if headLen == ParseBad: raise ContentTooLong
    result.selectedProtocol = validateResponse(
      toOpenArray(result.input.data, 0, headLen - 1), key, options.protocols)
    result.input.pos = headLen
    result.live = true
  except ErrorCode as e:
    terminate(result, csTransportError)
    raise e

proc send*(ws: WebSocket; data: string; binary = false; dl = never): bool {.passive.} =
  ## Send one masked message. The caller supplies valid UTF-8 for text messages.
  ## Return false unless open, or on a failed write; failures release it.
  if not ws.live: return false
  result = emit(ws, (if binary: opBinary else: opText), toOpenArray(data, 0, data.len - 1),
                budget(ws, dl))

proc send*(ws: WebSocket; data: seq[byte]; dl = never): bool {.passive.} =
  ## Send one binary message without converting bytes to a string.
  ## Return false unless open, or on a failed write; failures release it.
  if not ws.live: return false
  result = emit(ws, opBinary, toOpenArray(data, 0, data.len - 1), budget(ws, dl))

proc ping*(ws: WebSocket; data = ""; dl = never): bool {.passive, raises.} =
  ## Send a ping of at most 125 bytes. recv consumes pong replies.
  ## Return false unless open, or on a failed write; failures release it.
  ## A longer payload raises BadOperation before any I/O and keeps the connection.
  if data.len > MaxControlPayload: raise BadOperation
  if not ws.live: return false
  result = emit(ws, opPing, toOpenArray(data, 0, data.len - 1), budget(ws, dl))

proc closeWith(ws: WebSocket; code: int; reason: string; source: CloseSource;
               payload: string; closeSent: bool; dl: Deadline): Message {.passive.} =
  ## Record the outcome, answer with a Close frame unless closeSent, then
  ## release; TLS connections also send close_notify.
  ws.closure = CloseInfo(code: code, reason: reason, source: source)
  if closeSent or emit(ws, opClose, toOpenArray(payload, 0, payload.len - 1), dl):
    closeNotify(ws.transport)
    release(ws)
  result = closedMessage(ws)

proc failProtocol(ws: WebSocket; code: int; closeSent: bool; dl: Deadline): Message
    {.passive.} =
  closeWith(ws, code, "", csProtocolError, closeBody(code), closeSent, dl)

proc eof(ws: WebSocket): Message =
  terminate(ws, csEof)
  closedMessage(ws)

proc readMore(ws: WebSocket; dl: Deadline): bool {.passive, raises.} =
  ## With nothing buffered, read a large payload remainder straight into the
  ## message, otherwise refill the input. False at end of stream.
  let left = payloadLeft(ws.message)
  if left >= DirectRead and buffered(ws.input) == 0:
    let n = readInto(ws.transport, ws.message.payload, left, dl)
    appended(ws.message, n)
    result = n > 0
  else:
    result = fill(ws.input, ws.transport, dl) > 0

proc receive(ws: WebSocket; deadline: Deadline; closeSent: bool): Opt[Message]
    {.passive.} =
  ## recv under an absolute deadline; closeSent suppresses a second Close frame.
  if not ws.live: return some(closedMessage(ws))
  try:
    checkDeadline(deadline)
    while true:
      flush(ws, deadline)
      var used = 0
      let action = feed(ws.message, unread(ws.input), ws.maxMessage, used)
      ws.input.pos += used
      case action.kind
      of akNone: discard
      of akIncomplete:
        if not readMore(ws, deadline): return some(eof(ws))
      of akMessage:
        return some(Message(kind: (if action.binary: wmBinary else: wmText),
                            data: action.data))
      of akPong:
        prepareFrame(ws, opPong, toOpenArray(action.data, 0, action.data.len - 1))
        flush(ws, deadline)
      of akClose:
        # Echo the peer's code and reason; a Close without a code is echoed empty.
        let payload = if action.code == 1005: "" else: closeBody(action.code, action.data)
        return some(closeWith(ws, action.code, action.data, csPeer, payload,
                              closeSent, deadline))
      of akError: return some(failProtocol(ws, action.code, closeSent, deadline))
  except ErrorCode as e:
    if e == TimeoutError:
      result = none[Message]()
    else:
      transportFailed(ws, e)
      result = some(closedMessage(ws))

proc recv*(ws: WebSocket; dl = never): Opt[Message] {.passive.} =
  ## Receive Some(complete message or terminal wmClose), or None on deadline expiry.
  ## One deadline spans fragments and pings. Expiry preserves the live connection,
  ## partial input and pending control output for the next operation.
  ## Peer close, EOF, protocol failure and I/O failure all release the socket;
  ## a protocol failure first sends a Close frame and, over TLS, close_notify.
  result = receive(ws, budget(ws, dl), false)

proc close*(ws: WebSocket; code = 1000; reason = ""; dl = afterMs(1000)): Message
    {.passive, raises, discardable.} =
  ## Send Close and await the peer's Close within dl and the operation budget.
  ## Always release and return the terminal outcome; csPeer means a peer Close arrived.
  ## Return the recorded outcome if already closed.
  ## An invalid code or a reason over 123 bytes raises BadOperation before any
  ## I/O and keeps the connection. abort releases immediately without a handshake.
  if not validCloseCode(code) or reason.len > MaxCloseReason: raise BadOperation
  if not ws.live: return closedMessage(ws)
  let deadline = budget(ws, dl)
  let body = closeBody(code, reason)
  if not emit(ws, opClose, toOpenArray(body, 0, body.len - 1), deadline):
    return closedMessage(ws)
  while true:
    case receive(ws, deadline, true)
    of Some(message):
      if message.kind == wmClose: return message
    of None():
      terminate(ws, csTimeout)
      return closedMessage(ws)
