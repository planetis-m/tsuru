## WebSocket message assembly, UTF-8 and close handling, independent of I/O.
import ./frame
import ./internal/buffer

type
  ActionKind* = enum
    akNone, akMessage, akPong, akClose, akError
  Action* = object
    ## A complete message, control reply or local protocol failure for the I/O loop.
    kind*: ActionKind
    data*: string ## Message bytes, pong bytes or peer close reason, according to kind.
    binary*: bool ## Message type for akMessage.
    code*: int ## Close status for akClose or local failure status for akError.
  MessageState* = object
    ## Owns an unfinished message between frames: data frames append their
    ## payload to it as it arrives, and the finished message is moved out.
    fragmented: bool ## A started message still expects frames.
    binary: bool ## Meaningful only while a message is assembled.
    data: string

const AsciiMask = 0x8080_8080_8080_8080'u64

proc validUtf8*(s: openArray[char]): bool =
  ## Strict RFC 3629 validation, including overlong and surrogate exclusions.
  ## ASCII runs are checked 32 or 8 bytes at a time.
  var i = 0
  while i < s.len:
    if s.len - i >= 32:
      var words = default(array[4, uint64])
      copyMem(addr words[0], addr s[i], sizeof(words))
      if ((words[0] or words[1] or words[2] or words[3]) and AsciiMask) == 0:
        i += 32
        continue
    if s.len - i >= 8:
      var word = 0'u64
      copyMem(addr word, addr s[i], sizeof(word))
      if (word and AsciiMask) == 0:
        i += 8
        continue
    let c = ord(s[i])
    if c < 128:
      inc i
    else:
      var n = 0
      var lo = 128
      var hi = 191
      if c in 0xC2..0xDF: n = 2
      elif c in 0xE0..0xEF:
        n = 3
        if c == 0xE0: lo = 0xA0
        if c == 0xED: hi = 0x9F
      elif c in 0xF0..0xF4:
        n = 4
        if c == 0xF0: lo = 0x90
        if c == 0xF4: hi = 0x8F
      else: return false
      if s.len - i < n: return false
      if ord(s[i + 1]) < lo or ord(s[i + 1]) > hi: return false
      for j in 2..<n:
        if ord(s[i + j]) notin 128..191: return false
      i += n
  result = true

proc validCloseCode(code: int): bool =
  ## Codes allowed on the wire, including registered and private use ranges.
  result = code in 3000..4999 or code in 1000..1003 or code in 1007..1014

proc closeBody*(code: int; reason = ""): string =
  ## Encode a validated close code and reason; validation belongs to the caller.
  result = newStringOfCap(2 + reason.len)
  result.add char((code shr 8) and 255)
  result.add char(code and 255)
  result.add reason

proc failure(code: int): Action =
  Action(kind: akError, code: code)

proc handleClose*(payload: openArray[char]): Action =
  ## Decode a peer Close: code and UTF-8 reason (RFC 6455 §5.5.1, §7.4).
  let n = payload.len
  if n == 0:
    return Action(kind: akClose, code: 1005)
  if n == 1:
    return failure(1002)
  let code = (ord(payload[0]) shl 8) or ord(payload[1])
  if not validCloseCode(code):
    return failure(1002)
  if not validUtf8(toOpenArray(payload, 2, n - 1)):
    return failure(1007)
  result = Action(kind: akClose, code: code, data: copyBytes(toOpenArray(payload, 2, n - 1)))

proc handleControl*(op: Opcode; payload: openArray[char]): Action =
  ## Ping, pong or close; op must be a control opcode.
  case op
  of opPing: result = Action(kind: akPong, data: copyBytes(payload))
  of opClose: result = handleClose(payload)
  else: result = Action(kind: akNone)

proc startData*(s: var MessageState; h: FrameHeader; maxMessage: int): int =
  ## Accept a data frame header: zero, or the close code that fails the
  ## connection. Enforces fragment order (RFC 6455 §5.4) and the message limit
  ## before any payload is stored. maxMessage is nonnegative.
  if h.opcode == opContinuation:
    if not s.fragmented: return 1002
  else:
    if s.fragmented: return 1002
    s.binary = h.opcode == opBinary
    s.data.setLen(0)
  if h.length > maxMessage - s.data.len: return 1009
  s.fragmented = not h.fin
  result = 0

proc payload*(s: var MessageState): var string {.inline.} =
  ## The message under assembly; frame payloads are appended to it in place.
  s.data

proc finishMessage*(s: var MessageState): Action =
  ## Complete the message after its final frame: validate text, then move the
  ## assembled bytes out without copying.
  if not s.binary and not validUtf8(s.data): return failure(1007)
  result = Action(kind: akMessage, binary: s.binary, data: move s.data)
  s.data = ""

proc handleFrame*(s: var MessageState; f: Frame;
                  maxMessage = DefaultMaxMessage): Action =
  ## Assemble messages, validate text and closes, and handle interleaved control frames.
  ## Pass frames accepted by parseFrame; wire-level invariants belong to the parser.
  ## maxMessage is nonnegative.
  if f.opcode.isControl:
    return handleControl(f.opcode, f.payload)
  let code = startData(s, FrameHeader(fin: f.fin, opcode: f.opcode,
                                      length: f.payload.len), maxMessage)
  if code != 0: return failure(code)
  s.data.add f.payload
  if f.fin: result = finishMessage(s)
  else: result = Action(kind: akNone)
