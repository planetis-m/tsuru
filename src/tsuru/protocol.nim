## WebSocket message assembly, UTF-8 and close handling, independent of I/O.
import ./frame

type
  ActionKind* = enum
    akNone, akMessage, akPong, akClose, akError
  Action* = object
    ## A complete message, control reply or local protocol failure for the I/O loop.
    kind*: ActionKind
    data*: string
      ## Message bytes, pong bytes or peer close reason, according to kind.
    binary*: bool
      ## Message type for akMessage.
    code*: int
      ## Close status for akClose or local failure status for akError.
  MessageState* = object
    ## Owns an unfinished fragmented message between handleFrame calls.
    fragmented: bool
    binary: bool
    data: string

proc validUtf8*(s: string): bool =
  ## Strict RFC 3629 validation, including overlong and surrogate exclusions.
  var i = 0
  while i < s.len:
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
  result = ""
  result.add char((code shr 8) and 255)
  result.add char(code and 255)
  result.add reason

proc failure(code: int): Action =
  Action(kind: akError, code: code)

proc handleClose(f: Frame): Action =
  let n = f.payload.len
  if n == 0:
    return Action(kind: akClose, code: 1005)
  if n == 1:
    return failure(1002)
  let code = (ord(f.payload[0]) shl 8) or ord(f.payload[1])
  if not validCloseCode(code):
    return failure(1002)
  let reason = if n > 2: f.payload[2..^1] else: ""
  if not validUtf8(reason):
    return failure(1007)
  result = Action(kind: akClose, code: code, data: reason)

proc handleFrame*(s: var MessageState; f: Frame;
                  maxMessage = DefaultMaxMessage): Action =
  ## Assemble messages, validate text and closes, and handle interleaved control frames.
  ## Pass frames accepted by parseFrame; wire-level invariants belong to the parser.
  ## maxMessage is nonnegative.
  case f.opcode
  of opPing: result = Action(kind: akPong, data: f.payload)
  of opPong: result = Action(kind: akNone)
  of opClose: result = handleClose(f)
  of opText, opBinary, opContinuation:
    if f.payload.len > maxMessage: return failure(1009)
    if f.opcode == opContinuation:
      if not s.fragmented: return failure(1002)
      if s.data.len > maxMessage - f.payload.len: return failure(1009)
      s.data.add f.payload
    else:
      if s.fragmented: return failure(1002)
      s.binary = f.opcode == opBinary
      s.data = f.payload
    s.fragmented = not f.fin
    if f.fin:
      if not s.binary and not validUtf8(s.data): return failure(1007)
      result = Action(kind: akMessage, data: s.data, binary: s.binary)
      s.data = ""
    else: result = Action(kind: akNone)
