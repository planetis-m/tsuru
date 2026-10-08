## RFC 6455 framing and client protocol decisions, independent of socket I/O.
import std/[sha1, base64]

const DefaultMaxMessage* = 16 * 1024 * 1024

type
  Opcode* = enum
    opContinuation = 0, opText = 1, opBinary = 2, opClose = 8, opPing = 9, opPong = 10
  ParseStatus* = enum
    psIncomplete, psOk, psError, psTooLarge
  ParseResult* = object
    status*: ParseStatus
    consumed*: int
  Frame* = object
    fin*: bool
    opcode*: Opcode
    payload*: string
  ActionKind* = enum
    akNone, akMessage, akPong, akClose, akError
  Action* = object
    kind*: ActionKind
    data*: string
    binary*: bool
    code*: int
  MessageState* = object
    fragmented: bool
    binary: bool
    data: string

proc acceptKey*(key: string): string =
  ## Expected Sec-WebSocket-Accept for a client nonce.
  var ctx = newSha1State()
  ctx.update(key)
  ctx.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
  result = encode(ctx.finalize())

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

proc validCloseCode*(code: int): bool =
  ## Codes allowed on the wire, including registered and private use ranges.
  result = code in 3000..4999 or code in 1000..1003 or code in 1007..1014

proc closeBody*(code: int; reason = ""): string =
  ## Encode a validated close code and reason; validation belongs to the caller.
  result = ""
  result.add char((code shr 8) and 255)
  result.add char(code and 255)
  result.add reason

proc header(op: Opcode; n: int; fin, masked: bool): string =
  result = ""
  result.add char(ord(op) or (if fin: 128 else: 0))
  let maskBit = if masked: 128 else: 0
  if n < 126: result.add char(n or maskBit)
  elif n <= 65535:
    result.add char(126 or maskBit)
    result.add char((n shr 8) and 255)
    result.add char(n and 255)
  else:
    result.add char(127 or maskBit)
    for shift in countdown(7, 0):
      result.add char((uint64(n) shr (shift * 8)) and 255'u64)

proc encodeFrame*(op: Opcode; data: string; key: array[4, uint8]; fin = true): string =
  ## Encode a masked client frame. Supply a fresh cryptographic key for every call.
  result = header(op, data.len, fin, true)
  for b in key: result.add char(b)
  for i in 0..<data.len: result.add char(ord(data[i]) xor int(key[i and 3]))

proc serverFrame*(op: Opcode; data: string; fin = true): string =
  ## Unmasked frame encoder for deterministic protocol fixtures.
  result = header(op, data.len, fin, false)
  result.add data

proc parseFrame*(data: string; start: int; frame: var Frame;
                 maxPayload = DefaultMaxMessage): ParseResult =
  ## Parse one unmasked server frame. Check lengths before allocation and indexing.
  result = ParseResult(status: psIncomplete)
  if start < 0 or start > data.len or maxPayload < 0:
    return ParseResult(status: psError)
  let avail = data.len - start
  if avail < 2: return
  let b0 = ord(data[start])
  let b1 = ord(data[start + 1])
  let op = b0 and 15
  if (b0 and 112) != 0 or (b1 and 128) != 0 or op notin [0, 1, 2, 8, 9, 10]:
    return ParseResult(status: psError)
  let fin = (b0 and 128) != 0
  if op >= 8 and not fin: return ParseResult(status: psError)
  var size = uint64(b1 and 127)
  var head = 2
  if size == 126 or size == 127:
    let bytes = if size == 126: 2 else: 8
    head += bytes
    if avail < head: return
    size = 0'u64
    for i in 0..<bytes: size = (size shl 8) or uint64(ord(data[start + 2 + i]))
    if (bytes == 2 and size < 126) or (bytes == 8 and size < 65536) or
        (size shr 63) != 0:
      return ParseResult(status: psError)
  if op >= 8 and size > 125: return ParseResult(status: psError)
  if size > uint64(maxPayload): return ParseResult(status: psTooLarge)
  let n = int(size)
  if n > avail - head: return
  var opcode = opContinuation
  case op
  of 1: opcode = opText
  of 2: opcode = opBinary
  of 8: opcode = opClose
  of 9: opcode = opPing
  of 10: opcode = opPong
  else: discard
  frame = Frame(fin: fin, opcode: opcode)
  if n > 0: frame.payload = data[start + head .. start + head + n - 1]
  result = ParseResult(status: psOk, consumed: head + n)

proc failure(code: int): Action =
  Action(kind: akError, code: code)

proc handleFrame*(s: var MessageState; f: Frame;
                  maxMessage = DefaultMaxMessage): Action =
  ## Assemble messages, validate text and closes, and handle interleaved control frames.
  case f.opcode
  of opPing: result = Action(kind: akPong, data: f.payload)
  of opPong: result = Action(kind: akNone)
  of opClose:
    if f.payload.len == 0: return Action(kind: akClose, code: 1005)
    if f.payload.len == 1: return failure(1002)
    let code = (ord(f.payload[0]) shl 8) or ord(f.payload[1])
    if not validCloseCode(code): return failure(1002)
    let reason = if f.payload.len > 2: f.payload[2..^1] else: ""
    if not validUtf8(reason): return failure(1007)
    result = Action(kind: akClose, code: code, data: reason)
  of opText, opBinary, opContinuation:
    if maxMessage < 0 or f.payload.len > maxMessage: return failure(1009)
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
