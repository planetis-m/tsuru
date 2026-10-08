## RFC 6455 client framing: parse unmasked server frames and encode masked sends.

const DefaultMaxMessage* = 16 * 1024 * 1024
  ## Default limit for a frame payload or an assembled message.

type
  Opcode* = enum
    ## RFC 6455 frame opcodes.
    opContinuation = 0, opText = 1, opBinary = 2, opClose = 8, opPing = 9, opPong = 10
  ParseStatus* = enum
    psIncomplete, psOk, psError, psTooLarge
  ParseResult* = object
    ## Parse outcome; consumed is nonzero only for psOk.
    status*: ParseStatus
    consumed*: int
  Frame* = object
    ## One unmasked server frame, owning its payload.
    fin*: bool
    opcode*: Opcode
    payload*: string

proc frameHeader*(op: Opcode; n: int; key: array[4, uint8]; fin = true): string =
  ## Encode a masked client header, including the key, for a payload of n bytes.
  ## n is nonnegative; control payloads are at most 125 bytes and have fin = true.
  result = ""
  result.add char(ord(op) or (if fin: 128 else: 0))
  let maskBit = 128
  if n < 126: result.add char(n or maskBit)
  elif n <= 65535:
    result.add char(126 or maskBit)
    result.add char((n shr 8) and 255)
    result.add char(n and 255)
  else:
    result.add char(127 or maskBit)
    for shift in countdown(7, 0):
      result.add char((uint64(n) shr (shift * 8)) and 255'u64)
  for b in key: result.add char(b)

proc maskInto*[T: char | byte](dest: var openArray[char]; source: openArray[T];
                              key: array[4, uint8]; offset = 0) =
  ## Mask source into dest[0..<source.len], leaving the rest of dest untouched.
  ## dest must be large enough; offset is the chunk's position within the payload.
  for i in 0..<source.len:
    dest[i] = char(ord(source[i]) xor int(key[(offset + i) and 3]))

proc encodeFrame*(op: Opcode; data: string; key: array[4, uint8]; fin = true): string =
  ## Encode a masked client frame. Supply a fresh cryptographic key for every call.
  result = frameHeader(op, data.len, key, fin)
  let headerLen = result.len
  var payload = toOpenArray(beginStore(result, headerLen + data.len, headerLen),
    0, data.len - 1)
  maskInto(toOpenArray(payload, 0, payload.len - 1), data, key)
  endStore(result)

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
