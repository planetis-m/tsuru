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

proc copyMasked[T: char | byte](dest: nil ptr UncheckedArray[char]; start: int;
                               source: openArray[T]; key: array[4, uint8]) =
  ## Copy and mask a complete payload into storage returned by beginStore.
  ## Fixed-size copies support unaligned buffers without typed pointer casts.
  var mask32 = 0'u32
  copyMem(addr mask32, addr key[0], sizeof(mask32))
  let mask64 = uint64(mask32) or (uint64(mask32) shl 32)
  var i = 0
  while source.len - i >= sizeof(uint64):
    var word = 0'u64
    copyMem(addr word, addr source[i], sizeof(word))
    word = word xor mask64
    copyMem(addr dest[start + i], addr word, sizeof(word))
    i += sizeof(word)
  while i < source.len:
    dest[start + i] = char(uint8(source[i]) xor key[i and 3])
    inc i

proc encodeFrame*[T: char | byte](dest: var string; op: Opcode; data: openArray[T];
                                  key: array[4, uint8]; fin = true) =
  ## Store one masked frame, reusing dest's capacity. data must not alias dest.
  ## Supply a fresh cryptographic key and valid outgoing payload for every frame.
  let head = frameHeader(op, data.len, key, fin)
  let total = head.len + data.len
  let output = beginStore(dest, total)
  copyMem(output, readRawData(head), head.len)
  copyMasked(output, head.len, data, key)
  endStore(dest)

proc encodeFrame*(op: Opcode; data: string; key: array[4, uint8]; fin = true): string =
  ## Encode a masked client frame. Supply a fresh cryptographic key for every call.
  result = ""
  encodeFrame(result, op, data, key, fin)

proc parseFrame*(data: string; start: int; frame: var Frame;
                 maxPayload = DefaultMaxMessage): ParseResult =
  ## Parse one unmasked server frame. Check lengths before allocation and indexing.
  ## The caller supplies 0 <= start <= data.len and a nonnegative maxPayload.
  result = ParseResult(status: psIncomplete)
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
