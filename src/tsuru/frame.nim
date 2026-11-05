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
  FrameHeader* = object
    ## A validated server frame header; the payload follows it on the wire.
    fin*: bool
    opcode*: Opcode
    length*: int

proc isControl*(op: Opcode): bool {.inline.} = ord(op) >= 8

proc headerLen(n: int): int {.inline.} =
  ## Bytes of a masked client header, including the key, for n payload bytes.
  (if n < 126: 2 elif n <= 65535: 4 else: 10) + 4

proc fillHeader(dest: nil ptr UncheckedArray[char]; op: Opcode; n: int;
                key: array[4, uint8]; fin: bool): int =
  ## Spell a masked header into storage returned by beginStore; return its length.
  dest[0] = char(ord(op) or (if fin: 128 else: 0))
  var i = 2
  if n < 126:
    dest[1] = char(n or 128)
  elif n <= 65535:
    dest[1] = char(126 or 128)
    dest[2] = char((n shr 8) and 255)
    dest[3] = char(n and 255)
    i = 4
  else:
    dest[1] = char(127 or 128)
    for k in 0..7:
      dest[2 + k] = char((uint64(n) shr ((7 - k) * 8)) and 255'u64)
    i = 10
  for k in 0..3: dest[i + k] = char(key[k])
  result = i + 4

proc frameHeader*(op: Opcode; n: int; key: array[4, uint8]; fin = true): string =
  ## Encode a masked client header, including the key, for a payload of n bytes.
  ## n is nonnegative; control payloads are at most 125 bytes and have fin = true.
  result = ""
  discard fillHeader(beginStore(result, headerLen(n)), op, n, key, fin)
  endStore(result)

proc copyMasked[T: char | byte](dest: nil ptr UncheckedArray[char]; start: int;
                               source: openArray[T]; key: array[4, uint8]) =
  ## Copy and mask a complete payload into storage returned by beginStore.
  ## Fixed-size copies support unaligned buffers without typed pointer casts.
  var mask32 = 0'u32
  copyMem(addr mask32, addr key[0], sizeof(mask32))
  let mask64 = uint64(mask32) or (uint64(mask32) shl 32)
  var i = 0
  while source.len - i >= 32:
    var words = default(array[4, uint64])
    copyMem(addr words[0], addr source[i], sizeof(words))
    for k in 0..3: words[k] = words[k] xor mask64
    copyMem(addr dest[start + i], addr words[0], sizeof(words))
    i += 32
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
  ## The header is written in place; nothing else is allocated.
  let head = headerLen(data.len)
  let output = beginStore(dest, head + data.len)
  discard fillHeader(output, op, data.len, key, fin)
  copyMasked(output, head, data, key)
  endStore(dest)

proc encodeFrame*(op: Opcode; data: string; key: array[4, uint8]; fin = true): string =
  ## Encode a masked client frame. Supply a fresh cryptographic key for every call.
  result = ""
  encodeFrame(result, op, data, key, fin)

proc parseFrameHeader*(data: openArray[char]; h: var FrameHeader;
                       maxPayload = DefaultMaxMessage): ParseResult =
  ## Parse and validate one server frame header at the front of data without
  ## touching its payload; consumed is the header length. Rejects masking, RSV
  ## bits, unknown opcodes, fragmented or long controls and non-minimal lengths
  ## (RFC 6455 §5.1, §5.2, §5.5). A nonnegative maxPayload bounds the length
  ## before any allocation.
  result = ParseResult(status: psIncomplete)
  if data.len < 2: return
  let b0 = ord(data[0])
  let b1 = ord(data[1])
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
    if data.len < head: return
    size = 0'u64
    for i in 0..<bytes: size = (size shl 8) or uint64(ord(data[2 + i]))
    if (bytes == 2 and size < 126) or (bytes == 8 and size < 65536) or
        (size shr 63) != 0:
      return ParseResult(status: psError)
  if op >= 8 and size > 125: return ParseResult(status: psError)
  if size > uint64(maxPayload): return ParseResult(status: psTooLarge)
  var opcode = opContinuation
  case op
  of 1: opcode = opText
  of 2: opcode = opBinary
  of 8: opcode = opClose
  of 9: opcode = opPing
  of 10: opcode = opPong
  else: discard
  h = FrameHeader(fin: fin, opcode: opcode, length: int(size))
  result = ParseResult(status: psOk, consumed: head)
