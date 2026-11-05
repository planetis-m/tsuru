## Seeded malformed-wire coverage. Check every successful parse stays inside its
## input, and drive the client's receive path (protocol.feed) with random reads.
import std/[random, unicode]
import testkit
import tsuru/[frame, protocol, handshake, http]
import wire

var rng = initRand(6455)

proc model(wire: string; maxMessage: int): seq[Action] =
  ## Independent reference: whole frames from parseFrameHeader, assembled here.
  result = @[]
  var pos = 0
  var message = ""
  var binary = false
  var fragmented = false
  while true:
    var h = FrameHeader()
    let parsed = parseFrameHeader(toOpenArray(wire, pos, wire.len - 1), h, max(maxMessage, 125))
    case parsed.status
    of psIncomplete: return
    of psError:
      result.add Action(kind: akError, code: 1002)
      return
    of psTooLarge:
      result.add Action(kind: akError, code: 1009)
      return
    of psOk: discard
    let first = pos + parsed.consumed
    if not h.opcode.isControl:
      # Fragment order and the limit are judged on the header alone.
      if (h.opcode == opContinuation) != fragmented:
        result.add Action(kind: akError, code: 1002)
        return
      if h.opcode != opContinuation:
        message = ""
        binary = h.opcode == opBinary
      if h.length > maxMessage - message.len:
        result.add Action(kind: akError, code: 1009)
        return
    if h.length > wire.len - first: return
    let payload = wire.substr(first, first + h.length - 1)
    pos = first + h.length
    case h.opcode
    of opPing: result.add Action(kind: akPong, data: payload)
    of opPong: discard
    of opClose:
      let a = handleClose(payload)
      result.add a
      return
    else:
      message.add payload
      fragmented = not h.fin
      if h.fin:
        if not binary and not validUtf8(message):
          result.add Action(kind: akError, code: 1007)
          return
        result.add Action(kind: akMessage, data: message, binary: binary)

proc randomSteps(rng: var Rand): seq[int] =
  result = @[]
  for i in 0..rand(rng, 0..3):
    result.add(if rand(rng, 0..3) == 0: rand(rng, 1..300) else: rand(rng, 1..4))

proc checkFeed(rng: var Rand; wire: string; maxMessage: int) =
  ## The receive path agrees with the model for any read sizes, with and
  ## without direct payload reads.
  let expected = model(wire, maxMessage)
  var s = MessageState()
  let got = feedAll(s, wire, maxMessage, randomSteps(rng), rand(rng, 0..1) == 1)
  doAssert got.len == expected.len
  for i in 0..<got.len:
    doAssert got[i].kind == expected[i].kind and got[i].code == expected[i].code and
      got[i].data == expected[i].data and got[i].binary == expected[i].binary
    if got[i].kind == akMessage: doAssert got[i].data.len <= maxMessage

const Texts = ["", "a", "hello", "\xc3", "\xa9", "\xe2\x82\xac", "\xff", "\xed\xa0\x80"]

proc randomFrames(rng: var Rand): string =
  ## Mostly valid frame sequences: fragments, interleaved controls, boundary
  ## lengths, invalid text and order violations.
  result = ""
  for i in 0..rand(rng, 0..6):
    let k = rand(rng, 0..99)
    var data = ""
    if k < 50:
      if rand(rng, 0..1) == 0: data = Texts[rand(rng, 0..Texts.len - 1)]
      else:
        for j in 0..<[0, 1, 125, 126, 300, 65536][rand(rng, 0..5)]: data.add char(rand(rng, 0..255))
    let op = if k < 35: [opText, opBinary, opContinuation][rand(rng, 0..2)]
             elif k < 50: opContinuation
             elif k < 70: opPing
             elif k < 85: opPong
             elif k < 95: opClose
             else: opText
    if op == opClose:
      data = (if rand(rng, 0..3) == 0: "" else: closeBody([1000, 1001, 1005, 3000, 999][rand(rng, 0..4)],
                                                        Texts[rand(rng, 0..Texts.len - 1)]))
    elif op.isControl: data = Texts[rand(rng, 0..Texts.len - 1)]
    result.add serverFrame(op, data, fin = op.isControl or rand(rng, 0..2) > 0)
  for i in 0..<rand(rng, 0..2):
    if result.len > 0: result[rand(rng, 0..result.len - 1)] = char(rand(rng, 0..255))
  if result.len > 0 and rand(rng, 0..3) == 0: result.setLen(rand(rng, 0..result.len - 1))

for iteration in 0..<100000:
  var wire = ""
  let n = rand(rng, 0..128)
  for i in 0..<n: wire.add char(rand(rng, 0..255))
  let start = rand(rng, 0..n)
  var h = FrameHeader()
  let header = parseFrameHeader(toOpenArray(wire, start, wire.len - 1), h, 256)
  if header.status == psOk:
    doAssert header.consumed >= 2 and header.consumed <= wire.len - start
    doAssert h.length <= 256 and h.length >= 0
  else: doAssert header.consumed == 0
  checkFeed(rng, wire.substr(start), 256)
  doAssert validUtf8(wire) == (validateUtf8(wire) < 0)
  try: discard parseResponseHead(wire, "GET")
  except ErrorCode: discard
  try: discard parseEndpoint(wire)
  except ErrorCode: discard
  try: discard validateResponse(wire, "nonce", @[])
  except ErrorCode: discard

# Mostly-ASCII text with multibyte and invalid bytes: the word-at-a-time UTF-8
# check must agree with std/unicode at every alignment.
const Pieces = ["a", "abcdefgh", "\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x98\x80", "\x80",
  "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe2\x82", "\xff"]
for iteration in 0..<50000:
  var text = ""
  for i in 0..<rand(rng, 0..24):
    let k = rand(rng, 0..99)
    text.add(if k < 70: Pieces[k mod 2] elif k < 95: Pieces[2 + k mod 3] else: Pieces[5 + k mod 6])
  doAssert validUtf8(text) == (validateUtf8(text) < 0)

# Mutated valid heads reach deep into the HTTP tokenizer.
const Head = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n" &
  "Transfer-Encoding: chunked\r\nX-A: b\tc\r\n\r\n"
for iteration in 0..<50000:
  var head = Head
  for i in 0..rand(rng, 0..3):
    head[rand(rng, 0..head.len - 1)] = char(rand(rng, 0..255))
  try:
    let r = parseResponseHead(head, "GET")
    doAssert r.response.status in 100..599 and r.response.headers.len <= 100
  except ErrorCode: discard
  try: discard validateResponse(head, "nonce", @[])
  except ErrorCode: discard

# Generated frame sequences reach deep into the receive path.
for iteration in 0..<20000:
  checkFeed(rng, randomFrames(rng), [3, 125, 1000, 100000][rand(rng, 0..3)])

echo "220000 deterministic malformed-input cases passed"
