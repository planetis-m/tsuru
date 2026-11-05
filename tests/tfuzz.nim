## Seeded malformed-wire coverage. Check every successful parse stays inside its input.
import std/[random, unicode]
import testkit
import tsuru/[frame, protocol, handshake, http]

var rng = initRand(6455)
for iteration in 0..<100000:
  var wire = ""
  let n = rand(rng, 0..128)
  for i in 0..<n: wire.add char(rand(rng, 0..255))
  var f = Frame()
  let start = rand(rng, 0..n)
  let parsed = parseFrame(wire, start, f, 256)
  if parsed.status == psOk:
    doAssert parsed.consumed >= 2 and parsed.consumed <= wire.len - start
    doAssert f.payload.len <= 256
    var state = MessageState()
    let action = handleFrame(state, f, 256)
    doAssert action.kind in [akNone, akMessage, akPong, akClose, akError]
  else: doAssert parsed.consumed == 0
  doAssert validUtf8(wire) == (validateUtf8(wire) < 0)
  var h = FrameHeader()
  let header = parseFrameHeader(toOpenArray(wire, start, wire.len - 1), h, 256)
  doAssert header.status == parsed.status or
    (header.status == psOk and parsed.status == psIncomplete)
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

echo "200000 deterministic malformed-input cases passed"
