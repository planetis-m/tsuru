## Seeded malformed-wire coverage. Check every successful parse stays inside its input.
import std/random
import testkit
import tsuru/[protocol, handshake]

var rng = initRand(6455)
for iteration in 0..<100000:
  var wire = ""
  let n = rand(rng, 0..128)
  for i in 0..<n: wire.add char(rand(rng, 0..255))
  var f = Frame()
  let start = rand(rng, -2..n + 2)
  let parsed = parseFrame(wire, start, f, 256)
  if parsed.status == psOk:
    doAssert parsed.consumed >= 2 and parsed.consumed <= wire.len - start
    doAssert f.payload.len <= 256
    var state = MessageState()
    let action = handleFrame(state, f, 256)
    doAssert action.kind in [akNone, akMessage, akPong, akClose, akError]
  else: doAssert parsed.consumed == 0
  discard validUtf8(wire)
  try: discard parseEndpoint(wire)
  except ErrorCode: discard
  try: discard validateResponse(wire, "nonce", @[])
  except ErrorCode: discard

echo "100000 deterministic malformed-input cases passed"
