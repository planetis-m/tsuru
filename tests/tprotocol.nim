import testkit
import tsuru/protocol
import wire

block masking_vector:
  let wire = encodeFrame(opText, "Hello", [0x37'u8, 0xFA'u8, 0x21'u8, 0x3D'u8])
  doAssert wire == "\x81\x85\x37\xFA\x21\x3D\x7F\x9F\x4D\x51\x58"

block masking_slices:
  let key = [0x37'u8, 0xFA'u8, 0x21'u8, 0x3D'u8]
  var buffer = ['!', '\0', '\0', '\0', '\0', '\0', '!']
  maskInto(toOpenArray(buffer, 1, 3), "Hel", key)
  maskInto(toOpenArray(buffer, 4, 5), @[byte('l'), byte('o')], key, offset = 3)
  doAssert buffer == ['!', '\x7F', '\x9F', '\x4D', '\x51', '\x58', '!']

block frame_lengths:
  for n in [0, 125, 126, 65535, 65536]:
    let payload = newString(n)
    let wire = serverFrame(opBinary, payload)
    var f = Frame()
    let parsed = parseFrame(wire, 0, f, 100000)
    doAssert parsed.status == psOk and parsed.consumed == wire.len
    doAssert f.payload == payload
    doAssert parseFrame(wire, wire.len, f).status == psIncomplete
    for cut in [0, 1, wire.len - 1]:
      doAssert parseFrame(wire[0..<cut], 0, f).status == psIncomplete
  var f = Frame()
  doAssert parseFrame("\x82\x7f\x80\0\0\0\0\0\0\0", 0, f).status == psError
  doAssert parseFrame("\x82\x7e\0\x01x", 0, f).status == psError
  doAssert parseFrame("\x82\x7f\0\0\0\0\0\0\0\x01x", 0, f).status == psError
  doAssert parseFrame("\x81\x80", 0, f).status == psError
  doAssert parseFrame("\xc1\0", 0, f).status == psError
  doAssert parseFrame("\x09\0", 0, f).status == psError
  doAssert parseFrame("\x83\0", 0, f).status == psError
  doAssert parseFrame("", -1, f).status == psError
  doAssert parseFrame("\x82\x7f\x7f\xff\xff\xff\xff\xff\xff\xff", 0, f).status == psTooLarge

block fragments_and_controls:
  var s = MessageState()
  doAssert handleFrame(s, Frame(opcode: opText, payload: "\xc3")).kind == akNone
  doAssert handleFrame(s, Frame(fin: true, opcode: opPing, payload: "p")).kind == akPong
  let a = handleFrame(s, Frame(fin: true, opcode: opContinuation, payload: "\xa9"))
  doAssert a.kind == akMessage and a.data == "\xc3\xa9" and not a.binary
  doAssert handleFrame(s, Frame(fin: true, opcode: opContinuation)).code == 1002

block utf8_and_limits:
  for text in ["\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xc3", "\x80"]:
    doAssert not validUtf8(text)
  doAssert validUtf8("hello\0\xf0\x9f\x98\x80")
  var s = MessageState()
  doAssert handleFrame(s, Frame(fin: true, opcode: opText, payload: "\xff")).code == 1007
  doAssert handleFrame(s, Frame(fin: true, opcode: opBinary, payload: "123"), 2).code == 1009
  discard handleFrame(s, Frame(opcode: opBinary, payload: "12"), 3)
  doAssert handleFrame(s, Frame(fin: true, opcode: opContinuation, payload: "34"), 3).code == 1009

block closing:
  var s = MessageState()
  let a = handleFrame(s, Frame(fin: true, opcode: opClose, payload: closeBody(1001, "bye")))
  doAssert a.kind == akClose and a.code == 1001 and a.data == "bye"
  doAssert handleFrame(s, Frame(fin: true, opcode: opClose)).code == 1005
  doAssert handleFrame(s, Frame(fin: true, opcode: opClose, payload: "x")).code == 1002
  doAssert handleFrame(s, Frame(fin: true, opcode: opClose, payload: "\x03\xed")).code == 1002

echo "protocol tests passed"
