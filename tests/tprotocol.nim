import testkit
import std/strutils
import tsuru/[frame, protocol]
import wire

block masking_vector:
  let wire = encodeFrame(opText, "Hello", [0x37'u8, 0xFA'u8, 0x21'u8, 0x3D'u8])
  doAssert wire == "\x81\x85\x37\xFA\x21\x3D\x7F\x9F\x4D\x51\x58"

block masking_lengths_and_reuse:
  let key = [0x37'u8, 0xFA'u8, 0x21'u8, 0x3D'u8]
  var buffer = ""
  for n in [65536, 126, 125, 33, 32, 31, 17, 16, 15, 9, 8, 7, 1, 0]:
    var data = newSeq[byte](n)
    for i in 0..<n: data[i] = byte(i and 255)
    encodeFrame(buffer, opBinary, data, key)
    let head = frameHeader(opBinary, n, key)
    doAssert buffer.len == head.len + n
    doAssert buffer[0..<head.len] == head
    for i in 0..<n:
      doAssert uint8(buffer[head.len + i]) == (data[i] xor key[i and 3])

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

block header_only:
  # The header parser never needs or copies the payload.
  var h = FrameHeader()
  let wire = serverFrame(opBinary, newString(70000), fin = false)
  let parsed = parseFrameHeader(toOpenArray(wire, 0, 9), h, 100000)
  doAssert parsed.status == psOk and parsed.consumed == 10
  doAssert h.length == 70000 and not h.fin and h.opcode == opBinary
  doAssert parseFrameHeader(toOpenArray(wire, 0, 9), h, 69999).status == psTooLarge
  doAssert parseFrameHeader(toOpenArray(wire, 0, 8), h).status == psIncomplete
  doAssert parseFrameHeader("\x89\x7e\x00\x7e", h).status == psError

block streamed_assembly:
  var s = MessageState()
  doAssert startData(s, FrameHeader(opcode: opText, length: 3), 8) == 0
  s.payload.add "\xe2\x82"
  doAssert startData(s, FrameHeader(opcode: opText, length: 1), 8) == 1002
  doAssert startData(s, FrameHeader(fin: true, opcode: opContinuation, length: 7), 8) == 1009
  doAssert startData(s, FrameHeader(fin: true, opcode: opContinuation, length: 1), 8) == 0
  s.payload.add "\xac"
  let a = finishMessage(s)
  doAssert a.kind == akMessage and a.data == "\xe2\x82\xac" and not a.binary
  doAssert s.payload.len == 0
  doAssert startData(s, FrameHeader(fin: true, opcode: opContinuation), 8) == 1002
  doAssert startData(s, FrameHeader(fin: true, opcode: opText, length: 1), 8) == 0
  s.payload.add "\xff"
  doAssert finishMessage(s).code == 1007
  var b = MessageState()
  doAssert startData(b, FrameHeader(fin: true, opcode: opBinary, length: 1), 1) == 0
  b.payload.add "\xff"
  doAssert finishMessage(b).binary

block controls:
  doAssert handleControl(opPing, "abc").kind == akPong
  doAssert handleControl(opPing, "abc").data == "abc"
  doAssert handleControl(opPong, "abc").kind == akNone
  for code in [999, 1004, 1005, 1006, 1015, 1016, 2999, 5000]:
    doAssert handleClose(closeBody(code)).code == 1002
  for code in [1000, 1003, 1007, 1014, 3000, 4999]:
    doAssert handleClose(closeBody(code, "ok")).code == code
  doAssert handleClose(closeBody(1000, "\xc3\x28")).code == 1007

block utf8_word_boundaries:
  # Multibyte sequences and errors at every offset across the 8/32-byte ASCII steps.
  for offset in 0..40:
    let prefix = repeat("a", offset)
    doAssert validUtf8(prefix & "\xf0\x9f\x98\x80" & repeat("b", 40))
    doAssert not validUtf8(prefix & "\x80" & repeat("b", 40))
    doAssert not validUtf8(prefix & "\xe2\x82")
    doAssert not validUtf8(repeat("c", 40) & prefix & "\xed\xa0\x80")

block closing:
  var s = MessageState()
  let a = handleFrame(s, Frame(fin: true, opcode: opClose, payload: closeBody(1001, "bye")))
  doAssert a.kind == akClose and a.code == 1001 and a.data == "bye"
  doAssert handleFrame(s, Frame(fin: true, opcode: opClose)).code == 1005
  doAssert handleFrame(s, Frame(fin: true, opcode: opClose, payload: "x")).code == 1002
  doAssert handleFrame(s, Frame(fin: true, opcode: opClose, payload: "\x03\xed")).code == 1002

echo "protocol tests passed"
