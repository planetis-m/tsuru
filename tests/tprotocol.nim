import testkit
import std/strutils
import tsuru/internal/[frame, protocol]
import wire

const DefaultMaxMessage = 16 * 1024 * 1024

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

proc only(wire: string; maxMessage = DefaultMaxMessage): Action =
  ## The single outcome of wire, delivered whole, bytewise and directly.
  var s = MessageState()
  let whole = feedAll(s, wire, maxMessage, [wire.len])
  doAssert whole.len == 1
  for direct in [false, true]:
    var t = MessageState()
    let bytewise = feedAll(t, wire, maxMessage, [1], direct)
    doAssert bytewise.len == 1 and bytewise[0].kind == whole[0].kind and
      bytewise[0].data == whole[0].data and bytewise[0].code == whole[0].code
  result = whole[0]

block frame_lengths:
  for n in [0, 125, 126, 65535, 65536]:
    var payload = newString(n)
    for i in 0..<n: payload[i] = char(i and 255)
    let wire = serverFrame(opBinary, payload)
    let a = only(wire, 100000)
    doAssert a.kind == akMessage and a.binary and a.data == payload
    for cut in [0, 1, wire.len - 1]:
      var s = MessageState()
      doAssert feedAll(s, wire[0..<cut], 100000, [1]).len == 0
  doAssert only("\x82\x7f\x80\0\0\0\0\0\0\0").code == 1002
  doAssert only("\x82\x7e\0\x01x").code == 1002
  doAssert only("\x82\x7f\0\0\0\0\0\0\0\x01x").code == 1002
  doAssert only("\x81\x80").code == 1002
  doAssert only("\xc1\0").code == 1002
  doAssert only("\x09\0").code == 1002
  doAssert only("\x83\0").code == 1002
  doAssert only("\x82\x7f\x7f\xff\xff\xff\xff\xff\xff\xff").code == 1009

block fragments_and_controls:
  let wire = serverFrame(opText, "\xc3", fin = false) & serverFrame(opPing, "p") &
    serverFrame(opPong, "q") & serverFrame(opContinuation, "", fin = false) &
    serverFrame(opContinuation, "\xa9") & serverFrame(opContinuation, "")
  for step in [1, 2, 3, 100]:
    for direct in [false, true]:
      var s = MessageState()
      let got = feedAll(s, wire, DefaultMaxMessage, [step], direct)
      doAssert got.len == 3
      doAssert got[0].kind == akPong and got[0].data == "p"
      doAssert got[1].kind == akMessage and got[1].data == "\xc3\xa9" and not got[1].binary
      doAssert got[2].kind == akError and got[2].code == 1002
  # A zero-length final frame completes a message without further input.
  var s = MessageState()
  var used = 0
  doAssert feed(s, serverFrame(opText, ""), 8, used).kind == akNone and used == 2
  let empty = feed(s, "", 8, used)
  doAssert empty.kind == akMessage and empty.data == "" and used == 0

block direct_payload:
  # Payload appended by the caller is accounted for and completes the frame.
  var s = MessageState()
  var used = 0
  let wire = serverFrame(opBinary, "abcdef")
  doAssert feed(s, toOpenArray(wire, 0, 3), 16, used).kind == akNone and used == 2
  doAssert feed(s, toOpenArray(wire, 2, 3), 16, used).kind == akIncomplete and used == 2
  doAssert payloadLeft(s) == 4
  s.payload.add "cdef"
  appended(s, 4)
  doAssert payloadLeft(s) == 0
  let a = feed(s, "", 16, used)
  doAssert a.kind == akMessage and a.data == "abcdef" and a.binary

block utf8_and_limits:
  for text in ["\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xc3", "\x80"]:
    doAssert not validUtf8(text)
  doAssert validUtf8("hello\0\xf0\x9f\x98\x80")
  doAssert only(serverFrame(opText, "\xff")).code == 1007
  doAssert only(serverFrame(opBinary, "123"), 2).code == 1009
  # The limit covers assembled fragments and is checked before their payload arrives.
  doAssert only(serverFrame(opBinary, "12", fin = false) &
                serverFrame(opContinuation, "34"), 3).code == 1009
  doAssert only(serverFrame(opBinary, "12", fin = false) &
                serverFrame(opContinuation, "34")[0..1], 3).code == 1009

block header_only:
  # The header parser never needs or copies the payload.
  var h = FrameHeader()
  let wire = serverFrame(opBinary, newString(70000), fin = false)
  let parsed = parseFrameHeader(toOpenArray(wire, 0, 9), h, 100000)
  doAssert parsed.status == psOk and parsed.consumed == 10
  doAssert h.length == 70000 and not h.fin and h.opcode == opBinary
  doAssert parseFrameHeader(toOpenArray(wire, 0, 9), h, 69999).status == psTooLarge
  doAssert parseFrameHeader(toOpenArray(wire, 0, 8), h, 100000).status == psIncomplete
  doAssert parseFrameHeader("\x89\x7e\x00\x7e", h, 100000).status == psError

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
  let a = only(serverFrame(opClose, closeBody(1001, "bye")))
  doAssert a.kind == akClose and a.code == 1001 and a.data == "bye"
  doAssert only(serverFrame(opClose, "")).code == 1005
  doAssert only(serverFrame(opClose, "x")).code == 1002
  doAssert only(serverFrame(opClose, "\x03\xed")).code == 1002

echo "protocol tests passed"
