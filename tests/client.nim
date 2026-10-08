## Network test driver. The Python runner supplies independent wire fixtures.
import std/[cmdline, syncio, threadpool, ioring, atomics, strutils]
import tsuru
import testkit

var done: int
var failed: int

proc dropConnection(url: string) {.passive, raises.} =
  let ws = connectWebSocket(url)
  doAssert ws.send("drop without explicit close")

proc main(url, mode, caFile: string) {.passive.} =
  var expected = Success
  if mode == "bad-upgrade": expected = ValueError
  elif mode == "handshake-timeout": expected = TimeoutError
  elif mode == "tls-reject": expected = PermissionDenied
  elif mode == "no-tls": expected = UnimplementedOperation
  var caught = Success
  try:
    if mode == "drop":
      dropConnection(url)
    else:
      var options = initWebSocketOptions()
      options.caFile = caFile
      if mode in ["handshake-timeout", "read-timeout", "write-timeout"]:
        options.timeoutMs = 150
      if mode == "too-large": options.maxMessage = 4
      if mode == "protocols":
        options.protocols = @["chat", "other"]
        options.origin = "https://example.com"
        options.headers = @[Header(name: "Authorization", value: "Bearer test")]
      let ws = connectWebSocket(url, options)
      defer: ws.abort()
      if mode == "echo":
        for n in [0, 5, 125, 126, 65536, 256000]:
          let data = repeat("x", n)
          doAssert ws.send(data)
          let text = ws.recv()
          doAssert text.kind == wmText and text.data == data
        doAssert ws.send("\0\xff\x80", binary = true)
        let binary = ws.recv()
        doAssert binary.kind == wmBinary and binary.data == "\0\xff\x80"
        for n in [0, 3, 8192, 65536, 256000]:
          var bytes = newSeq[byte](n)
          var expectedData = newString(n)
          for i in 0..<n:
            bytes[i] = byte(i and 255)
            expectedData[i] = char(bytes[i])
          doAssert ws.send(bytes)
          let reply = ws.recv()
          doAssert reply.kind == wmBinary and reply.data == expectedData
        doAssert ws.ping("probe")
        doAssert ws.send("after ping")
        doAssert ws.recv().data == "after ping"
        doAssert ws.close(1000, "done")
        doAssert ws.state == wsClosed
        doAssert ws.close()
      elif mode == "fragments":
        let m = ws.recv()
        doAssert m.kind == wmText and m.data == "\xc3\xa9!"
        let last = ws.recv()
        doAssert last.kind == wmClose and last.code == 1001 and last.data == "bye"
        doAssert last.closeSource == csPeer
        doAssert ws.state == wsClosed
        doAssert ws.recv().code == 1001
      elif mode == "empty-close":
        let m = ws.recv()
        doAssert m.kind == wmClose and m.code == 1005 and m.closeSource == csPeer
      elif mode == "eof":
        let m = ws.recv()
        doAssert m.kind == wmClose and m.code == 1006 and m.closeSource == csEof
      elif mode == "protocols":
        doAssert ws.protocol == "chat"
        doAssert ws.recv().data == "ready"
        let next = ws.recv()
        doAssert next.kind == wmBinary and next.data == "\0\xff"
        doAssert ws.close()
      elif mode == "write-timeout":
        doAssert not ws.send(repeat("x", 16 * 1024 * 1024))
        let m = ws.recv()
        doAssert m.kind == wmClose and m.code == 1006 and m.closeSource == csTransportError
        doAssert not ws.open
      elif mode == "read-timeout":
        let m = ws.recv()
        doAssert m.kind == wmClose and m.code == 1006 and m.closeSource == csTransportError
        doAssert not ws.open
      elif mode == "protocol-error":
        let m = ws.recv()
        doAssert m.kind == wmClose and m.code in [1002, 1007]
        doAssert m.closeSource == csProtocolError and not ws.open
      elif mode == "too-large":
        let m = ws.recv()
        doAssert m.kind == wmClose and m.code == 1009
        doAssert m.closeSource == csProtocolError and not ws.open
      elif mode == "close-without-reply":
        doAssert ws.close(1000, "done")
        doAssert not ws.open
        doAssert ws.close()
        doAssert not ws.send("closed")
        doAssert not ws.send(newSeq[byte](0))
        doAssert not ws.ping()
        ws.abort()
        let m = ws.recv()
        doAssert m.kind == wmClose and m.code == 1000 and m.data == "done"
        doAssert m.closeSource == csLocal
      else: discard ws.recv()
  except ErrorCode as e:
    caught = e
  if caught != expected:
    echo "expected ", expected, ", got ", caught, " (", mode, ")"
    atomicStore(failed, 1)
  atomicStore(done, 1)

initIoRing()
submit(delay main(paramStr(1), paramStr(2), (if paramCount() >= 3: paramStr(3) else: "")))
while atomicLoad(done) == 0:
  discard poolHelp()
  discard gReactor(10)
shutdown()
quit(atomicLoad(failed))
