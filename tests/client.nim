## Network test driver. The Python runner supplies independent wire fixtures.
import std/[cmdline, syncio, threadpool, ioring, atomics, strutils]
import tsuru
import testkit

var done: int
var failed: int

proc dropConnection(url: string) {.passive, raises.} =
  let ws = connectWebSocket(url)
  ws.send("drop without explicit close")

proc main(url, mode, caFile: string) {.passive.} =
  var expected = Success
  if mode in ["bad-upgrade", "protocol-error"]: expected = ValueError
  elif mode in ["handshake-timeout", "read-timeout", "write-timeout", "close-timeout"]:
    expected = TimeoutError
  elif mode == "too-large": expected = ContentTooLong
  elif mode == "tls-reject": expected = PermissionDenied
  elif mode == "no-tls": expected = UnimplementedOperation
  var caught = Success
  try:
    if mode == "drop":
      dropConnection(url)
    else:
      var options = initWebSocketOptions()
      options.caFile = caFile
      if mode in ["handshake-timeout", "read-timeout", "write-timeout", "close-timeout"]:
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
          ws.send(data)
          let text = ws.recv()
          doAssert text.kind == wmText and text.data == data
        ws.send("\0\xff\x80", binary = true)
        let binary = ws.recv()
        doAssert binary.kind == wmBinary and binary.data == "\0\xff\x80"
        for n in [0, 3, 8192, 65536, 256000]:
          var bytes = newSeq[byte](n)
          var expectedData = newString(n)
          for i in 0..<n:
            bytes[i] = byte(i and 255)
            expectedData[i] = char(bytes[i])
          ws.send(bytes)
          let reply = ws.recv()
          doAssert reply.kind == wmBinary and reply.data == expectedData
        ws.ping("probe")
        ws.send("after ping")
        doAssert ws.recv().data == "after ping"
        ws.close(1000, "done")
        doAssert ws.state == wsClosed
        ws.close()
      elif mode == "fragments":
        let m = ws.recv()
        doAssert m.kind == wmText and m.data == "\xc3\xa9!"
        let last = ws.recv()
        doAssert last.kind == wmClose and last.code == 1001 and last.data == "bye"
        doAssert ws.state == wsClosed
        doAssert ws.recv().code == 1001
      elif mode == "empty-close":
        let m = ws.recv()
        doAssert m.kind == wmClose and m.code == 1005
      elif mode == "eof":
        let m = ws.recv()
        doAssert m.kind == wmClose and m.code == 1006
      elif mode == "protocols":
        doAssert ws.protocol == "chat"
        doAssert ws.recv().data == "ready"
        let next = ws.recv()
        doAssert next.kind == wmBinary and next.data == "\0\xff"
        ws.close()
      elif mode == "write-timeout":
        ws.send(repeat("x", 16 * 1024 * 1024))
      elif mode == "close-timeout": ws.close()
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
