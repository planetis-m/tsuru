## Network test driver. The Python runner supplies independent wire fixtures.
import std/[cmdline, syncio, threadpool, ioring, atomics, strutils, parseutils, dirs, paths, opt]
import tsuru
import testkit

var done: int
var failed: int

proc receive(ws: WebSocket; dl = never): Message {.passive.} =
  case ws.recv(dl)
  of Some(message): result = message
  of None(): doAssert false, "expected a message, received deadline expiry"

proc dropConnection(url: string) {.passive, raises.} =
  let ws = connectWebSocket(url)
  doAssert ws.send("drop without explicit close")

proc fdCount(): int {.raises.} =
  result = 0
  for entry in walkDir(path("/proc/self/fd"), checkDir = true): inc result

proc resourceLoop(url: string) {.passive, raises.} =
  let warmup = connectWebSocket(url)
  warmup.abort()
  let baseline = fdCount()
  for cycle in 0..<2:
    for mode in ["peer", "bad-upgrade", "protocol", "reset", "close-timeout", "abort", "setup-timeout"]:
      var caught = Success
      try:
        let ws = connectWebSocket(url, dl = afterMs(if mode == "setup-timeout": 25 else: 2000))
        defer: ws.abort()
        if mode == "abort": ws.abort()
        elif mode == "close-timeout": doAssert ws.close(1000, "done").closeSource == csTimeout
        elif mode == "reset":
          doAssert ws.send("reset")
          doAssert ws.receive().closeSource == csTransportError
        elif mode == "protocol": doAssert ws.receive().closeSource == csProtocolError
        else: doAssert ws.receive().closeSource == csPeer
        doAssert ws.state == wsClosed
      except ErrorCode as e: caught = e
      doAssert caught == (if mode == "bad-upgrade": ValueError
                         elif mode == "setup-timeout": TimeoutError else: Success)
      doAssert fdCount() == baseline

proc main(url, mode, caFile: string) {.passive.} =
  var expected = Success
  if mode == "bad-upgrade": expected = ValueError
  elif mode == "handshake-timeout": expected = TimeoutError
  elif mode == "tls-reject": expected = PermissionDenied
  elif mode == "no-tls": expected = UnimplementedOperation
  var caught = Success
  try:
    if mode == "resources": resourceLoop(url)
    elif mode == "drop":
      dropConnection(url)
    else:
      var options = initWebSocketOptions()
      options.caFile = caFile
      if mode in ["handshake-timeout", "write-timeout"]:
        options.timeoutMs = 150
      if mode == "too-large": options.maxMessage = 4
      if mode == "large": options.maxMessage = 64 * 1024 * 1024
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
          let text = ws.receive()
          doAssert text.kind == wmText and text.data == data
        doAssert ws.send("\0\xff\x80", binary = true)
        let binary = ws.receive()
        doAssert binary.kind == wmBinary and binary.data == "\0\xff\x80"
        for n in [0, 3, 8192, 65536, 256000]:
          var bytes = newSeq[byte](n)
          var expectedData = newString(n)
          for i in 0..<n:
            bytes[i] = byte(i and 255)
            expectedData[i] = char(bytes[i])
          doAssert ws.send(bytes)
          let reply = ws.receive()
          doAssert reply.kind == wmBinary and reply.data == expectedData
        doAssert ws.ping("probe")
        doAssert ws.send("after ping")
        doAssert ws.receive().data == "after ping"
        doAssert ws.close(1000, "done").closeSource == csPeer
        doAssert ws.state == wsClosed
        doAssert ws.close().closeSource == csPeer
      elif mode == "fragments":
        let m = ws.receive()
        doAssert m.kind == wmText and m.data == "\xc3\xa9!"
        let last = ws.receive()
        doAssert last.kind == wmClose and last.code == 1001 and last.data == "bye"
        doAssert last.closeSource == csPeer
        doAssert ws.state == wsClosed
        doAssert ws.receive().code == 1001
      elif mode == "empty-close":
        let m = ws.receive()
        doAssert m.kind == wmClose and m.code == 1005 and m.closeSource == csPeer
      elif mode == "eof":
        let m = ws.receive()
        doAssert m.kind == wmClose and m.code == 1006 and m.closeSource == csEof
      elif mode == "protocols":
        doAssert ws.protocol == "chat"
        doAssert ws.receive().data == "ready"
        let next = ws.receive()
        doAssert next.kind == wmBinary and next.data == "\0\xff"
        doAssert ws.close().closeSource == csPeer
        doAssert ws.receive().closeSource == csPeer
      elif mode == "write-timeout":
        doAssert not ws.send(repeat("x", 16 * 1024 * 1024))
        let m = ws.receive()
        doAssert m.kind == wmClose and m.code == 1006 and m.closeSource == csTimeout
        doAssert not ws.open
      elif mode == "read-timeout":
        doAssert ws.recv(dl = afterMs(50)).isNone
        doAssert ws.open
        doAssert ws.send("after timeout")
        let m = ws.receive(dl = afterMs(2000))
        doAssert m.kind == wmText and m.data == "ready"
        doAssert ws.close().closeSource == csPeer
      elif mode == "buffered-timeout":
        doAssert ws.recv(dl = afterMs(-1)).isNone
        doAssert ws.open
        let m = ws.receive(dl = afterMs(2000))
        doAssert m.kind == wmText and m.data == "buffered"
        doAssert ws.close().closeSource == csPeer
      elif mode == "partial-timeout":
        doAssert ws.recv(dl = afterMs(50)).isNone
        doAssert ws.open
        doAssert ws.send("after timeout")
        let m = ws.receive(dl = afterMs(2000))
        doAssert m.kind == wmText and m.data == "\xc3\xa9!"
        let last = ws.receive()
        doAssert last.kind == wmClose and last.code == 1001 and last.data == "bye"
        doAssert last.closeSource == csPeer
      elif mode == "control-timeout":
        doAssert ws.recv(dl = afterMs(75)).isNone
        doAssert ws.open
        let m = ws.receive(dl = afterMs(2000))
        doAssert m.kind == wmText and m.data == "ready"
        doAssert ws.close().closeSource == csPeer
      elif mode == "control-backpressure":
        doAssert ws.recv(dl = afterMs(2500)).isNone, "pong pressure must expire normally"
        doAssert ws.open
        doAssert ws.send("after backpressure", dl = afterMs(10_000)), "pending pong must resume before send"
        let m = ws.receive(dl = afterMs(10_000))
        doAssert m.kind == wmText and m.data == "ready", "pong stream must drain without corruption"
        doAssert ws.close().closeSource == csPeer, "close after pong pressure must succeed"
      elif mode == "commands":
        var pending = default(array[100, bool])
        for id in 0..31:
          pending[id] = true
          doAssert ws.send("{\"id\":" & $id & "}")
        pending[99] = true
        doAssert ws.send("{\"id\":99}")
        let commandDeadline = afterMs(50)
        doAssert ws.recv(dl = commandDeadline).isNone
        pending[99] = false
        doAssert ws.open
        pending[32] = true
        doAssert ws.send("{\"id\":32}")
        var remaining = 33
        var late = 0
        var events = 0
        while remaining > 0:
          let m = ws.receive(dl = afterMs(2000))
          doAssert m.kind == wmText
          if m.data == "{\"event\":\"tick\"}": inc events
          else:
            var id = 0.BiggestInt
            doAssert parseBiggestInt(m.data.toOpenArray(6, m.data.high), id) > 0
            doAssert id in 0..99
            if not pending[int(id)]: inc late
            else:
              pending[int(id)] = false
              dec remaining
        doAssert late == 1 and events == 7
        let last = ws.receive()
        doAssert last.kind == wmClose and last.code == 1001 and last.data == "done"
        doAssert last.closeSource == csPeer
      elif mode == "large":
        let data = repeat("x", 20 * 1024 * 1024)
        doAssert ws.send(data, dl = afterMs(10_000))
        let m = ws.receive(dl = afterMs(10_000))
        doAssert m.kind == wmText and m.data == data
        doAssert ws.close().closeSource == csPeer
      elif mode == "reset":
        doAssert ws.send("reset")
        let m = ws.receive()
        doAssert m.kind == wmClose and m.code == 1006 and m.closeSource == csTransportError
        doAssert ws.state == wsClosed
      elif mode == "protocol-error":
        let m = ws.receive()
        doAssert m.kind == wmClose and m.code in [1002, 1007]
        doAssert m.closeSource == csProtocolError and not ws.open
      elif mode == "too-large":
        let m = ws.receive()
        doAssert m.kind == wmClose and m.code == 1009
        doAssert m.closeSource == csProtocolError and not ws.open
      elif mode == "close-handshake":
        let m = ws.close(1000, "done")
        doAssert m.closeSource == csPeer
        doAssert ws.state == wsClosed and not ws.open
        doAssert ws.close(1001, "again").closeSource == csPeer
        doAssert not ws.send("closed")
        doAssert not ws.send(newSeq[byte](0))
        doAssert not ws.ping()
        doAssert m.kind == wmClose and m.code == 1001 and m.data == "bye"
        doAssert m.closeSource == csPeer
        doAssert ws.state == wsClosed
        ws.abort()
        doAssert ws.receive().code == 1001
      elif mode == "close-abort":
        ws.abort()
        let m = ws.receive()
        doAssert m.kind == wmClose and m.code == 1006 and m.closeSource == csLocal
        doAssert ws.state == wsClosed
        doAssert ws.close().closeSource == csLocal
      elif mode in ["close-timeout", "close-eof", "close-protocol-error"]:
        let started = monoNow()
        let m = ws.close(1000, "done", dl = afterMs(100))
        doAssert int64(monoNow()) - int64(started) < 500_000_000
        doAssert ws.state == wsClosed
        doAssert m.kind == wmClose
        if mode == "close-protocol-error":
          doAssert m.code == 1002 and m.closeSource == csProtocolError
        else:
          doAssert m.code == 1006
          doAssert m.closeSource == (if mode == "close-eof": csEof else: csTimeout)
        doAssert ws.state == wsClosed
        ws.abort()
        doAssert ws.receive().closeSource == m.closeSource
      else: discard ws.receive()
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
