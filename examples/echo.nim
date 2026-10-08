## Round trip a message against a WebSocket echo server.
import std/[cmdline, syncio, threadpool, ioring, atomics, opt]
import tsuru

var done: int
var failed: int

proc main(url: string) {.passive.} =
  try:
    let ws = connectWebSocket(url)
    defer: ws.abort()
    if not ws.send("Hello from Nimony"):
      echo "send failed"
      atomicStore(failed, 1)
    else:
      case ws.recv()
      of Some(message):
        if message.kind != wmText or message.data != "Hello from Nimony":
          echo "unexpected echo"
          atomicStore(failed, 1)
        else: echo message.data
      of None():
        echo "echo deadline expired"
        atomicStore(failed, 1)
      if ws.close().closeSource != csPeer:
        echo "close failed"
        atomicStore(failed, 1)
  except ErrorCode as e:
    echo "Connection failed: ", e
    atomicStore(failed, 1)
  atomicStore(done, 1)

initIoRing()
let url = if paramCount() > 0: paramStr(1) else: "ws://127.0.0.1:8080/"
submit(delay main(url))
while atomicLoad(done) == 0:
  discard poolHelp()
  discard gReactor(10)
shutdown()
quit(atomicLoad(failed))
