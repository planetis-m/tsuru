## Round trip a message against a WebSocket echo server.
import std/[cmdline, syncio, threadpool, ioring, atomics]
import tsuru

var done: int
var failed: int

proc main(url: string) {.passive.} =
  try:
    let ws = connectWebSocket(url)
    defer: ws.abort()
    ws.send("Hello from Nimony")
    let message = ws.recv()
    if message.kind != wmText or message.data != "Hello from Nimony":
      echo "unexpected echo"
      atomicStore(failed, 1)
    else: echo message.data
    ws.close()
  except ErrorCode as e:
    echo "WebSocket error: ", e
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
