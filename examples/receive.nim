## Receive messages until the peer closes. Configure optional authentication,
## subprotocol and CA trust with TSURU_TOKEN, TSURU_PROTOCOL and TSURU_CA_FILE.
import std/[cmdline, envvars, syncio, threadpool, ioring, atomics]
import tsuru

var done: int
var failed: int

proc main(url, token, subprotocol, caFile: string) {.passive.} =
  try:
    var options = initWebSocketOptions(timeoutMs = 300_000)
    if token.len > 0:
      options.headers = @[Header(name: "Authorization", value: "Bearer " & token)]
    if subprotocol.len > 0: options.protocols = @[subprotocol]
    options.caFile = caFile
    let ws = connectWebSocket(url, options, dl = afterMs(10_000))
    defer: ws.abort()
    echo "Connected; selected protocol: ", ws.protocol
    while ws.open:
      let message = ws.recv()
      case message.kind
      of wmText: echo message.data
      of wmBinary: echo "Binary message: ", message.data.len, " bytes"
      of wmTimeout: discard
      of wmClose:
        echo "Closed: ", message.closeSource, " ", message.code, " ", message.data
  except ErrorCode as e:
    echo "Connection failed: ", e
    atomicStore(failed, 1)
  atomicStore(done, 1)

if paramCount() == 0:
  echo "Usage: receive ws://host/path or wss://host/path"
  quit(1)

let url = paramStr(1)
let token = getEnv("TSURU_TOKEN")
let subprotocol = getEnv("TSURU_PROTOCOL")
let caFile = getEnv("TSURU_CA_FILE")
initIoRing()
submit(delay main(url, token, subprotocol, caFile))
while atomicLoad(done) == 0:
  discard poolHelp()
  discard gReactor(10)
shutdown()
quit(atomicLoad(failed))
