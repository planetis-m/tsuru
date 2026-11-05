## Loopback throughput benchmark against bench/server.c. One connection, one
## task, sequential operations. Usage: bench <port> <mode> <iterations>
import std/[cmdline, syncio, threadpool, ioring, atomics, parseutils, opt]
import tsuru

var done: int
var failed: int

proc httpLoop(port, path: string; iterations: int; stream: bool): int {.passive, raises.} =
  result = 0
  let c = connectHttp("http://127.0.0.1:" & port & path, never)
  defer: c.close()
  var chunk = default(array[65536, char])
  for i in 0..<iterations:
    let response = c.request(never)
    if response.status != 200: raise ValueError
    if stream:
      while true:
        let n = c.readBody(chunk)
        if n == 0: break
        result += n
    else:
      result += c.readAll().len

proc wsLoop(port, path: string; size, iterations: int): int {.passive, raises.} =
  result = 0
  var options = initWebSocketOptions(maxMessage = 64 * 1024 * 1024)
  let ws = connectWebSocket("ws://127.0.0.1:" & port & path, never, options)
  defer: ws.abort()
  var payload = ""
  let p = beginStore(payload, size)
  for i in 0..<size: p[i] = 'x'
  endStore(payload)
  for i in 0..<iterations:
    if not ws.send(payload): raise IOError
    case ws.recv()
    of Some(message):
      if message.kind != wmText or message.data.len != size: raise ValueError
      result += message.data.len
    of None(): raise TimeoutError
  discard ws.close()

proc measure(port, mode: string; iterations: int): int {.passive, raises.} =
  case mode
  of "http-small": result = httpLoop(port, "/small", iterations, false)
  of "http-large": result = httpLoop(port, "/large", iterations, false)
  of "http-large-stream": result = httpLoop(port, "/large", iterations, true)
  of "http-chunked": result = httpLoop(port, "/chunked", iterations, false)
  of "ws-small": result = wsLoop(port, "/", 16, iterations)
  of "ws-large": result = wsLoop(port, "/", 1024 * 1024, iterations)
  of "ws-frag": result = wsLoop(port, "/frag", 64 * 1024, iterations)
  else: raise ValueError

proc run(port, mode: string; iterations: int) {.passive.} =
  try:
    let started = monoNow()
    let bytes = measure(port, mode, iterations)
    let ns = int64(monoNow()) - int64(started)
    echo mode, " iterations=", iterations, " bytes=", bytes,
      " ns/op=", ns div int64(iterations)
  except ErrorCode as e:
    echo "benchmark failed: ", e
    atomicStore(failed, 1)
  atomicStore(done, 1)

var count = 0.BiggestInt
if paramCount() != 3 or parseBiggestInt(paramStr(3).toOpenArray(0, paramStr(3).high), count) == 0:
  echo "Usage: bench <port> <mode> <iterations>"
  quit(1)
initIoRing()
submit(delay run(paramStr(1), paramStr(2), int(count)))
while atomicLoad(done) == 0:
  discard poolHelp()
  discard gReactor(10)
shutdown()
quit(atomicLoad(failed))
