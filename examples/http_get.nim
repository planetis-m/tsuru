## Fetch an HTTP or HTTPS resource within one absolute request deadline.
import std/[cmdline, syncio, threadpool, ioring, atomics]
import tsuru/httpclient

var done: int
var failed: int

proc fetch(url: string) {.passive.} =
  try:
    let deadline = afterMs(10_000)
    let client = connectHttp(url, deadline)
    defer: client.close()
    let response = client.request(deadline)
    echo "HTTP status: ", response.status
    echo client.readAll()
  except ErrorCode as e:
    echo "HTTP request failed: ", e
    atomicStore(failed, 1)
  atomicStore(done, 1)

if paramCount() != 1:
  echo "Usage: http_get http://host/path or https://host/path"
  quit(1)
initIoRing()
submit(delay fetch(paramStr(1)))
while atomicLoad(done) == 0:
  discard poolHelp()
  discard gReactor(10)
shutdown()
quit(atomicLoad(failed))
