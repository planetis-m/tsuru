## Client side of independent HTTP/TLS wire fixtures.
import std/[cmdline, syncio, threadpool, ioring, atomics, strutils]
import tsuru/httpclient
import testkit
import fdcount

var done: int
var failed: int

proc exercise(url, mode, caFile: string) {.passive, raises.} =
  var options = initHttpOptions()
  options.caFile = caFile
  if mode in ["too-large", "chunk-limit", "eof-limit"]: options.maxBody = 4
  let c = connectHttp(url, afterMs(2000), options)
  defer: c.close()
  var expected = Success
  if mode in ["slow-head", "slow-body", "expired-request"]: expected = TimeoutError
  elif mode in ["malformed", "bad-chunk", "bad-trailer"]: expected = SyntaxError
  elif mode == "truncated":
    expected = if url.startsWith("https://"): IOError else: EndOfStreamError
  elif mode in ["too-large", "chunk-limit", "eof-limit", "huge-head"]: expected = ContentTooLong
  elif mode == "upgrade": expected = UnimplementedOperation
  var caught = Success
  try:
    if mode == "abort":
      c.close()
    elif mode == "expired-request":
      discard c.request(afterMs(-1))
    elif mode == "large":
      let data = repeat("x\0\xff", 7 * 1024 * 1024)
      let deadline = afterMs(10_000)
      let response = c.request(deadline, meth = "POST", body = data)
      doAssert response.status == 200
      doAssert c.readAll() == data
    elif mode == "no-body":
      for meth in ["HEAD", "GET", "GET"]:
        let response = c.request(afterMs(2000), meth = meth)
        doAssert response.status in [200, 204, 304]
        doAssert c.readAll() == "" and c.open
      let response = c.request(afterMs(2000))
      doAssert response.status == 404 and c.readAll() == "missing"
      doAssert not c.open
    elif mode in ["keepalive", "chunked", "http10", "unread-body"]:
      let response = c.request(afterMs(2000), headers = @[Header(name: "X-Trace", value: "id")])
      doAssert response.status == 200
      if mode == "unread-body":
        var rejected = Success
        try: discard c.request(afterMs(2000))
        except ErrorCode as e: rejected = e
        doAssert rejected == ValueError and c.open
      var body = ""
      var bytes = default(array[3, char])
      while true:
        let n = c.readBody(bytes)
        if n == 0: break
        for i in 0..<n: body.add bytes[i]
      doAssert body == (if mode == "chunked": "hello\0\xff" else: "hello")
      doAssert c.open
      if mode == "keepalive":
        doAssert response.headers.len == 3
        doAssert response.header("set-cookie") == "a=1"
      let second = c.request(afterMs(2000), meth = "POST", target = "/second", body = "payload")
      doAssert second.status == 201 and c.readAll() == "second"
      doAssert not c.open
    elif mode == "slow-body":
      let deadline = afterMs(100)
      discard c.request(deadline)
      var bytes = default(array[1, char])
      doAssert c.readBody(bytes) == 1 and bytes[0] == 'a'
      discard c.readBody(bytes, dl = afterMs(10_000))
    else:
      let response = c.request(afterMs(if mode == "slow-head": 100 else: 2000))
      doAssert response.status == 200
      let body = c.readAll()
      if mode == "eof": doAssert body == "bye" and not c.open
  except ErrorCode as e:
    caught = e
    doAssert not c.open, "failed HTTP operation must release its transport"
  doAssert caught == expected, "HTTP fixture " & mode & " returned " & $caught
  c.close()
  doAssert not c.open

proc main(url, mode, caFile: string) {.passive.} =
  var expected = Success
  if mode == "tls-reject": expected = PermissionDenied
  elif mode == "no-tls": expected = UnimplementedOperation
  elif mode == "expired-connect": expected = TimeoutError
  var caught = Success
  try:
    if mode in ["tls-reject", "no-tls", "expired-connect"]:
      var options = initHttpOptions()
      options.caFile = caFile
      let c = connectHttp(url, afterMs(if mode == "expired-connect": -1 else: 2000), options)
      c.close()
    elif mode == "resources":
      let warmup = connectHttp(url, afterMs(2000))
      warmup.close()
      let baseline = fdCount()
      for cycle in 0..<2:
        for path in ["keepalive", "chunked", "malformed", "truncated", "slow-body", "abort", "expired-request", "too-large"]:
          exercise(url, path, caFile)
          doAssert fdCount() == baseline
    else:
      let baseline = fdCount()
      exercise(url, mode, caFile)
      doAssert fdCount() == baseline
  except ErrorCode as e: caught = e
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
