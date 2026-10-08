import testkit
import std/strutils
import tsuru/http

proc parse(fields: string; status = "200 OK"; meth = "GET"): ResponseHead {.raises.} =
  parseResponseHead("HTTP/1.1 " & status & "\r\n" & fields & "\r\n", meth)

proc main() {.raises.} =
  let fixed = parse("Content-Length: 5\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n")
  doAssert fixed.framing == bodyLength and fixed.length == 5 and fixed.keepAlive
  doAssert fixed.response.header("CONTENT-LENGTH") == "5"
  doAssert fixed.response.headers.len == 3
  doAssert parse("Transfer-Encoding: Chunked\r\n").framing == bodyChunked
  doAssert parse("Connection: keep-alive, close\r\n").framing == bodyEof
  doAssert not parse("Connection: keep-alive, close\r\n").keepAlive
  doAssert parse("Content-Length: 999999999\r\n", meth = "HEAD").framing == bodyNone
  doAssert parse("", status = "204 No Content").framing == bodyNone
  doAssert parse("Content-Length: 99\r\n", status = "304 Not Modified").framing == bodyNone
  for fields in ["Content-Length: 1\r\nContent-Length: 1\r\n",
      "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
      "Content-Length: -1\r\n", "Content-Length: 9999999999999999999999\r\n",
      "Content-Length : 1\r\n", " folded: x\r\n", "X: x\0y\r\n"]:
    var caught = Success
    try: discard parse(fields)
    except ErrorCode as e: caught = e
    doAssert caught == SyntaxError
  doAssert requestHead("example.com", "POST", "/x?q=%20", 3,
    @[Header(name: "X-Trace", value: "id")]).contains("Content-Length: 3\r\n")
  for h in [Header(name: "Host", value: "other"), Header(name: "X", value: "x\r\ny")]:
    var caught = Success
    try: discard requestHead("example.com", "GET", "/", 0, @[h])
    except ErrorCode as e: caught = e
    doAssert caught == ValueError
  echo "HTTP head tests passed"

try: main()
except ErrorCode:
  doAssert false, "unexpected HTTP head test error"
