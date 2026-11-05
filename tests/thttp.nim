import testkit
import std/strutils
import tsuru/internal/[http, head]

proc parse(fields: string; status = "200 OK"; meth = "GET"): ResponseHead {.raises.} =
  parseResponseHead("HTTP/1.1 " & status & "\r\n" & fields & "\r\n", meth)

proc failure(head: string; meth = "GET"): ErrorCode =
  result = Success
  try: discard parseResponseHead(head, meth)
  except ErrorCode as e: result = e

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
      "Content-Length : 1\r\n", " folded: x\r\n", "X: x\0y\r\n", "X: a\rb\r\n",
      "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n", "NoColon\r\n"]:
    doAssert failure("HTTP/1.1 200 OK\r\n" & fields & "\r\n") == SyntaxError

  block statusLines:
    # The reason phrase is optional and discarded; bare LF ends lines (RFC 9112 §2.2).
    doAssert parseResponseHead("HTTP/1.1 204\r\n\r\n", "GET").response.status == 204
    doAssert parseResponseHead("HTTP/1.1 200 \tOK\nContent-Length: 2\n\n", "GET").length == 2
    for head in ["HTTP/1.1 200 O\x01K\r\n\r\n", "HTTP/2 200 OK\r\n\r\n", "HTTP/1.1 99 X\r\n\r\n",
        "HTTP/1.1 600 X\r\n\r\n", "HTTP/1.1 20X\r\n\r\n", "HTTP/1.1 200 OK\r\n",
        "HTTP/1.1 200 OK\r\n\r\nextra", "HTTP/1.1 200 OK\r\r\n\r\n"]:
      doAssert failure(head) == SyntaxError

  block fieldValues:
    let r = parse("X-Long: " & repeat("v", 12000) & "\r\nX-Tab: a\tb \t\r\nX-Empty:\r\n").response
    doAssert r.header("x-long").len == 12000
    doAssert r.header("X-TAB") == "a\tb" and r.header("x-empty") == "" and r.headers[2].name == "x-empty"
    var many = ""
    for i in 0..<100: many.add "X: 1\r\n"
    doAssert parse(many).response.headers.len == 100
    doAssert failure("HTTP/1.1 200 OK\r\n" & many & "X: 1\r\n\r\n") == ContentTooLong
    doAssert failure("HTTP/1.1 200 OK\r\nX: " & repeat("v", 17000) & "\r\n\r\n") == ContentTooLong

  block persistence:
    doAssert parseResponseHead("HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\n" &
      "Content-Length: 0\r\n\r\n", "GET").keepAlive
    doAssert not parseResponseHead("HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n", "GET").keepAlive
    doAssert not parse("Connection: Upgrade,\t CLOSE \r\nContent-Length: 0\r\n").keepAlive
    doAssert hasToken("a, Keep-Alive ,b", "keep-alive") and not hasToken("keep-alive-x", "keep-alive")
    doAssert not hasToken("", "close") and hasToken(",,close", "CLOSE")

  block unsupported:
    doAssert failure("HTTP/1.1 101 Switching Protocols\r\n\r\n") == UnimplementedOperation
    doAssert failure("HTTP/1.1 200 OK\r\n\r\n", "CONNECT") == UnimplementedOperation
    doAssert failure("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n") ==
      UnimplementedOperation
    doAssert failure("HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n") ==
      UnimplementedOperation

  block requests:
    let head = requestHead("example.com", "POST", "/x?q=%20", 3,
      @[Header(name: "X-Trace", value: "id"), Header(name: "ACCEPT-ENCODING", value: "gzip")])
    doAssert head == "POST /x?q=%20 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n" &
      "X-Trace: id\r\nACCEPT-ENCODING: gzip\r\n\r\n"
    doAssert requestHead("a", "GET", "/", 0, @[]).endsWith("Accept-Encoding: identity\r\n\r\n")
    # Our own head is not limited to the receive-side 16 KiB.
    let big = requestHead("a", "GET", "/", 0, @[Header(name: "Cookie", value: repeat("c", 20000))])
    doAssert big.len > 20000
    for h in [Header(name: "Host", value: "other"), Header(name: "X", value: "x\r\ny"),
              Header(name: "CoNtEnT-LeNgTh", value: "1"), Header(name: "Bad Name", value: "x"),
              Header(name: "", value: "x")]:
      var caught = Success
      try: discard requestHead("example.com", "GET", "/", 0, @[h])
      except ErrorCode as e: caught = e
      doAssert caught == ValueError
    for target in ["", "x", "/a b", "/a#f", "/\r\n"]:
      var caught = Success
      try: discard requestHead("example.com", "GET", target, 0, @[])
      except ErrorCode as e: caught = e
      doAssert caught == ValueError
  echo "HTTP head tests passed"

try: main()
except ErrorCode:
  doAssert false, "unexpected HTTP head test error"
