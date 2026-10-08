import testkit
import tsuru/handshake

template rejects(body: untyped) {.untyped.} =
  block:
    var caught = false
    try:
      body
    except ErrorCode:
      caught = true
    doAssert caught

proc main() {.raises.} =
  doAssert acceptKey("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
  block urls:
    let e = parseEndpoint("ws://localhost:8080/chat?token=x")
    doAssert e.host == "localhost" and e.port == 8080 and e.target == "/chat?token=x"
    doAssert parseEndpoint("wss://example.com?q=x").target == "/?q=x"
    doAssert parseEndpoint("wss://example.com").port == 443
    doAssert parseEndpoint("wss://example.com").secure
    doAssert parseEndpoint("ws://[::1]:8080/").host == "::1"
    for url in ["http://a", "ws://", "ws://a:0", "ws://a:9999999999999999999",
        "ws://u@a", "ws://a/#frag", "ws://a/\r\nX: x", "ws://a:", "ws://::1"]:
      rejects: discard parseEndpoint(url)

  block response:
    let key = "dGhlIHNhbXBsZSBub25jZQ=="
    let head = "HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\n" &
      "Connection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: " & acceptKey(key) & "\r\n"
    doAssert validateResponse(head & "\r\n", key, @[]) == ""
    doAssert validateResponse(head & "Sec-WebSocket-Protocol: chat\r\n\r\n", key,
      @["chat"]) == "chat"
    rejects: discard validateResponse(head & "\r\n", "wrong", @[])
    rejects: discard validateResponse(head & "Sec-WebSocket-Accept: x\r\n\r\n", key, @[])
    rejects: discard validateResponse(head & "Sec-WebSocket-Protocol: chat\r\n\r\n", key, @[])
    rejects: discard validateResponse(head & "Sec-WebSocket-Extensions: x\r\n\r\n", key, @[])
    rejects: discard validateResponse("HTTP/1.1 200 OK\r\n\r\n", key, @[])

  block request:
    var options = initWebSocketOptions()
    options.protocols = @["chat"]
    options.headers = @[Header(name: "Authorization", value: "Bearer example")]
    let req = buildRequest(parseEndpoint("ws://localhost"), "nonce", options)
    doAssert req.len > 0
    options.headers = @[Header(name: "Host", value: "other")]
    rejects: discard buildRequest(parseEndpoint("ws://localhost"), "nonce", options)
    options.headers = @[Header(name: "X-Test", value: "x\r\nBad: injected")]
    rejects: discard buildRequest(parseEndpoint("ws://localhost"), "nonce", options)
    options.headers = @[]
    options.caFile = "ca\0.pem"
    rejects: validateOptions(options)

  echo "handshake tests passed"

try:
  main()
except ErrorCode:
  echo "unexpected handshake test error"
  quit(1)
