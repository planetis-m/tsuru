## Facade and explicit imports share one Header, Deadline and operation set.
import testkit
import std/ioring
import tsuru
import tsuru/websocket
import tsuru/httpclient

proc relayHeader(h: Header): Header = h
proc relayDeadline(dl: Deadline): Deadline = dl
proc relayMessage(m: Message): Message = m

proc operation(ws: WebSocket): string =
  if ws.open: result = "open"
  else: result = "closed"

proc operation(c: HttpClient): string =
  if c.open: result = "open"
  else: result = "closed"

block sharedHeader:
  let header = relayHeader(Header(name: "X-Test", value: "id"))
  doAssert header.name == "X-Test" and header.value == "id"

block sharedDeadline:
  let dl = afterMs(250)
  let relayed = relayDeadline(dl)
  doAssert relayed == dl and never == never

block overloads:
  let ws = WebSocket()
  let client = HttpClient()
  doAssert operation(ws) == "closed" and operation(client) == "closed"
  doAssert ws.state == wsClosed and not client.open
  client.close()
  ws.abort()

block sharedRecords:
  let message = relayMessage(Message(kind: wmClose, data: "done", code: 1006))
  let response = HttpResponse(status: 204)
  doAssert message.kind == wmClose and message.code == 1006
  doAssert response.status == 204 and response.header("x") == ""

echo "facade and explicit import tests passed"
