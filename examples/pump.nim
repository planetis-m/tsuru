## One task owns the connection; other tasks queue messages for it.
##
## A WebSocket supports one operation at a time, so a task must not send while
## another is parked in recv (the send buffer is shared, and OpenSSL forbids
## concurrent reads and writes on one session). This pump is the supported
## pattern for request/response protocols such as WebDriver BiDi: it receives
## in short slices and, between slices, sends whatever other tasks queued.
##
## The trade-off is latency: a queued message waits up to PollMs while no
## traffic arrives, and an idle connection wakes the owner every PollMs.
## An expired recv keeps the connection and any partial frame, so slicing
## loses nothing. Run it against an echo server.
import std/[cmdline, syncio, threadpool, ioring, atomics, opt, channels]
import tsuru/websocket

const
  PollMs = 10
  Producers = 4
  PerProducer = 25

var done: int
var failed: int

proc producer(queue: Sender[string]; id: int) {.passive.} =
  ## Any task may queue a message; only the pump touches the connection.
  try:
    for i in 0..<PerProducer:
      if not queue.send("{\"id\":" & $(id * PerProducer + i) & "}"): return
  except ErrorCode: discard

proc pump(ws: WebSocket; pending: Receiver[string]; expected: int): bool {.passive.} =
  ## Send what is queued, then receive for at most PollMs. A real client would
  ## dispatch each reply to its waiting command by id; this one counts them.
  var replies = 0
  var text = ""
  try:
    while true:
      while pending.tryRecv(text):
        if not ws.send(text): return false
      case ws.recv(afterMs(PollMs))
      of Some(message):
        if message.kind == wmClose: return false
        inc replies
        if replies == expected: return ws.close().closeSource == csPeer
      of None: discard
  except ErrorCode:
    result = false # tryRecv raises only on a default-constructed Receiver,
                   # close only on invalid arguments

proc main(url: string) {.passive.} =
  try:
    let ws = connectWebSocket(url, afterMs(10_000))
    defer: ws.abort()
    let (pending, queue) = channel[string](64)
    for id in 0..<Producers:
      submit(delay producer(queue, id))
    if pump(ws, pending, Producers * PerProducer):
      echo "received ", Producers * PerProducer, " replies"
    else:
      echo "pump ended early"
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
