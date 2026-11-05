## Read-ahead input shared by the HTTP and WebSocket clients: one owned string
## consumed through a cursor and compacted once per read.
import std/ioring
import ./[transport, buffer]

const
  MinRead* = 1024
  MaxRead* = 16 * 1024
    ## Buffered reads start small and double while the peer fills them, as in
    ## std/streamio, so an idle connection keeps a small input buffer.
  DirectRead* = 16 * 1024
    ## With nothing buffered, a read at least this large skips the input and
    ## goes from the socket straight into the caller's storage.

type Input* = object
  data*: string
  pos*: int ## Unread input starts here; consumed bytes are dropped before reads.
  step: int

proc initInput*(): Input = Input(step: MinRead)

proc buffered*(i: Input): int {.inline.} = i.data.len - i.pos

template unread*(i: Input): untyped =
  ## A view of the unread bytes.
  toOpenArray(i.data, i.pos, i.data.len - 1)

proc clear*(i: var Input) =
  ## Drop all input and its storage.
  i.data = ""
  i.pos = 0

proc fill*(i: var Input; t: var Transport; dl: Deadline): int {.passive, raises.} =
  ## Append one read to the unread input, compacting consumed bytes first.
  ## Zero means end of stream.
  if i.pos > 0:
    dropPrefix(i.data, i.pos)
    i.pos = 0
  result = readInto(t, i.data, i.step, dl)
  if result >= i.step: i.step = min(i.step * 2, MaxRead)
  elif result > 0: i.step = MinRead
