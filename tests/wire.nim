## Test-only unmasked encoder and receive driver. Network fixtures use an
## independent Python codec.
import tsuru/internal/[frame, protocol]
import testkit

proc serverFrame*(op: Opcode; data: string; fin = true): string =
  result = ""
  result.add char(ord(op) or (if fin: 128 else: 0))
  let n = data.len
  if n < 126: result.add char(n)
  elif n <= 65535:
    result.add char(126)
    result.add char((n shr 8) and 255)
    result.add char(n and 255)
  else:
    result.add char(127)
    for shift in countdown(7, 0):
      result.add char((uint64(n) shr (shift * 8)) and 255'u64)
  result.add data

proc feedAll*(s: var MessageState; wire: string; maxMessage: int;
              steps: openArray[int]; direct = false): seq[Action] =
  ## Drive feed as the client does: deliver wire in reads of steps[i] bytes
  ## (cycled), and with direct, append payload remainders straight into the
  ## message when nothing is buffered. Collect outcomes up to a close, a
  ## failure or the end of wire.
  result = @[]
  var input = ""
  var sent = 0
  var k = 0
  while true:
    var used = 0
    let action = feed(s, input, maxMessage, used)
    doAssert used >= 0 and used <= input.len
    input = input.substr(used)
    case action.kind
    of akNone: doAssert used > 0 or payloadLeft(s) == 0
    of akIncomplete:
      if sent == wire.len: return
      let n = min(steps[k mod steps.len], wire.len - sent)
      inc k
      if direct and input.len == 0 and payloadLeft(s) > 0:
        let m = min(n, payloadLeft(s))
        s.payload.add wire.substr(sent, sent + m - 1)
        appended(s, m)
        sent += m
      else:
        input.add wire.substr(sent, sent + n - 1)
        sent += n
    of akClose, akError:
      result.add action
      return
    of akMessage, akPong:
      result.add action
