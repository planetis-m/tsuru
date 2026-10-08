## Test-only unmasked encoder. Network fixtures use an independent Python codec.
import tsuru/protocol

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
