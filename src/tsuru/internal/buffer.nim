## Bulk operations on owned strings and borrowed byte buffers.

proc appendBytes*[T: char | byte](s: var string; data: openArray[T]) =
  ## Append data without changing its owner. Empty input leaves s untouched.
  if data.len == 0:
    return
  let oldLen = s.len
  copyMem(beginStore(s, oldLen + data.len, oldLen), addr data[0], data.len)
  endStore(s)

proc copyOut*[T: char | byte](dest: var openArray[T]; s: string; start = 0) =
  ## Fill dest from s[start..]. The source must contain dest.len bytes.
  if dest.len > 0:
    copyMem(addr dest[0], readRawData(s, start), dest.len)

proc dropPrefix*(s: var string; n: int) =
  ## Discard n consumed bytes in place, where 0 <= n <= s.len. Retain capacity.
  if n == 0:
    return
  if n == s.len:
    s.setLen(0)
  else:
    let keep = s.len - n
    let dest = beginStore(s, s.len)
    moveMem(dest, readRawData(s, n), keep)
    s.setLen(keep)
    endStore(s)
