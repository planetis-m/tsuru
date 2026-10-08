## Bulk operations on owned strings and borrowed byte buffers.

proc appendBytes*(s: var string; data: openArray[char]) =
  ## Append data without changing its owner. Empty input leaves s untouched.
  if data.len == 0:
    return
  let oldLen = s.len
  copyMem(beginStore(s, oldLen + data.len, oldLen), addr data[0], data.len)
  endStore(s)

proc copyOut*(dest: var openArray[char]; s: string; start = 0) =
  ## Fill dest from s[start..]. The source must contain dest.len bytes.
  if dest.len > 0:
    copyMem(addr dest[0], readRawData(s, start), dest.len)

proc dropPrefix*(s: var string; n: int) =
  ## Discard n consumed bytes, where 0 <= n <= s.len. Release their storage.
  if n == 0:
    return
  if n == s.len:
    s = ""
  else:
    s = s[n..^1]
