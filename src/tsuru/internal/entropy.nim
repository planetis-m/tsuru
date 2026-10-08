## OS cryptographic randomness for nonces and masks; no socket state.
from std/posix/posix import errno, EINTR

proc getRandom(buf: pointer; len: csize_t; flags: cuint): int
  {.importc: "getrandom", header: "<sys/random.h>".}

proc randomBytes*(n: Positive): string {.raises.} =
  result = ""
  let bytes = beginStore(result, n)
  defer: endStore(result)
  var off = 0
  while off < n:
    let got = getRandom(addr bytes[off], csize_t(n - off), 0)
    if got > 0: off += got
    elif got == 0 or errno() != EINTR: raise IOError
