## OS cryptographic randomness for nonces and masks; no socket state.
from std/posix/posix import errno, EINTR

proc getRandom(buf: pointer; len: csize_t; flags: cuint): int
  {.importc: "getrandom", header: "<sys/random.h>".}

proc fillRandom*[T: char | byte](bytes: var openArray[T]) {.raises.} =
  ## Fill a byte buffer with OS cryptographic randomness.
  var off = 0
  while off < bytes.len:
    let got = getRandom(addr bytes[off], csize_t(bytes.len - off), 0)
    if got > 0:
      off += got
    elif got == 0 or errno() != EINTR:
      raise IOError

proc randomBytes*(n: Positive): string {.raises.} =
  ## Return n random bytes for an opening-handshake nonce.
  result = ""
  var bytes = toOpenArray(beginStore(result, n), 0, n - 1)
  defer: endStore(result)
  fillRandom(toOpenArray(bytes, 0, bytes.len - 1))
