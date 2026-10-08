## Nonblocking TCP and optional verified TLS. Only readiness waits park on the ring.
## Deadlines never leave a kernel read holding a pointer into an expired task.
import std/[ioring, socket, dns]
from std/posix/posix import errno, EAGAIN, EINTR

when not defined(linux):
  {.error: "Tsuru currently supports Linux.".}

proc cRecv(fd: cint; buf: pointer; len: csize_t; flags: cint): int
  {.importc: "recv", header: "<sys/socket.h>".}
proc cSend(fd: cint; buf: pointer; len: csize_t; flags: cint): int
  {.importc: "send", header: "<sys/socket.h>".}
proc cSocket(domain, kind, protocol: cint): cint
  {.importc: "socket", header: "<sys/socket.h>".}
proc inetPton(family: cint; src: cstring; dest: pointer): cint
  {.importc: "inet_pton", header: "<arpa/inet.h>".}
proc getRandom(buf: pointer; len: csize_t; flags: cuint): int
  {.importc: "getrandom", header: "<sys/random.h>".}

when defined(tsuruTls):
  {.passL: "-lssl -lcrypto".}
  {.compile: "tls_bio.c".}
  type
    SslCtx {.importc: "SSL_CTX", header: "<openssl/ssl.h>", incompleteStruct.} = object
    Ssl {.importc: "SSL", header: "<openssl/ssl.h>", incompleteStruct.} = object
    SslMethod {.importc: "SSL_METHOD", header: "<openssl/ssl.h>", incompleteStruct.} = object
  proc tlsMethod(): nil ptr SslMethod {.importc: "TLS_client_method", header: "<openssl/ssl.h>".}
  proc ctxNew(m: ptr SslMethod): nil ptr SslCtx
    {.importc: "SSL_CTX_new", header: "<openssl/ssl.h>".}
  proc ctxFree(c: ptr SslCtx) {.importc: "SSL_CTX_free", header: "<openssl/ssl.h>".}
  proc sslNew(c: ptr SslCtx): nil ptr Ssl {.importc: "SSL_new", header: "<openssl/ssl.h>".}
  proc sslFree(s: ptr Ssl) {.importc: "SSL_free", header: "<openssl/ssl.h>".}
  proc defaultTrust(c: ptr SslCtx): cint
    {.importc: "SSL_CTX_set_default_verify_paths", header: "<openssl/ssl.h>".}
  proc loadTrust(c: ptr SslCtx; file: cstring; dir: nil cstring): cint
    {.importc: "SSL_CTX_load_verify_locations", header: "<openssl/ssl.h>".}
  proc setVerify(c: ptr SslCtx; mode: cint; cb: nil pointer)
    {.importc: "SSL_CTX_set_verify", header: "<openssl/ssl.h>".}
  proc tlsConfigure(s: ptr Ssl; fd: cint; host: cstring): cint
    {.importc: "tsuru_tls_configure".}
  proc tlsConnect(s: ptr Ssl): cint {.importc: "SSL_connect", header: "<openssl/ssl.h>".}
  proc tlsRead(s: ptr Ssl; buf: pointer; len: cint): cint
    {.importc: "SSL_read", header: "<openssl/ssl.h>".}
  proc tlsWrite(s: ptr Ssl; buf: pointer; len: cint): cint
    {.importc: "SSL_write", header: "<openssl/ssl.h>".}
  proc tlsError(s: ptr Ssl; ret: cint): cint
    {.importc: "SSL_get_error", header: "<openssl/ssl.h>".}
  proc clearErrors() {.importc: "ERR_clear_error", header: "<openssl/err.h>".}

type Transport* = object
  sock: Socket
  when defined(tsuruTls):
    ctx: nil ptr SslCtx
    ssl: nil ptr Ssl

proc `=destroy`*(t: Transport) =
  when defined(tsuruTls):
    let ssl = t.ssl
    let ctx = t.ctx
    if ssl != nil: sslFree(ssl)
    if ctx != nil: ctxFree(ctx)
  `=destroy`(t.sock)

proc `=wasMoved`*(t: var Transport) {.nodestroy.} =
  `=wasMoved`(t.sock)
  when defined(tsuruTls):
    t.ssl = nil
    t.ctx = nil

proc `=copy`*(dest: var Transport; src: Transport) {.error.}
proc `=dup`*(src: Transport): Transport {.error.}

proc initTransport*(): Transport =
  Transport(sock: initSocket(-1, never))

proc close*(t: var Transport) =
  ## Idempotent release of TLS handles and socket, including on handshake failure.
  when defined(tsuruTls):
    let ssl = t.ssl
    let ctx = t.ctx
    if ssl != nil: sslFree(ssl)
    if ctx != nil: ctxFree(ctx)
    t.ssl = nil
    t.ctx = nil
  close(t.sock)

proc waitReady(fd: cint; events: IoEvents; dl: Deadline) {.passive, raises.} =
  if dl <= monoNow(): raise TimeoutError
  var n = -1
  let c = delay()
  discard submitPollAdd(fd, dl, events, c, addr n)
  suspend()
  if n < 0: raise toErr(n)

proc randomBytes*(n: Positive): string {.raises.} =
  ## OS cryptographic randomness; no predictable PRNG or fallback on failure.
  var bytes = newSeq[char](n)
  var off = 0
  while off < n:
    let got = getRandom(addr bytes[off], csize_t(n - off), 0)
    if got > 0: off += got
    elif got == 0 or errno() != EINTR: raise IOError
  result = ""
  for b in bytes: result.add b

proc requireTls(secure: bool) {.raises.} =
  when not defined(tsuruTls):
    if secure: raise UnimplementedOperation

proc open*(t: var Transport; host: string; port: uint16; secure: bool;
           caFile: string; dl: Deadline) {.passive, raises.} =
  ## Connect IPv4/DNS or an IPv6 literal; bound the TCP and TLS handshakes by dl.
  requireTls(secure)
  var hostBuf = host
  if ':' in host:
    var sa = Sockaddr_storage()
    let raw = cast[ptr UncheckedArray[uint8]](addr sa)
    raw[0] = 10'u8
    raw[2] = uint8(port shr 8)
    raw[3] = uint8(port and 255)
    if inetPton(10, toCString(hostBuf), addr raw[8]) != 1: raise ValueError
    let fd = cSocket(10, 1, 6)
    if fd < 0: raise IOError
    t.sock = initSocket(fd, never)
    setNonBlocking(fd)
    var n = -1
    let c = delay()
    discard submitConnect(fd, sa, SockLen(28), dl, c, addr n)
    suspend()
    if n != 0: raise toErr(n)
  else:
    var ip = host
    var literal = true
    for c in host:
      if c notin {'0'..'9', '.'}: literal = false
    if not literal: ip = resolve(host, dl)
    t.sock = connect(ip, port, dl)
  when defined(tsuruTls):
    if secure:
      let tlsMode = tlsMethod()
      if tlsMode == nil: raise IOError
      let ctx = ctxNew(tlsMode)
      if ctx == nil: raise IOError
      t.ctx = ctx
      setVerify(ctx, 1, nil)
      if caFile.len == 0:
        if defaultTrust(ctx) != 1: raise IOError
      else:
        var caBuf = caFile
        if loadTrust(ctx, toCString(caBuf), nil) != 1: raise IOError
      let ssl = sslNew(ctx)
      if ssl == nil: raise IOError
      t.ssl = ssl
      if tlsConfigure(ssl, t.sock.fd, toCString(hostBuf)) != 1: raise IOError
      var done = false
      while not done:
        if dl <= monoNow(): raise TimeoutError
        clearErrors()
        let n = tlsConnect(ssl)
        if n == 1: done = true
        else:
          let err = tlsError(ssl, n)
          if err == 2: waitReady(t.sock.fd, {evRead}, dl)
          elif err == 3: waitReady(t.sock.fd, {evWrite}, dl)
          else: raise PermissionDenied

proc readSome*(t: var Transport; buf: var openArray[char]; dl: Deadline): int
    {.passive, raises.} =
  ## Read into task-owned memory using a nonblocking syscall, then wait if needed.
  result = 0
  if buf.len == 0: return
  while true:
    if dl <= monoNow(): raise TimeoutError
    when defined(tsuruTls):
      let ssl = t.ssl
      if ssl != nil:
        clearErrors()
        let n = tlsRead(ssl, addr buf[0], cint(buf.len))
        if n > 0: return int(n)
        let err = tlsError(ssl, n)
        if err == 6: return 0
        if err == 2: waitReady(t.sock.fd, {evRead}, dl)
        elif err == 3: waitReady(t.sock.fd, {evWrite}, dl)
        else: raise IOError
      else:
        let n = cRecv(t.sock.fd, addr buf[0], csize_t(buf.len), 0)
        if n >= 0: return n
        let err = errno()
        if err == EAGAIN: waitReady(t.sock.fd, {evRead}, dl)
        elif err != EINTR: raise IOError
    else:
      let n = cRecv(t.sock.fd, addr buf[0], csize_t(buf.len), 0)
      if n >= 0: return n
      let err = errno()
      if err == EAGAIN: waitReady(t.sock.fd, {evRead}, dl)
      elif err != EINTR: raise IOError

proc writeAll*(t: var Transport; data: string; dl: Deadline) {.passive, raises.} =
  ## Complete the write under one deadline, retaining the retry buffer across TLS waits.
  var buf = default(array[8192, char])
  var off = 0
  while off < data.len:
    let count = min(buf.len, data.len - off)
    copyMem(addr buf[0], readRawData(data, off), count)
    var sent = 0
    while sent < count:
      if dl <= monoNow(): raise TimeoutError
      when defined(tsuruTls):
        let ssl = t.ssl
        if ssl != nil:
          clearErrors()
          let n = tlsWrite(ssl, addr buf[sent], cint(count - sent))
          if n > 0: sent += int(n)
          else:
            let err = tlsError(ssl, n)
            if err == 2: waitReady(t.sock.fd, {evRead}, dl)
            elif err == 3: waitReady(t.sock.fd, {evWrite}, dl)
            else: raise IOError
        else:
          let n = cSend(t.sock.fd, addr buf[sent], csize_t(count - sent), 0x4000)
          if n > 0: sent += n
          elif n == 0: raise IOError
          else:
            let err = errno()
            if err == EAGAIN: waitReady(t.sock.fd, {evWrite}, dl)
            elif err != EINTR: raise IOError
      else:
        let n = cSend(t.sock.fd, addr buf[sent], csize_t(count - sent), 0x4000)
        if n > 0: sent += n
        elif n == 0: raise IOError
        else:
          let err = errno()
          if err == EAGAIN: waitReady(t.sock.fd, {evWrite}, dl)
          elif err != EINTR: raise IOError
    off += count
