## Nonblocking TCP and optional verified TLS. Only readiness waits park on the ring.
## Deadlines never leave a kernel read holding a pointer into an expired task.
import std/[ioring, dns, strutils]
from std/socket import toErr
from std/posix/posix import errno, EAGAIN, EINTR, SockAddr, TSa_Family

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
  descriptor: int
    ## fd + 1; zero owns nothing, including after default construction or a move.
  when defined(tsuruTls):
    ctx: nil ptr SslCtx
    ssl: nil ptr Ssl

proc fd(t: Transport): cint {.inline.} = cint(t.descriptor - 1)

proc release(t: Transport) =
  when defined(tsuruTls):
    let ssl = t.ssl
    let ctx = t.ctx
    if ssl != nil: sslFree(ssl)
    if ctx != nil: ctxFree(ctx)
  if t.descriptor != 0: closeFd(t.fd)

proc `=destroy`*(t: Transport) = release(t)

proc `=wasMoved`*(t: var Transport) {.nodestroy.} =
  t.descriptor = 0
  when defined(tsuruTls):
    t.ssl = nil
    t.ctx = nil

proc `=copy`*(dest: var Transport; src: Transport) {.error.}
proc `=dup`*(src: Transport): Transport {.error.}

proc close*(t: var Transport) =
  ## Idempotent release of TLS handles and socket, including on handshake failure.
  release(t)
  `=wasMoved`(t)

proc checkDeadline*(dl: Deadline) {.raises.} =
  if dl <= monoNow(): raise TimeoutError

proc waitReady(fd: cint; events: IoEvents; dl: Deadline) {.passive, raises.} =
  checkDeadline(dl)
  var n = -1
  let c = delay()
  discard submitPollAdd(fd, dl, events, c, addr n)
  suspend()
  if n < 0: raise toErr(n)

proc requireTls(secure: bool) {.raises.} =
  when not defined(tsuruTls):
    if secure: raise UnimplementedOperation

proc open*(t: var Transport; host: string; port: uint16; secure: bool;
           caFile: string; dl: Deadline) {.passive, raises.} =
  ## Connect IPv4/DNS or an IPv6 literal; bound the TCP and TLS handshakes by dl.
  requireTls(secure)
  checkDeadline(dl)
  var hostBuf = host
  var ip = host
  var family = AF_INET
  var addressOffset = 4
  var addressLen = SockLen(16)
  if ':' in host:
    family = AF_INET6
    addressOffset = 8
    addressLen = SockLen(28)
  else:
    if not host.allCharsInSet(Digits + {'.'}): ip = resolve(host, dl)
  var sa = Sockaddr_storage()
  cast[ptr SockAddr](addr sa)[].sa_family = TSa_Family(ord(family))
  let raw = cast[ptr UncheckedArray[uint8]](addr sa)
  raw[2] = uint8(port shr 8)
  raw[3] = uint8(port and 255)
  if inetPton(cint(family), toCString(ip), addr raw[addressOffset]) != 1: raise ValueError
  checkDeadline(dl)
  # Linux SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, set atomically at creation.
  let socketFd = cSocket(cint(family), cint(SOCK_STREAM) or O_NONBLOCK or 0x80000,
    cint(IPPROTO_TCP))
  if socketFd < 0: raise IOError
  t.descriptor = int(socketFd) + 1
  var n = -1
  let c = delay()
  discard submitConnect(socketFd, sa, addressLen, dl, c, addr n)
  suspend()
  if n != 0: raise toErr(n)
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
      if tlsConfigure(ssl, t.fd, toCString(hostBuf)) != 1: raise IOError
      var done = false
      while not done:
        checkDeadline(dl)
        clearErrors()
        let n = tlsConnect(ssl)
        if n == 1: done = true
        else:
          let err = tlsError(ssl, n)
          if err == 2: waitReady(t.fd, {evRead}, dl)
          elif err == 3: waitReady(t.fd, {evWrite}, dl)
          else: raise PermissionDenied

proc readSome*(t: var Transport; buf: var openArray[char]; dl: Deadline): int
    {.passive, raises.} =
  ## Read into task-owned memory using a nonblocking syscall, then wait if needed.
  result = 0
  if buf.len == 0: return
  while true:
    checkDeadline(dl)
    when defined(tsuruTls):
      let ssl = t.ssl
      if ssl != nil:
        clearErrors()
        let n = tlsRead(ssl, addr buf[0], cint(buf.len))
        if n > 0: return int(n)
        let err = tlsError(ssl, n)
        if err == 6: return 0
        if err == 2: waitReady(t.fd, {evRead}, dl)
        elif err == 3: waitReady(t.fd, {evWrite}, dl)
        else: raise IOError
        continue
    let n = cRecv(t.fd, addr buf[0], csize_t(buf.len), 0)
    if n >= 0: return n
    let err = errno()
    if err == EAGAIN: waitReady(t.fd, {evRead}, dl)
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
      checkDeadline(dl)
      when defined(tsuruTls):
        let ssl = t.ssl
        if ssl != nil:
          clearErrors()
          let n = tlsWrite(ssl, addr buf[sent], cint(count - sent))
          if n > 0: sent += int(n)
          else:
            let err = tlsError(ssl, n)
            if err == 2: waitReady(t.fd, {evRead}, dl)
            elif err == 3: waitReady(t.fd, {evWrite}, dl)
            else: raise IOError
          continue
      let n = cSend(t.fd, addr buf[sent], csize_t(count - sent), 0x4000)
      if n > 0: sent += n
      elif n == 0: raise IOError
      else:
        let err = errno()
        if err == EAGAIN: waitReady(t.fd, {evWrite}, dl)
        elif err != EINTR: raise IOError
    off += count
