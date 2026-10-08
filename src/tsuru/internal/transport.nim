## Nonblocking TCP and optional verified TLS. Only readiness waits park on the ring.
## Deadlines never leave a kernel read holding a pointer into an expired task.
import std/[ioring, dns, strutils]
import ./[buffer, net]
from std/socket import toErr
from std/posix/posix import errno, EAGAIN, EINTR

when not defined(linux):
  {.error: "Tsuru currently supports Linux.".}

when defined(tsuruTls):
  import ./tls

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
  var ip = host
  if ':' notin host and not host.allCharsInSet(Digits + {'.'}):
    ip = resolve(host, dl)
  var sa = Sockaddr_storage()
  var addressLen = SockLen(0)
  var socketFd = -1.cint
  checkDeadline(dl)
  prepareConnect(ip, port, sa, addressLen, socketFd)
  t.descriptor = int(socketFd) + 1
  var n = -1
  let c = delay()
  discard submitConnect(socketFd, sa, addressLen, dl, c, addr n)
  suspend()
  if n != 0: raise toErr(n)
  setNoDelay(socketFd)
  when defined(tsuruTls):
    if secure:
      let tlsMode = tlsMethod()
      if tlsMode == nil: raise IOError
      let ctx = ctxNew(tlsMode)
      if ctx == nil: raise IOError
      t.ctx = ctx
      setVerify(ctx, TlsVerifyPeer, nil)
      if caFile.len == 0:
        if defaultTrust(ctx) != 1: raise IOError
      else:
        var caBuf = caFile
        if loadTrust(ctx, toCString(caBuf), nil) != 1: raise IOError
      let ssl = sslNew(ctx)
      if ssl == nil: raise IOError
      t.ssl = ssl
      var hostBuf = host
      if tlsConfigure(ssl, t.fd, toCString(hostBuf)) != 1: raise IOError
      var done = false
      while not done:
        checkDeadline(dl)
        clearErrors()
        let n = tlsConnect(ssl)
        if n == 1: done = true
        else:
          let err = tlsError(ssl, n)
          if err == TlsWantRead: waitReady(t.fd, {evRead}, dl)
          elif err == TlsWantWrite: waitReady(t.fd, {evWrite}, dl)
          else: raise PermissionDenied

proc readSome*[T: char | byte](t: var Transport; buf: var openArray[T]; dl: Deadline): int
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
        if err == TlsClosed: return 0
        if err == TlsWantRead: waitReady(t.fd, {evRead}, dl)
        elif err == TlsWantWrite: waitReady(t.fd, {evWrite}, dl)
        else: raise IOError
        continue
    let n = net.recv(t.fd, addr buf[0], csize_t(buf.len), 0)
    if n >= 0: return n
    let err = errno()
    if err == EAGAIN: waitReady(t.fd, {evRead}, dl)
    elif err != EINTR: raise IOError

proc writeAll*[T: char | byte](t: var Transport; data: openArray[T]; sent: var int; dl: Deadline)
    {.passive, raises.} =
  ## Write task-owned memory. Keep data alive and unchanged until this call returns.
  ## TLS retries retain the same pointer and length across readiness waits.
  ## sent is an offset in data; preserve both across a resumable timeout.
  while sent < data.len:
    checkDeadline(dl)
    when defined(tsuruTls):
      let ssl = t.ssl
      if ssl != nil:
        clearErrors()
        let count = min(data.len - sent, int(high(cint)))
        let n = tlsWrite(ssl, addr data[sent], cint(count))
        if n > 0: sent += int(n)
        else:
          let err = tlsError(ssl, n)
          if err == TlsWantRead: waitReady(t.fd, {evRead}, dl)
          elif err == TlsWantWrite: waitReady(t.fd, {evWrite}, dl)
          else: raise IOError
        continue
    let n = net.send(t.fd, addr data[sent], csize_t(data.len - sent), MsgNoSignal)
    if n > 0: sent += n
    elif n == 0: raise IOError
    else:
      let err = errno()
      if err == EAGAIN: waitReady(t.fd, {evWrite}, dl)
      elif err != EINTR: raise IOError

proc writeAll*[T: char | byte](t: var Transport; data: openArray[T]; dl: Deadline)
    {.passive, raises.} =
  var sent = 0
  writeAll(t, data, sent, dl)

proc writeAll*(t: var Transport; data: string; dl: Deadline) {.passive, raises.} =
  ## Copy string chunks into task-owned memory before any suspended write.
  var buf = default(array[8192, char])
  var off = 0
  while off < data.len:
    let count = min(buf.len, data.len - off)
    copyOut(toOpenArray(buf, 0, count - 1), data, off)
    writeAll(t, toOpenArray(buf, 0, count - 1), dl)
    off += count
