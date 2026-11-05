## Nonblocking TCP and optional verified TLS. Only readiness waits park on the ring.
## Deadlines never leave a kernel read holding a pointer into an expired task.
import std/[ioring, dns, strutils]
import ./net
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

proc closeNotify*(t: var Transport) =
  ## Best effort before an orderly close: send a TLS close_notify without
  ## awaiting the peer's. A no-op for plain TCP; never suspends.
  when defined(tsuruTls):
    let ssl = t.ssl
    if ssl != nil:
      clearErrors()
      discard tlsShutdown(ssl)
      clearErrors()

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
  net.setNoDelay(socketFd)
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

const
  ReadWouldBlock = -1
  ReadWantsWrite = -2
  ReadInterrupted = -3

proc tryRead(t: var Transport; p: pointer; n: int): int {.raises.} =
  ## One nonblocking read of up to n bytes: the count, zero at end of stream,
  ## or a negative readiness code. Never suspends.
  when defined(tsuruTls):
    let ssl = t.ssl
    if ssl != nil:
      clearErrors()
      let got = tlsRead(ssl, p, cint(min(n, int(high(cint)))))
      if got > 0: return int(got)
      let err = tlsError(ssl, got)
      if err == TlsClosed: return 0
      if err == TlsWantRead: return ReadWouldBlock
      if err == TlsWantWrite: return ReadWantsWrite
      raise IOError
  let got = net.recv(t.fd, p, csize_t(n), 0)
  if got >= 0: return got
  let err = errno()
  if err == EAGAIN: return ReadWouldBlock
  if err == EINTR: return ReadInterrupted
  raise IOError

proc awaitRead(t: var Transport; code: int; dl: Deadline) {.passive, raises.} =
  if code == ReadWouldBlock: waitReady(t.fd, {evRead}, dl)
  elif code == ReadWantsWrite: waitReady(t.fd, {evWrite}, dl)

proc readSome*[T: char | byte](t: var Transport; buf: var openArray[T]; dl: Deadline): int
    {.passive, raises.} =
  ## Read into task-owned memory using a nonblocking syscall, then wait if needed.
  result = 0
  if buf.len == 0: return
  while true:
    checkDeadline(dl)
    let n = tryRead(t, addr buf[0], buf.len)
    if n >= 0: return n
    awaitRead(t, n, dl)

proc readInto*(t: var Transport; buf: var string; step: int; dl: Deadline): int
    {.passive, raises.} =
  ## Append up to step bytes straight into buf's spare capacity; zero means end
  ## of stream. The store is closed before any wait, so buf never suspends open.
  result = 0
  let old = buf.len
  while true:
    checkDeadline(dl)
    var n = ReadInterrupted
    let p = beginStore(buf, old + step, old)
    try:
      n = tryRead(t, p, step)
    finally:
      endStore(buf)
      buf.setLen(old + max(n, 0))
    if n >= 0: return n
    awaitRead(t, n, dl)

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
