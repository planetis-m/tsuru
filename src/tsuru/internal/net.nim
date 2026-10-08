## Linux socket calls and address construction for the passive transport.
from std/posix/posix import Sockaddr_in, Sockaddr_storage, SockLen, TSa_Family,
  AF_INET, AF_INET6, SOCK_STREAM, IPPROTO_TCP, O_NONBLOCK, O_CLOEXEC

type SockaddrIn6 = object
  ## Linux sockaddr_in6 layout; the ring accepts its bytes as Sockaddr_storage.
  family: uint16
  port: uint16
  flowInfo: uint32
  address: array[16, uint8]
  scopeId: uint32

const MsgNoSignal* = 0x4000.cint
  ## Suppress SIGPIPE for this send without changing process signal handlers.
const TcpNoDelay = 1.cint

proc recv*(fd: cint; buf: pointer; len: csize_t; flags: cint): int
  {.importc: "recv", header: "<sys/socket.h>".}
proc send*(fd: cint; buf: pointer; len: csize_t; flags: cint): int
  {.importc: "send", header: "<sys/socket.h>".}
proc socket(domain, kind, protocol: cint): cint
  {.importc: "socket", header: "<sys/socket.h>".}
proc inetPton(family: cint; src: cstring; dest: pointer): cint
  {.importc: "inet_pton", header: "<arpa/inet.h>".}
proc htons(value: uint16): uint16
  {.importc: "htons", header: "<arpa/inet.h>".}
proc setsockopt(fd, level, option: cint; value: pointer; length: SockLen): cint
  {.importc: "setsockopt", header: "<sys/socket.h>".}

proc setNoDelay*(fd: cint) =
  ## Disable Nagle for small WebSocket messages and control replies.
  var yes = 1.cint
  discard setsockopt(fd, IPPROTO_TCP, TcpNoDelay, addr yes, SockLen(sizeof(yes)))

proc prepareConnect*(ip: string; port: uint16; address: var Sockaddr_storage;
                     addressLen: var SockLen; fd: var cint) {.raises.} =
  ## Build a literal address and create a nonblocking, close-on-exec TCP socket.
  ## On success the caller owns fd. No descriptor is acquired on failure.
  var text = ip
  var family = AF_INET
  address = Sockaddr_storage()
  if ':' in ip:
    family = AF_INET6
    var a6 = SockaddrIn6(family: uint16(AF_INET6), port: htons(port))
    if inetPton(AF_INET6, toCString(text), addr a6.address) != 1:
      raise ValueError
    copyMem(addr address, addr a6, sizeof(a6))
    addressLen = SockLen(sizeof(a6))
  else:
    var a4 = Sockaddr_in()
    a4.sin_family = TSa_Family(AF_INET)
    a4.sin_port = htons(port)
    if inetPton(AF_INET, toCString(text), addr a4.sin_addr) != 1:
      raise ValueError
    copyMem(addr address, addr a4, sizeof(a4))
    addressLen = SockLen(sizeof(a4))
  fd = socket(family, SOCK_STREAM or O_NONBLOCK or O_CLOEXEC, IPPROTO_TCP)
  if fd < 0:
    raise IOError
