## Authority and wire target shared by HTTP and WebSocket connections.
import std/strutils

type Endpoint* = object
  host*, authority*, target*: string
  port*: uint16
  secure*: bool

proc parseEndpoint*(url, plainScheme, secureScheme: string): Endpoint {.raises.} =
  ## Parse a client URL; reject fragments, userinfo, whitespace and unescaped controls.
  var start = 0
  var secure = false
  if url.startsWith(plainScheme & "://"): start = plainScheme.len + 3
  elif url.startsWith(secureScheme & "://"):
    start = secureScheme.len + 3
    secure = true
  else: raise ValueError
  if url.find({'\0'..' ', '\x7f'..'\xff', '#', '\\'}) >= 0: raise ValueError
  var stop = start
  while stop < url.len and url[stop] != '/' and url[stop] != '?': inc stop
  if stop == start: raise ValueError
  let authority = url[start..<stop]
  if '@' in authority: raise ValueError
  var host = ""
  var portText = ""
  if authority[0] == '[':
    let bracket = authority.find(']')
    if bracket <= 1: raise ValueError
    host = authority[1..<bracket]
    if ':' notin host: raise ValueError
    if bracket + 1 < authority.len:
      if authority[bracket + 1] != ':': raise ValueError
      portText = authority[bracket + 2..^1]
      if portText.len == 0: raise ValueError
  else:
    let colon = authority.find(':')
    if colon >= 0:
      host = authority[0..<colon]
      portText = authority[colon + 1..^1]
      if portText.len == 0: raise ValueError
    else: host = authority
    if not host.allCharsInSet(Letters + Digits + {'-', '.'}): raise ValueError
  if host.len == 0: raise ValueError
  var port = if secure: 443 else: 80
  if portText.len > 0:
    port = 0
    for c in portText:
      if c notin {'0'..'9'}: raise ValueError
      port = port * 10 + ord(c) - ord('0')
      if port > 65535: raise ValueError
    if port == 0: raise ValueError
  var target = "/"
  if stop < url.len:
    target = url[stop..^1]
    if target[0] == '?': target = "/" & target
  result = Endpoint(host: host, authority: authority, target: target,
                    port: uint16(port), secure: secure)

