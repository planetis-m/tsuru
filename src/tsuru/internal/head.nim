## One-pass HTTP/1.x response head tokenizer shared by the HTTP client and the
## WebSocket upgrade. Every proc follows std/http/httpparse's shape: it reads
## the front of a view and returns the bytes consumed, or ParseBad. Validation
## is a by-product of tokenizing: nothing is rescanned and nothing is copied.
from std/http/httpparse import parseToken, skipSpaces, parseCrLf, parseStatus,
  parseReason, ParseBad

type Field* = object
  ## Offsets relative to the view handed to parseField.
  nameLen*: int
  valueStart*, valueLen*: int

const
  BadValueChars = {'\0'..'\x08', '\x0A'..'\x1F', '\x7F'}
    ## RFC 9110 §5.5: CR, LF and NUL are rejected; so are the other controls,
    ## except HTAB. obs-text (0x80-0xFF) is kept.

proc toLower(c: char): char {.inline.} =
  if c in {'A'..'Z'}: char(ord(c) + 32) else: c

proc validToken*(s: openArray[char]): bool =
  ## A nonempty RFC 9110 token, such as a field name or method.
  s.len > 0 and parseToken(s) == s.len

proc cleanValue*(s: openArray[char]): bool =
  ## Whether s may be sent as a field value: no controls other than HTAB.
  result = true
  for c in s:
    if c in BadValueChars: return false

proc parseStatusLine*(buf: openArray[char]; status, minor: var int): int =
  ## `HTTP/1.0` or `HTTP/1.1`, SP, a status in 100..599, optional reason, line end.
  ## The reason phrase is checked for controls while finding the line end and
  ## then discarded (RFC 9110 §15.1).
  const Prefix = "HTTP/1."
  if buf.len < 12: return ParseBad
  for k in 0..<Prefix.len:
    if buf[k] != Prefix[k]: return ParseBad
  if buf[7] notin {'0', '1'} or buf[8] != ' ': return ParseBad
  minor = ord(buf[7]) - ord('0')
  if parseStatus(toOpenArray(buf, 9, buf.len - 1), status) != 3: return ParseBad
  var i = 12
  if i < buf.len and buf[i] == ' ':
    let reason = parseReason(toOpenArray(buf, i + 1, buf.len - 1))
    if reason < 0: return ParseBad
    i += reason + 1
  let eol = parseCrLf(toOpenArray(buf, i, buf.len - 1))
  result = if eol < 0: ParseBad else: i + eol

proc parseField*(buf: openArray[char]; f: var Field): int =
  ## `token ":" OWS value OWS` and its line end. Leading whitespace (obs-fold)
  ## and whitespace before the colon are rejected.
  let nameLen = parseToken(buf)
  if nameLen < 0 or nameLen >= buf.len or buf[nameLen] != ':': return ParseBad
  var i = nameLen + 1
  i += skipSpaces(toOpenArray(buf, i, buf.len - 1))
  let start = i
  while i < buf.len and buf[i] != '\r' and buf[i] != '\n':
    if buf[i] in BadValueChars: return ParseBad
    inc i
  var stop = i
  while stop > start and buf[stop - 1] in {' ', '\t'}: dec stop
  let eol = parseCrLf(toOpenArray(buf, i, buf.len - 1))
  if eol < 0: return ParseBad
  f = Field(nameLen: nameLen, valueStart: start, valueLen: stop - start)
  result = i + eol

proc parseHeadEnd*(buf: openArray[char]): int =
  ## The blank line ending a head: its length, or ParseBad when a field follows.
  result = parseCrLf(buf)
  if result < 0: result = ParseBad

proc equals*(s: openArray[char]; b: string): bool =
  if s.len != b.len: return false
  for i in 0..<s.len:
    if s[i] != b[i]: return false
  result = true

proc equalsLower*(s: openArray[char]; lower: string): bool =
  ## ASCII case-insensitive comparison with an already lowercase string.
  if s.len != lower.len: return false
  for i in 0..<s.len:
    if toLower(s[i]) != lower[i]: return false
  result = true

proc sameIgnoreCase*(a, b: openArray[char]): bool =
  if a.len != b.len: return false
  for i in 0..<a.len:
    if toLower(a[i]) != toLower(b[i]): return false
  result = true

proc hasToken*(value: openArray[char]; token: string): bool =
  ## Whether a comma-separated list contains token, ignoring ASCII case and OWS.
  result = false
  var i = 0
  while i < value.len:
    while i < value.len and value[i] in {' ', '\t', ','}: inc i
    let start = i
    while i < value.len and value[i] != ',': inc i
    var stop = i
    while stop > start and value[stop - 1] in {' ', '\t'}: dec stop
    if stop > start and sameIgnoreCase(toOpenArray(value, start, stop - 1), token):
      return true

proc copyLower*(s: openArray[char]): string =
  result = ""
  if s.len > 0:
    let p = beginStore(result, s.len)
    for i in 0..<s.len: p[i] = toLower(s[i])
    endStore(result)
