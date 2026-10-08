import testkit
import tsuru/internal/buffer

block append:
  var s = "hi"
  let alias = s
  appendBytes(s, ['!', '\0', '\xFF'])
  doAssert s == "hi!\0\xFF" and alias == "hi"

block consume:
  var s = "firstsecond"
  let alias = s
  dropPrefix(s, 5)
  doAssert s == "second" and alias == "firstsecond"
  dropPrefix(s, 0)
  doAssert s == "second"
  dropPrefix(s, s.len)
  doAssert s == ""
  appendBytes(s, "third")
  doAssert s == "third"

echo "buffer tests passed"
