## Count current process descriptors through libc's directory interface.
import testkit
{.compile: "fdcount.c".}
proc nativeCount(): cint {.importc: "tsuru_test_fd_count".}

proc fdCount*(): int =
  result = int(nativeCount())
  doAssert result >= 0
