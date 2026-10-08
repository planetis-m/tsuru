import std/[assertions, syncio]
import sanitizers
export syncio

template doAssert*(cond: bool; msg = "test failed") =
  if not cond: raiseAssert(msg)
