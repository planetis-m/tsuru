## Optional instrumentation for the Nimony C backend.
when defined(addressSanitizer):
  {.passC: "-g -fsanitize=address,undefined -fno-omit-frame-pointer".}
  {.passL: "-fsanitize=address,undefined".}
