# Working on Tsuru

This is a Nimony 0.6.3 library, not a Nim 2 library. Read stdlib declarations
before using them. Errors are `ErrorCode`; scheduling and I/O use `.passive`.

Build and check with `tests/run --network`. Test TLS changes with
`tests/run --tls --network` and resource/I/O changes with
`tests/run --tls --asan --network`. Release and danger configurations must keep
the protocol checks active. The small testkit checks remain enabled in danger.

Keep pure framing/handshake decisions independent of socket operations. Check
peer lengths and indexes before allocating or indexing. Preserve one absolute
deadline across every operation's fragments, control frames and partial writes.
Each connection belongs to one task. Do not introduce concurrent access to an
OpenSSL session or bypass certificate verification.

Custom ownership hooks belong only on resources the compiler cannot release;
the transport is move-only and the public connection is a reference handle.
Never shut down the application's shared worker pool from library code.

The sibling Hashi checkout is a test dependency only, never a runtime dependency.
Its current compiler compatibility caveat is recorded in doc/verification.md.
Do not change Hashi as part of this client's tests; use tests/hashi.py --compat.
