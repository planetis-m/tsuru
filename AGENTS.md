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

Follow Hashi's module boundaries and byte-buffer conventions. `frame` owns the
wire codec; `protocol` owns message assembly and protocol decisions. Socket and
OpenSSL declarations belong in `internal/net` and `internal/tls`; `transport`
owns resources and passive I/O. Keep bulk string operations in `internal/buffer`.
Use `openArray` views for byte operations and `beginStore`/`endStore` for writable
string storage. Keep raw pointers at the FFI and bulk-store boundaries.
Borrowed parameters may span a normal passive call; scheduler entry points must
take owned values. Source comments describe current contracts and invariants.

Match Hashi's reusable send buffer and in-place receive consumption. Offer whole
frames to the transport and handle partial writes there. Use a word-sized mask
loop with a byte tail. Trust application-supplied outgoing payloads; document
their preconditions rather than adding validation. Keep client-specific masking,
upgrade checks and existing peer protocol checks.
