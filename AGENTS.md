# Working on Tsuru

This is a Nimony library. Read installed stdlib declarations before using them.
Errors are `ErrorCode`; scheduling and I/O use `.passive`.

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

`frame` owns the wire codec; `protocol` owns message assembly and protocol
decisions. `handshake` owns URL and HTTP upgrade decisions. Socket and
OpenSSL declarations belong in `internal/net` and `internal/tls`; `transport`
owns resources and passive I/O. Keep bulk string operations in `internal/buffer`.
Use `openArray` views for byte operations and `beginStore`/`endStore` for writable
string storage. Keep raw pointers at the FFI and bulk-store boundaries.
Borrowed parameters may span a normal passive call; scheduler entry points must
take owned values. Source comments describe current contracts and invariants.

Keep connection state private to the client. Use strings for owned wire buffers
and message payloads; accept byte sequences when that avoids a caller conversion.
Offer coalesced frames to the transport and handle partial writes there. Keep
buffer reuse and retained-memory costs explicit in the API docs. Trust outgoing
application payloads and document their preconditions. Validate peer framing,
text and upgrade responses. Every outgoing frame needs a fresh random mask.

Use tests/hashi.py --compat for optional integration checks against the sibling
server. The runner uses a temporary copy; do not change the server checkout.
