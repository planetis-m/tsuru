# A standard-library WebSocket client for WebDriver BiDi

The implementation target is WebDriver BiDi. Use whole-message operations and
terminal transport I/O failures/timeouts. Message-body streams and resumable
application/control writes are outside the initial scope. BiDi command deadlines
remain a separate policy decision above the WebSocket transport.

## Requirements derived from BiDi

BiDi transports JSON in WebSocket text messages. Commands carry IDs, responses
may arrive out of order, and events arrive independently. Screenshots are
Base64 strings inside JSON, so some messages can be large.

Sources: [BiDi transport](https://www.w3.org/TR/webdriver-bidi/#transport),
[commands](https://www.w3.org/TR/webdriver-bidi/#commands), and
[captureScreenshot](https://www.w3.org/TR/webdriver-bidi/#command-browsingContext-captureScreenshot).
These establish the application requirements; the policies below are design
recommendations rather than additional protocol requirements.

Use a compact WebSocket protocol object over standard streams. The constructor
completes the upgrade before returning, network operations are passive and raise
standard errors, and TLS uses the same TlsEngine convention as std/httpclient.

## Initial WebSocket surface

Tsuru already supplies the required transport behavior on its supported Linux/C
platform: complete text messages, strict incoming UTF-8, fragment assembly,
automatic controls, and receive expiry preserving partial input and pending
pongs. Its command wire fixture exercises concurrent IDs, reverse-order replies,
events, expiry, and a late response; its large-message fixture uses 20 MiB text.
These are transport fixtures, not validation against a real BiDi browser.
The BiDi JSON dispatcher still needs to be implemented above Tsuru. Configure
its message limit and operation budgets for the workload; secure connections
require its OpenSSL-enabled build. No stdlib additions are needed to use Tsuru.

- Construct an owned, move-only connection from a ws/wss URL, with an absolute
  setup deadline, optional standard headers/TLS engine, and a message-size limit.
- Send a complete text string and flush it before returning.
- Receive one complete message, preserving its text/binary/close distinction.
  The BiDi layer accepts text and diagnoses an unexpected binary message.
- Explicit close performs a deadline-bounded closing handshake; abort and
  destruction release immediately. No destructor waits for a peer.
- Expose connection status and peer-close information as needed.

Keep binary and close distinctions in the codec even though BiDi sends text.
Do not mistake a transport read, WebSocket frame, or fragment for a complete
JSON message. Receive must assemble fragmentation, validate UTF-8 and lengths,
answer pings, and process close frames. Use a configurable message limit that
can accommodate large screenshot and script results.

Whole-message strings are sufficient for the first implementation. Omit the
previously proposed nextMessage/read/readAll body interface, Reader upload
overload, compression negotiation, automatic reconnection, background heartbeats,
and independently usable read/write handles.

## Terminal transport failures and timeouts

An I/O failure or deadline expiry aborts the WebSocket and raises ErrorCode.
Discard incomplete input and output and release both standard-stream ends.
Suppress the Writer's clean-finish destructor before dropping it, so a failed
message is not flushed or finalized implicitly. Invalid caller input detected
before I/O can raise without terminating a healthy connection.

This policy removes the need for persistent pending ciphertext, resumable
partial-write cursors, adapter replay rules, or a new TLS-engine interface.
Normal short writes are still handled by the existing write loops; a timeout
during that loop is terminal.

This is a deliberate change from the earlier receive-polling proposal. Tsuru's
own recoverable-expiry contract remains unchanged.

## BiDi session layer

Keep BiDi-specific JSON and command semantics above std/websocket:

```text
BiDi session: JSON, command IDs, pending responses, events, command deadlines
    |
std/websocket: complete messages, fragmentation, controls, terminal I/O errors
    |
std/streamio: buffering, deadlines, TLS, socket ownership
```

Use one owning task or caller-driven pump to serialize socket operations. It
can send several commands without waiting for their responses. A naive
send-command/read-next-message implementation is insufficient: that next
message can be an event or a response to a different command.

The session dispatcher maintains IDs and pending requests, routes responses by
ID, and dispatches events. Follow-up commands triggered by events must be
sendable while earlier commands remain pending. Avoid blocking the owner on an
event handler that itself waits for the owner to process another response.

A command deadline belongs to its pending request, independently of socket
lifetime. Expiry stops waiting locally; it does not cancel the remote action.
Handle late responses deliberately and avoid reusing IDs while they could be
confused with an earlier response. Do not automatically retry a timed-out
command: it may already have affected the browser.

Do not use short receive deadlines for polling under the terminal-timeout
policy. The simplest initial client can treat a command wait deadline as a
transport deadline and terminate the connection on expiry. If the session must
continue after command expiry, command timers must expire independently of a
pending receive. Servicing new outgoing commands while that receive is parked
also needs an explicit scheduling/serialization design. Current stream pairs do
not establish safe concurrent TLS or control writes. That stronger asynchronous
session model is separate work; the buffered-reader additions do not provide it.

## Adjacent standard-library work

| Module | Change | Current branch / assessment |
| --- | --- | --- |
| streamio.Reader | buffered, peek, consume, fill, following Socket | Covered by stdlib-streamio-reader-buffer; no blocking findings in source review |
| streamio | Deadline getters/setters and setup deadlines spanning DNS, TCP, TLS, and initial request output | Covered separately by codex/streamio-deadlines; not included in the reader branch |
| http/httpheaders | Shared header construction, lookup, iteration, and literal helpers; re-export from httpclient | Covered separately by codex/httpheaders-helpers |
| unicode | Strict validation of complete text messages | unicode-stateless-utf8 provides the focused correctness fix |

The compiled probe confirmed that the base unicode.validateUtf8 accepts
overlong encodings, surrogate encodings, and values above U+10FFFF. Incremental
validation while assembling a message is optional and independent of the
timeout policy. unicode-utf8-validation adds that capability; use it if we choose
early validation like Beast, rather than making it a prerequisite for BiDi.

No resumable-output change is needed with terminal I/O errors. The WebSocket
implementation must still enforce terminal cleanup; the new Reader functions
do not change the failure policy of existing standard streams.

The reader branch exposes decoded unread bytes without copying, preserves the
tail while filling/compacting, and supports adapter handoff. A zero fill result
can coexist with unread bytes at source/adapter end. The caller must inspect
buffered input before treating zero as an incomplete-message EOF, and must bound
accumulation. The branch's tests cover these contracts. This was source review;
the tests were not rerun.

Use parseUri for splitting and validate the WebSocket URL separately. Validate
the complete caller header block as well as individual inserted headers, since
HttpHeaders can be constructed directly from a string.

IPv6 and broader TLS interoperability remain shared transport work. Use the
standard TLS engine and its existing injection point. The initial client need
not introduce a second socket owner, OpenSSL bindings, or a new scheduler.

## Acceptance tests

Test base WebSocket framing with deterministic fixtures, including fragmentation
and split UTF-8, empty messages, upgrade read-ahead, malformed framing, early
length rejection, ping/pong, and peer close. Force expiry during partial input
and partial automatic output; verify terminal cleanup, no retry of partial
output, and no implicit writer flushing. Include TLS failures and descriptor
cleanup.

Test the BiDi dispatcher with events between responses, out-of-order responses,
large JSON results, and cleanup on browser disconnect. Test the chosen command
timeout policy explicitly. If independently expiring command waits and continued
sessions are implemented, additionally test late responses, follow-up commands
while another is pending, and a subsequent successful command on the same
connection.

Finally verify against a real BiDi endpoint: establish a session, subscribe to
events, issue navigation/script commands, receive events and responses, and
capture a screenshot. Tests for browser features should match the commands
actually implemented; full coverage of the BiDi specification is not required
to validate the WebSocket transport.

Earlier transport probing verified plain and TLS standard-stream connections,
client masking, upgrade read-ahead, and TLS hostname rejection. The UTF-8 defect
was also reproduced with a compiled probe. The recommended implementation and
the new shared-library changes have not yet been built.
