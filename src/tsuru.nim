## Tsuru (鶴): passive WebSocket and HTTP/1.1 clients for Nimony.
##
## The package root is a facade. Importing `tsuru` re-exports both
## `tsuru/websocket` and `tsuru/httpclient`, including their shared `Header`,
## `HttpResponse` and `Deadline` types. Prefer the explicit module import when
## a module uses only one protocol. The clients share one passive, sequential
## I/O model; see the module documentation of each client for contracts.
import tsuru/websocket
import tsuru/httpclient

export websocket
export httpclient
