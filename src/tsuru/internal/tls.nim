## OpenSSL client bindings and the socket BIO used by the transport.
{.passL: "-lssl -lcrypto".}
{.compile: "tls_bio.c".}

type
  SslCtx* {.importc: "SSL_CTX", header: "<openssl/ssl.h>", incompleteStruct.} = object
  Ssl* {.importc: "SSL", header: "<openssl/ssl.h>", incompleteStruct.} = object
  SslMethod* {.importc: "SSL_METHOD", header: "<openssl/ssl.h>", incompleteStruct.} = object

proc tlsMethod*(): nil ptr SslMethod {.importc: "TLS_client_method", header: "<openssl/ssl.h>".}
proc ctxNew*(m: ptr SslMethod): nil ptr SslCtx
  {.importc: "SSL_CTX_new", header: "<openssl/ssl.h>".}
proc ctxFree*(c: ptr SslCtx) {.importc: "SSL_CTX_free", header: "<openssl/ssl.h>".}
proc sslNew*(c: ptr SslCtx): nil ptr Ssl {.importc: "SSL_new", header: "<openssl/ssl.h>".}
proc sslFree*(s: ptr Ssl) {.importc: "SSL_free", header: "<openssl/ssl.h>".}
proc defaultTrust*(c: ptr SslCtx): cint
  {.importc: "SSL_CTX_set_default_verify_paths", header: "<openssl/ssl.h>".}
proc loadTrust*(c: ptr SslCtx; file: cstring; dir: nil cstring): cint
  {.importc: "SSL_CTX_load_verify_locations", header: "<openssl/ssl.h>".}
proc setVerify*(c: ptr SslCtx; mode: cint; cb: nil pointer)
  {.importc: "SSL_CTX_set_verify", header: "<openssl/ssl.h>".}
proc tlsConfigure*(s: ptr Ssl; fd: cint; host: cstring): cint
  {.importc: "tsuru_tls_configure".}
proc tlsConnect*(s: ptr Ssl): cint {.importc: "SSL_connect", header: "<openssl/ssl.h>".}
proc tlsRead*(s: ptr Ssl; buf: pointer; len: cint): cint
  {.importc: "SSL_read", header: "<openssl/ssl.h>".}
proc tlsWrite*(s: ptr Ssl; buf: pointer; len: cint): cint
  {.importc: "SSL_write", header: "<openssl/ssl.h>".}
proc tlsError*(s: ptr Ssl; ret: cint): cint
  {.importc: "SSL_get_error", header: "<openssl/ssl.h>".}
proc clearErrors*() {.importc: "ERR_clear_error", header: "<openssl/err.h>".}

const
  TlsWantRead* = 2.cint
  TlsWantWrite* = 3.cint
  TlsClosed* = 6.cint
  TlsVerifyPeer* = 1.cint
