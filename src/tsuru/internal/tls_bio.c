/* Internal OpenSSL socket BIO with per-send SIGPIPE suppression. */
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

static BIO_METHOD *socket_method;
static CRYPTO_ONCE socket_once = CRYPTO_ONCE_STATIC_INIT;

static int socket_create(BIO *b) {
  BIO_set_init(b, 1);
  return 1;
}
static int socket_destroy(BIO *b) { (void)b; return 1; }
static int socket_read(BIO *b, char *buf, int len) {
  BIO_clear_retry_flags(b);
  int n = (int)recv((int)(intptr_t)BIO_get_data(b), buf, (size_t)len, 0);
  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
    BIO_set_retry_read(b);
  return n;
}
static int socket_write(BIO *b, const char *buf, int len) {
  BIO_clear_retry_flags(b);
  int n = (int)send((int)(intptr_t)BIO_get_data(b), buf, (size_t)len, MSG_NOSIGNAL);
  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
    BIO_set_retry_write(b);
  return n;
}
static long socket_ctrl(BIO *b, int cmd, long arg, void *ptr) {
  (void)b; (void)arg; (void)ptr;
  return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}
static void socket_setup(void) {
  socket_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "tsuru socket");
  if (!socket_method) return;
  BIO_meth_set_create(socket_method, socket_create);
  BIO_meth_set_destroy(socket_method, socket_destroy);
  BIO_meth_set_read(socket_method, socket_read);
  BIO_meth_set_write(socket_method, socket_write);
  BIO_meth_set_ctrl(socket_method, socket_ctrl);
}
int tsuru_tls_configure(SSL *ssl, int fd, const char *host) {
  unsigned char ip[16];
  if (inet_pton(AF_INET, host, ip) == 1 || inet_pton(AF_INET6, host, ip) == 1) {
    if (!X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host)) return 0;
  } else {
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!SSL_set1_host(ssl, host) || !SSL_set_tlsext_host_name(ssl, host)) return 0;
  }
  if (!CRYPTO_THREAD_run_once(&socket_once, socket_setup) || !socket_method) return 0;
  BIO *bio = BIO_new(socket_method);
  if (!bio) return 0;
  BIO_set_data(bio, (void *)(intptr_t)fd);
  SSL_set_bio(ssl, bio, bio);
  return 1;
}
