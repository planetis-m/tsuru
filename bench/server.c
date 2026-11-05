/* Loopback benchmark peer for tsuru: HTTP/1.1 keep-alive responses and a
 * WebSocket echo. One thread per connection; responses are precomputed so the
 * client dominates the measurement. Build: cc -O2 -pthread bench/server.c -lcrypto */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define SMALL_LEN 16
#define LARGE_LEN (8 * 1024 * 1024)
#define CHUNKED_LEN (1024 * 1024)
#define CHUNK 4096
#define FRAGMENT 1024

static char *small_resp, *large_resp, *chunked_resp;
static size_t small_len, large_len, chunked_len;

static int write_all(int fd, const char *p, size_t n) {
  while (n > 0) {
    ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
    if (w <= 0) return -1;
    p += w; n -= (size_t)w;
  }
  return 0;
}

static int read_exact(int fd, char *p, size_t n) {
  while (n > 0) {
    ssize_t r = recv(fd, p, n, 0);
    if (r <= 0) return -1;
    p += r; n -= (size_t)r;
  }
  return 0;
}

static char *fixed_response(size_t body, size_t *len) {
  char head[128];
  int h = snprintf(head, sizeof head, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                   "Content-Length: %zu\r\n\r\n", body);
  char *r = malloc((size_t)h + body);
  memcpy(r, head, (size_t)h);
  for (size_t i = 0; i < body; i++) r[h + i] = (char)('a' + i % 26);
  *len = (size_t)h + body;
  return r;
}

static char *chunked_response(size_t *len) {
  const char *head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
  size_t cap = strlen(head) + CHUNKED_LEN + (CHUNKED_LEN / CHUNK) * 16 + 16;
  char *r = malloc(cap);
  size_t n = strlen(head);
  memcpy(r, head, n);
  for (size_t done = 0; done < CHUNKED_LEN; done += CHUNK) {
    n += (size_t)sprintf(r + n, "%x\r\n", CHUNK);
    for (size_t i = 0; i < CHUNK; i++) r[n + i] = (char)('a' + i % 26);
    n += CHUNK;
    memcpy(r + n, "\r\n", 2); n += 2;
  }
  memcpy(r + n, "0\r\n\r\n", 5); n += 5;
  *len = n;
  return r;
}

static size_t frame_head(char *h, int op, int fin, uint64_t n) {
  h[0] = (char)((fin ? 0x80 : 0) | op);
  if (n < 126) { h[1] = (char)n; return 2; }
  if (n <= 65535) { h[1] = 126; h[2] = (char)(n >> 8); h[3] = (char)n; return 4; }
  h[1] = 127;
  for (int i = 0; i < 8; i++) h[2 + i] = (char)(n >> (56 - 8 * i));
  return 10;
}

static void websocket(int fd, const char *key, int fragments) {
  static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char joined[128], accept[64], resp[256];
  unsigned char digest[SHA_DIGEST_LENGTH];
  snprintf(joined, sizeof joined, "%s%s", key, guid);
  SHA1((const unsigned char *)joined, strlen(joined), digest);
  EVP_EncodeBlock((unsigned char *)accept, digest, SHA_DIGEST_LENGTH);
  int n = snprintf(resp, sizeof resp, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                   "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept);
  if (write_all(fd, resp, (size_t)n)) return;
  size_t cap = 1 << 20;
  char *msg = malloc(cap), *out = malloc(cap + 64);
  size_t len = 0;
  int msg_op = 0;
  for (;;) {
    unsigned char h[14];
    if (read_exact(fd, (char *)h, 2)) break;
    int op = h[0] & 15, fin = h[0] & 128;
    uint64_t size = h[1] & 127;
    if (size == 126) { if (read_exact(fd, (char *)h + 2, 2)) break; size = (h[2] << 8) | h[3]; }
    else if (size == 127) {
      if (read_exact(fd, (char *)h + 2, 8)) break;
      size = 0;
      for (int i = 0; i < 8; i++) size = (size << 8) | h[2 + i];
    }
    unsigned char mask[4];
    if (read_exact(fd, (char *)mask, 4)) break;
    if (len + size > cap) {
      while (len + size > cap) cap *= 2;
      msg = realloc(msg, cap); out = realloc(out, cap + 64);
    }
    if (read_exact(fd, msg + len, size)) break;
    for (uint64_t i = 0; i < size; i++) msg[len + i] ^= (char)mask[i & 3];
    if (op == 8) { size_t hl = frame_head(out, 8, 1, size); memcpy(out + hl, msg + len, size);
      write_all(fd, out, hl + size); break; }
    if (op == 9) { size_t hl = frame_head(out, 10, 1, size); memcpy(out + hl, msg + len, size);
      if (write_all(fd, out, hl + size)) break;
      continue; }
    if (op != 0) msg_op = op;
    len += size;
    if (!fin) continue;
    size_t o = 0;
    if (fragments && len > FRAGMENT) {
      for (size_t at = 0; at < len; at += FRAGMENT) {
        size_t piece = len - at < FRAGMENT ? len - at : FRAGMENT;
        o += frame_head(out + o, at == 0 ? msg_op : 0, at + piece == len, piece);
        memcpy(out + o, msg + at, piece); o += piece;
        if (o + FRAGMENT + 16 > cap + 64) { if (write_all(fd, out, o)) goto done; o = 0; }
      }
    } else {
      o = frame_head(out, msg_op, 1, len);
      memcpy(out + o, msg, len); o += len;
    }
    if (write_all(fd, out, o)) break;
    len = 0;
  }
done:
  free(msg); free(out);
}

static void *serve(void *arg) {
  int fd = (int)(intptr_t)arg;
  int yes = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof yes);
  char buf[65536];
  size_t have = 0;
  for (;;) {
    char *end = NULL;
    while (!(end = memmem(buf, have, "\r\n\r\n", 4))) {
      if (have == sizeof buf) goto out;
      ssize_t r = recv(fd, buf + have, sizeof buf - have, 0);
      if (r <= 0) goto out;
      have += (size_t)r;
    }
    size_t head = (size_t)(end - buf) + 4;
    buf[head - 1] = 0;
    char *cl = strcasestr(buf, "\r\ncontent-length:");
    size_t body = cl ? strtoul(cl + 17, NULL, 10) : 0;
    char *key = strcasestr(buf, "\r\nsec-websocket-key:");
    if (key) {
      char k[64] = {0};
      sscanf(key + 20, " %63[^\r]", k);
      websocket(fd, k, strstr(buf, " /frag") != NULL);
      goto out;
    }
    const char *resp = small_resp; size_t len = small_len;
    if (strstr(buf, " /large")) { resp = large_resp; len = large_len; }
    else if (strstr(buf, " /chunked")) { resp = chunked_resp; len = chunked_len; }
    size_t consumed = head + body;
    if (have >= consumed) {
      memmove(buf, buf + consumed, have - consumed);
      have -= consumed;
    } else {                           /* discard the rest of a request body */
      size_t left = consumed - have;
      have = 0;
      while (left > 0) {
        ssize_t r = recv(fd, buf, left < sizeof buf ? left : sizeof buf, 0);
        if (r <= 0) goto out;
        left -= (size_t)r;
      }
    }
    if (write_all(fd, resp, len)) break;
  }
out:
  close(fd);
  return NULL;
}

int main(int argc, char **argv) {
  int port = argc > 1 ? atoi(argv[1]) : 9180;
  small_resp = fixed_response(SMALL_LEN, &small_len);
  large_resp = fixed_response(LARGE_LEN, &large_len);
  chunked_resp = chunked_response(&chunked_len);
  int ls = socket(AF_INET, SOCK_STREAM, 0), yes = 1;
  setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
  struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(ls, (struct sockaddr *)&a, sizeof a) || listen(ls, 64)) { perror("listen"); return 1; }
  for (;;) {
    int fd = accept(ls, NULL, NULL);
    if (fd < 0) continue;
    pthread_t t;
    pthread_create(&t, NULL, serve, (void *)(intptr_t)fd);
    pthread_detach(t);
  }
}
