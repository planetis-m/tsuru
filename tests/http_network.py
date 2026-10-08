#!/usr/bin/env python3
"""HTTP wire fixtures, independent of Tsuru's encoder and parser."""
import argparse
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def read_request(peer):
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        byte = peer.recv(1)
        assert byte, "request head ended early"
        head += byte
        assert len(head) <= 16384
    lines = head.decode().split("\r\n")
    headers = dict(line.split(": ", 1) for line in lines[1:] if line)
    assert headers["Host"] and headers["Accept-Encoding"] == "identity"
    n = int(headers["Content-Length"])
    body = bytearray()
    while len(body) < n:
        data = peer.recv(min(65536, n - len(body)))
        assert data, "request body ended early"
        body += data
    return lines[0], headers, bytes(body)


def fixed(peer, body, *, status=200, fields=b"", version=b"1.1"):
    peer.sendall(b"HTTP/" + version + b" " + str(status).encode() + b" OK\r\nContent-Length: " +
                 str(len(body)).encode() + b"\r\n" + fields + b"\r\n" + body)


def fixture(peer, mode):
    if mode in ("abort", "expired-request", "warmup"):
        assert peer.recv(1) == b""
        return
    line, headers, body = read_request(peer)
    assert line.endswith(" /chat?q=%20 HTTP/1.1")
    if mode == "large":
        assert line.startswith("POST ") and body == b"x\0\xff" * (7 * 1024 * 1024)
        fixed(peer, body)
    elif mode == "no-body":
        assert line.startswith("HEAD ")
        peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n")
        read_request(peer)
        peer.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
        read_request(peer)
        peer.sendall(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 999999999\r\n\r\n")
        read_request(peer)
        fixed(peer, b"missing", status=404, fields=b"Connection: close\r\n")
    elif mode in ("keepalive", "chunked", "http10", "unread-body"):
        assert headers["X-Trace"] == "id"
        if mode == "chunked":
            wire = (b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n"
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n"
                    b"3;id=1\r\nhel\r\n4\r\nlo\0\xff\r\n0\r\nX-Trailer: done\r\nContent-Length: 999\r\n\r\n")
            for byte in wire:
                peer.sendall(bytes([byte]))
        elif mode == "http10":
            fixed(peer, b"hello", version=b"1.0", fields=b"Connection: keep-alive\r\n")
        else:
            fixed(peer, b"hello", fields=b"Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n")
        second, _, body = read_request(peer)
        assert second == "POST /second HTTP/1.1" and body == b"payload"
        fixed(peer, b"second", status=201, fields=b"Connection: close\r\n",
              version=b"1.0" if mode == "http10" else b"1.1")
    elif mode == "eof":
        peer.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbye")
        peer.shutdown(socket.SHUT_WR)
    elif mode == "slow-head":
        peer.sendall(b"HTTP/1.1 200")
        time.sleep(0.25)
    elif mode == "slow-body":
        peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na")
        time.sleep(0.25)
    elif mode == "truncated":
        peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ncut")
        peer.shutdown(socket.SHUT_WR)
    elif mode == "malformed":
        peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n")
    elif mode == "bad-chunk":
        peer.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nQ\r\n")
    elif mode == "bad-trailer":
        peer.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n folded: bad\r\n\r\n")
    elif mode == "too-large":
        fixed(peer, b"12345")
    elif mode == "chunk-limit":
        peer.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n")
    elif mode == "eof-limit":
        peer.sendall(b"HTTP/1.1 200 OK\r\n\r\n12345")
    elif mode == "huge-head":
        try:
            peer.sendall(b"HTTP/1.1 200 OK\r\nX: " + b"x" * 17000)
        except (BrokenPipeError, ConnectionResetError):
            pass
    elif mode == "upgrade":
        peer.sendall(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
    else:
        raise AssertionError(mode)
    assert peer.recv(1) == b"", "HTTP terminal/explicit close must release the socket"


def run_case(binary, mode, *, tls=None, ca="", hostname=None, ipv6=False):
    errors = []
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET) as listener:
        listener.bind(("::1" if ipv6 else "127.0.0.1", 0))
        listener.listen()
        listener.settimeout(10)
        port = listener.getsockname()[1]

        def server():
            try:
                modes = ("warmup",) + ("keepalive", "chunked", "malformed", "truncated", "slow-body", "abort", "expired-request", "too-large") * 2 if mode == "resources" else (mode,)
                for path in modes:
                    with listener.accept()[0] as sock:
                        sock.settimeout(10)
                        if tls:
                            try:
                                sock = tls.wrap_socket(sock, server_side=True)
                            except (ssl.SSLError, ConnectionResetError):
                                if path == "tls-reject": return
                                raise
                        with sock:
                            fixture(sock, path)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        host = hostname or ("[::1]" if ipv6 else "127.0.0.1")
        scheme = "https" if tls else "http"
        result = subprocess.run([str(binary), f"{scheme}://{host}:{port}/chat?q=%20", mode, ca],
                                capture_output=True, text=True, timeout=30)
        thread.join(11)
        assert not thread.is_alive(), "HTTP fixture did not finish"
        assert result.returncode == 0, result.stdout + result.stderr
        assert not errors, repr(errors)
    print(f"PASS {scheme} {mode}" + (" IPv6" if ipv6 else ""), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--tls", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve()
    for mode in ("keepalive", "chunked", "http10", "unread-body", "no-body", "eof", "large",
                 "slow-head", "slow-body", "truncated", "malformed", "bad-chunk", "bad-trailer",
                 "too-large", "chunk-limit", "eof-limit", "huge-head", "upgrade", "abort", "expired-request", "resources"):
        run_case(binary, mode)
    run_case(binary, "keepalive", ipv6=True)
    run_case(binary, "keepalive", hostname="localhost")
    subprocess.run([str(binary), "http://127.0.0.1:1/", "expired-connect"], check=True, timeout=10)
    if args.tls:
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                            "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext",
                            "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            names = []
            context.set_servername_callback(lambda peer, name, ctx: names.append(name))
            run_case(binary, "keepalive", tls=context, ca=str(cert), hostname="localhost")
            assert names[-1] == "localhost"
            for mode in ("chunked", "large", "slow-head", "slow-body", "truncated"):
                run_case(binary, mode, tls=context, ca=str(cert))
            run_case(binary, "tls-reject", tls=context)
            run_case(binary, "tls-reject", tls=context, ca=str(cert), hostname="wrong.localhost")
    else:
        subprocess.run([str(binary), "https://127.0.0.1:1/", "no-tls"], check=True, timeout=10)
    print("HTTP network tests passed", flush=True)


if __name__ == "__main__":
    main()
