#!/usr/bin/env python3
"""Independent RFC wire fixtures; stdlib only. No external network access."""
import argparse
import base64
import hashlib
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def exact(sock, n):
    data = b""
    while len(data) < n:
        more = sock.recv(n - len(data))
        if not more:
            raise AssertionError("unexpected EOF")
        data += more
    return data


def read_frame(sock):
    a, b = exact(sock, 2)
    assert a & 0x70 == 0 and b & 0x80, "client frames must be masked"
    size = b & 127
    if size == 126:
        size = struct.unpack("!H", exact(sock, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", exact(sock, 8))[0]
    assert size <= 32 * 1024 * 1024
    mask = exact(sock, 4)
    payload = exact(sock, size)
    return a & 15, bytes(c ^ mask[i % 4] for i, c in enumerate(payload))


def frame(op, data=b"", fin=True):
    head = bytes([op | (128 if fin else 0)])
    n = len(data)
    if n < 126:
        head += bytes([n])
    elif n <= 65535:
        head += b"\x7e" + struct.pack("!H", n)
    else:
        head += b"\x7f" + struct.pack("!Q", n)
    return head + data


def handshake(sock, *, suffix=b"", bad=False, protocols=False):
    request = b""
    while not request.endswith(b"\r\n\r\n"):
        request += exact(sock, 1)
        assert len(request) <= 16384
    lines = request.decode().split("\r\n")
    headers = dict(line.split(": ", 1) for line in lines[1:] if line)
    assert lines[0] == "GET /chat?q=1 HTTP/1.1"
    assert len(base64.b64decode(headers["Sec-WebSocket-Key"], validate=True)) == 16
    assert headers["Sec-WebSocket-Version"] == "13"
    accept = base64.b64encode(hashlib.sha1((headers["Sec-WebSocket-Key"] + GUID).encode()).digest())
    if bad:
        accept = b"wrong"
    reply = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    reply += b"Sec-WebSocket-Accept: " + accept + b"\r\n"
    if protocols:
        assert headers["Sec-WebSocket-Protocol"] == "chat, other"
        assert headers["Origin"] == "https://example.com"
        assert headers["Authorization"] == "Bearer test"
        reply += b"Sec-WebSocket-Protocol: chat\r\n"
    sock.sendall(reply + b"\r\n" + suffix)


def echo(sock):
    handshake(sock)
    while True:
        op, data = read_frame(sock)
        sock.sendall(frame(10 if op == 9 else op, data))
        if op == 8:
            assert sock.recv(1) == b""
            return


def fixture(sock, mode, wire=None, code=1002):
    if mode == "handshake-timeout":
        time.sleep(0.5)
        return
    if mode == "echo":
        echo(sock)
        return
    if mode == "drop":
        handshake(sock)
        assert read_frame(sock) == (1, b"drop without explicit close")
        assert sock.recv(1) == b"", "dropping the last handle must release its socket"
        return
    if mode == "bad-upgrade":
        handshake(sock, bad=True)
        assert sock.recv(1) == b""
        return
    if mode == "fragments":
        # Upgrade and first fragment in the same TCP write; split UTF-8 across frames.
        handshake(sock, suffix=frame(1, b"\xc3", False) + frame(9, b"probe"))
        assert read_frame(sock) == (10, b"probe")
        wire = frame(0, b"\xa9!", True) + frame(8, struct.pack("!H", 1001) + b"bye")
        for b in wire:
            sock.sendall(bytes([b]))
        assert read_frame(sock) == (8, struct.pack("!H", 1001) + b"bye")
        return
    if mode == "empty-close":
        handshake(sock, suffix=frame(8))
        assert read_frame(sock) == (8, b"")
        return
    if mode == "eof":
        handshake(sock, suffix=b"\x81\x08trunc")
        return
    if mode == "protocols":
        handshake(sock, protocols=True, suffix=frame(1, b"ready") + frame(2, b"\x00\xff"))
        op, data = read_frame(sock)
        assert op == 8
        sock.sendall(frame(8, data))
        assert sock.recv(1) == b""
        return
    if mode in ("close-handshake", "close-inflight", "close-abort",
                "close-timeout", "close-eof", "close-protocol-error"):
        handshake(sock)
        assert read_frame(sock) == (8, struct.pack("!H", 1000) + b"done")
        if mode == "close-handshake":
            sock.sendall(frame(1, b"ignored") + frame(9, b"probe"))
            assert read_frame(sock) == (10, b"probe")
            sock.sendall(frame(8, struct.pack("!H", 1001) + b"bye"))
        elif mode == "close-inflight":
            sock.sendall(frame(1, b"\xc3", False) + frame(9, b"probe"))
            assert read_frame(sock) == (10, b"probe")
            sock.sendall(frame(0, b"\xa9!") + frame(2, b"\0\xff")
                         + frame(8, struct.pack("!H", 1001) + b"bye"))
        elif mode == "close-abort":
            assert sock.recv(1) == b""
            return
        elif mode == "close-protocol-error":
            sock.sendall(b"\x81\x80")
        elif mode == "close-eof":
            return
        else:
            time.sleep(0.7)
        assert sock.recv(1) == b"", "close must release without sending a second close frame"
        return
    if mode in ("read-timeout", "write-timeout"):
        handshake(sock)
        time.sleep(0.7)
        return
    handshake(sock, suffix=wire)
    op, body = read_frame(sock)
    assert op == 8 and body[:2] == struct.pack("!H", code), (op, body)
    assert sock.recv(1) == b""


def run_case(binary, mode, *, wire=None, code=1002, tls=None, ca="", ipv6=False, hostname=None):
    errors = []
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    with socket.socket(family) as listener:
        listener.bind(("::1" if ipv6 else "127.0.0.1", 0))
        listener.listen()
        listener.settimeout(10)
        port = listener.getsockname()[1]

        def server():
            try:
                with listener.accept()[0] as peer:
                    peer.settimeout(10)
                    if tls:
                        try:
                            peer = tls.wrap_socket(peer, server_side=True)
                        except (ssl.SSLError, ConnectionResetError):
                            if mode in ("tls-reject", "no-tls"):
                                return
                            raise
                    with peer:
                        fixture(peer, mode, wire, code)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=server, daemon=True)
        thread.start()
        host = hostname or ("[::1]" if ipv6 else "127.0.0.1")
        scheme = "wss" if tls else "ws"
        result = subprocess.run([str(binary), f"{scheme}://{host}:{port}/chat?q=1", mode, ca],
                                capture_output=True, text=True, timeout=15)
        thread.join(11)
        assert not thread.is_alive(), "fixture thread did not finish"
        assert result.returncode == 0, result.stdout + result.stderr
        assert not errors, repr(errors)
    print(f"PASS {scheme} {mode}" + (" IPv6" if ipv6 else ""), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--tls", action="store_true")
    args = parser.parse_args()
    binary = args.binary.resolve()
    for mode in ("echo", "drop", "fragments", "empty-close", "eof", "protocols",
                 "bad-upgrade", "handshake-timeout", "read-timeout", "write-timeout",
                 "close-handshake", "close-inflight", "close-abort",
                 "close-timeout", "close-eof", "close-protocol-error"):
        run_case(binary, mode)
    for wire, code in [(b"\x81\x80", 1002), (frame(1, b"\xff"), 1007),
                       (frame(0, b"orphan"), 1002), (frame(8, b"x"), 1002),
                       (frame(8, struct.pack("!H", 1005)), 1002),
                       (b"\x82\x7e\x00\x01x", 1002), (b"\xc1\x00", 1002)]:
        run_case(binary, "protocol-error", wire=wire, code=code)
    run_case(binary, "too-large", wire=frame(2, b"12345"), code=1009)
    run_case(binary, "echo", ipv6=True)
    run_case(binary, "echo", hostname="localhost")
    if args.tls:
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=localhost", "-addext",
                            "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                           check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server_names = []
            context.set_servername_callback(lambda peer, name, ctx: server_names.append(name))
            run_case(binary, "echo", tls=context, ca=str(cert))
            run_case(binary, "echo", tls=context, ca=str(cert), hostname="localhost")
            assert server_names[-1] == "localhost", "DNS connections must send SNI"
            run_case(binary, "write-timeout", tls=context, ca=str(cert))
            run_case(binary, "tls-reject", tls=context)
            run_case(binary, "tls-reject", tls=context, ca=str(cert), hostname="wrong.localhost")
    else:
        subprocess.run([str(binary), "wss://127.0.0.1:1/", "no-tls"], check=True, timeout=10)
    print("network tests passed", flush=True)


if __name__ == "__main__":
    main()
