#!/usr/bin/env python3
"""Run the client against a sibling Hashi checkout; never edit that checkout."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=ROOT.parent / "hashi")
    parser.add_argument("--server-compiler", default=os.environ.get("HASHI_NIMONY",
                        os.environ.get("NIMONY", "nimony")))
    parser.add_argument("--compat", action="store_true",
                        help="adapt a temporary copy for Nimony 0.6.3 synchronization checking")
    args = parser.parse_args()
    compiler = os.environ.get("NIMONY", "nimony")
    with tempfile.TemporaryDirectory(prefix="tsuru-hashi-") as tmp:
        tmp = Path(tmp)
        source = args.source.resolve()
        if args.compat:
            target = tmp / "hashi"
            shutil.copytree(source / "src", target / "src")
            shutil.copytree(source / "examples", target / "examples")
            for module in (target / "src").rglob("*.nim"):
                module.write_text('{.feature: "assumeSync".}\n' + module.read_text())
            module = target / "src/hashi/net.nim"
            text = module.read_text()
            text = text.replace('var errno {.importc: "errno", header: "<errno.h>".}: cint',
                                'from std/posix/posix import errno')
            text = text.replace("result.err = errno", "result.err = errno()")
            text = text.replace("let e = errno", "let e = errno()")
            module.write_text(text)
            source = target
        server_bin, client_bin = tmp / "server", tmp / "client"
        subprocess.run([args.server_compiler, "c", f"--path:{source / 'src'}",
                        f"--nimcache:{tmp / 'server-cache'}", f"-o:{server_bin}",
                        str(source / "examples/ws_echo.nim")], cwd=ROOT, check=True)
        subprocess.run([compiler, "c", f"--nimcache:{tmp / 'client-cache'}", f"-o:{client_bin}",
                        "tests/client.nim"], cwd=ROOT, check=True)
        with tempfile.TemporaryFile() as log:
            server = subprocess.Popen([str(server_bin)], cwd=ROOT, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                ready = False
                while time.monotonic() < deadline and server.poll() is None:
                    try:
                        with socket.create_connection(("127.0.0.1", 8080), timeout=0.1):
                            ready = True
                            break
                    except OSError:
                        time.sleep(0.02)
                if not ready:
                    log.seek(0)
                    raise RuntimeError(log.read().decode())
                subprocess.run([str(client_bin), "ws://127.0.0.1:8080/", "hashi"],
                               cwd=ROOT, check=True, timeout=15)
                assert server.poll() is None, "Hashi exited during round trips"
                print("Hashi interoperability passed" + (" (temporary compatibility copy)" if args.compat else ""))
            finally:
                if server.poll() is None:
                    server.terminate()
                server.wait(timeout=5)


if __name__ == "__main__":
    main()
