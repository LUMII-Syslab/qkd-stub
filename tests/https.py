#!/usr/bin/env python3
"""Process-level HTTPS checks. Run after cargo build: python3 tests/https.py."""
import base64
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("QKD_STUB_BIN", ROOT / "target/debug/qkd-stub"))


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fetch(port, path, context, data=None):
    req = urllib.request.Request(
        f"https://127.0.0.1:{port}/api/v1/keys/{path}",
        data=None if data is None else json.dumps(data).encode(),
        headers={} if data is None else {"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, context=context, timeout=3) as response:
        return json.load(response)


def start(port, pki, log, context, psk):
    proc = subprocess.Popen(
        [str(BINARY), "--listen", f"127.0.0.1:{port}", "--tls-cert", str(pki / "server.crt"),
         "--tls-key", str(pki / "server.key"), "--no-sae-binding"] + ["--psk-file", str(psk)], stdout=log, stderr=log)
    for _ in range(100):
        if proc.poll() is not None:
            raise AssertionError(f"Server exited with {proc.returncode}")
        try:
            fetch(port, "B/status", context)
            return proc
        except (urllib.error.URLError, OSError):
            time.sleep(0.05)
    stop(proc)
    raise AssertionError("Server did not become ready")


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=7)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise AssertionError("Server did not shut down gracefully")
    assert proc.returncode == 0, proc.returncode


def main():
    procs = []
    with tempfile.TemporaryDirectory(prefix="qkd-stub-https-") as temp:
        pki = Path(temp) / "pki"
        subprocess.run([str(ROOT / "scripts/gen-certs.sh"), str(pki), "localhost", "127.0.0.1", "::1"], check=True)
        # Refusing an overwrite must preserve all generated files.
        original = {p.name: p.read_bytes() for p in pki.iterdir()}
        result = subprocess.run([str(ROOT / "scripts/gen-certs.sh"), str(pki), "localhost"], capture_output=True)
        assert result.returncode != 0
        assert original == {p.name: p.read_bytes() for p in pki.iterdir()}
        psk = Path(temp) / "shared.psk"
        psk.write_bytes(os.urandom(32))
        trusted = ssl.create_default_context(cafile=str(pki / "ca.crt"))
        a, b = free_port(), free_port()
        while b == a:
            b = free_port()
        with open(Path(temp) / "server.log", "w+") as log:
            try:
                procs.append(start(a, pki, log, trusted, psk))
                procs.append(start(b, pki, log, trusted, psk))
                subprocess.run([str(ROOT / "scripts/smoke-test.sh"), str(pki / "ca.crt"),
                                f"https://127.0.0.1:{a}", f"https://127.0.0.1:{b}"], check=True)
                issued = fetch(a, "B/enc_keys?number=3&size=1024", trusted)
                ids = {"key_IDs": [{"key_ID": k["key_ID"]} for k in issued["keys"]]}
                assert fetch(b, "A/dec_keys", trusted, ids) == issued
                stop(procs.pop())
                procs.append(start(b, pki, log, trusted, psk))
                assert fetch(b, "unrelated-SAE/dec_keys", trusted, ids) == issued
                for key in issued["keys"]:
                    assert len(base64.b64decode(key["key"], validate=True)) == 128
                for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                    ctx = ssl.create_default_context(cafile=str(pki / "ca.crt"))
                    ctx.minimum_version = ctx.maximum_version = version
                    assert fetch(a, "B/status", ctx)["key_size"] == 256
                try:
                    fetch(a, "B/status", ssl.create_default_context())
                except urllib.error.URLError as exc:
                    assert isinstance(exc.reason, ssl.SSLCertVerificationError), exc
                else:
                    raise AssertionError("Untrusted certificate accepted")
                # Invalid TLS paths fail at startup, before serving requests.
                bad = subprocess.run([str(BINARY), "--tls-cert", str(pki / "missing.crt"),
                                      "--tls-key", str(pki / "server.key"), "--psk-file", str(psk), "--no-sae-binding"], capture_output=True, timeout=5)
                assert bad.returncode != 0 and b"cannot load TLS" in bad.stderr
                print("PASS: restart retrieval, TLS 1.2/1.3, untrusted certificate rejection, invalid TLS configuration")
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read())
                raise
            finally:
                for proc in procs:
                    stop(proc)
    print("PASS: graceful shutdown and certificate overwrite protection")


if __name__ == "__main__":
    main()
