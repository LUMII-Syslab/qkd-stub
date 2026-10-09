#!/usr/bin/env python3
"""Process-level HTTPS checks. Run after cargo build: python3 tests/https.py."""
import base64
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import urllib.error

from common import BINARY, ROOT, free_port, script, stop, write_config
from mtls import context, fetch, start

MAPPING = ROOT / "examples/sae-map.toml"


def main():
    procs = []
    with tempfile.TemporaryDirectory(prefix="qkd-stub-https-") as temp:
        pki = Path(temp) / "pki"
        subprocess.run([script("gen-certs"), str(pki), "localhost", "127.0.0.1", "::1"], check=True)
        subprocess.run([script("gen-client-cert"), str(pki), "client-a"], check=True)
        subprocess.run([script("gen-client-cert"), str(pki), "client-b", "urn:qkd:sae:B"], check=True)
        # Refusing an overwrite must preserve all generated files.
        original = {p.name: p.read_bytes() for p in pki.iterdir()}
        result = subprocess.run([script("gen-certs"), str(pki), "localhost"], capture_output=True)
        assert result.returncode != 0
        assert original == {p.name: p.read_bytes() for p in pki.iterdir()}
        psk = Path(temp) / "shared.psk"
        psk.write_bytes(os.urandom(32))
        ctx_a, ctx_b = context(pki, "client-a"), context(pki, "client-b")
        a, b = free_port(), free_port()
        while b == a:
            b = free_port()
        with open(Path(temp) / "server.log", "w+") as log:
            try:
                procs.append(start(a, pki, MAPPING, log, ctx_a, psk))
                procs.append(start(b, pki, MAPPING, log, ctx_b, psk))
                status, issued = fetch(a, "B/enc_keys?number=3&size=1024", ctx_a)
                assert status == 200
                ids = {"key_IDs": [{"key_ID": k["key_ID"]} for k in issued["keys"]]}
                assert fetch(b, "A/dec_keys", ctx_b, ids) == (200, issued)
                stop(procs.pop())
                procs.append(start(b, pki, MAPPING, log, ctx_b, psk))
                assert fetch(b, "A/dec_keys", ctx_b, ids) == (200, issued)
                for key in issued["keys"]:
                    assert len(base64.b64decode(key["key"], validate=True)) == 128
                for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                    ctx = context(pki, "client-a")
                    ctx.minimum_version = ctx.maximum_version = version
                    status, data = fetch(a, "B/status", ctx)
                    assert status == 200 and data["key_size"] == 256
                try:
                    fetch(a, "B/status", ssl.create_default_context())
                except urllib.error.URLError as exc:
                    assert isinstance(exc.reason, ssl.SSLCertVerificationError), exc
                else:
                    raise AssertionError("Untrusted certificate accepted")
                # Invalid TLS paths fail at startup, before serving requests.
                bad_pki = Path(temp) / "missing-pki"
                bad_pki.mkdir()
                for name in ("server.key", "ca.crt"):
                    (bad_pki / name).write_bytes((pki / name).read_bytes())
                config = write_config(Path(temp) / "bad.toml", free_port(), bad_pki, MAPPING, psk)
                bad = subprocess.run([str(BINARY), "--config", str(config), "serve"], capture_output=True, timeout=5)
                assert bad.returncode != 0 and b"MISSING/INVALID  server certificate" in bad.stdout
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
