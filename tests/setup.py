#!/usr/bin/env python3
"""Exercise native script entry points, including paths with spaces and validation."""
import os
from pathlib import Path
import subprocess
import tempfile

from https import script


def run(name, *args, ok=True):
    result = subprocess.run([script(name), *map(str, args)], capture_output=True)
    assert (result.returncode == 0) == ok, (name, result.stdout, result.stderr)


def main():
    with tempfile.TemporaryDirectory(prefix='qkd setup ') as temp:
        root = Path(temp)
        pki = root / 'pki with spaces'
        run('gen-certs', pki, 'localhost', '127.0.0.1', '::1')
        original = {p.name: p.read_bytes() for p in pki.iterdir()}
        run('gen-certs', pki, 'localhost', ok=False)
        assert original == {p.name: p.read_bytes() for p in pki.iterdir()}
        run('gen-certs', pki, 'localhost', '--force')
        assert original['ca.crt'] != (pki / 'ca.crt').read_bytes()
        run('gen-client-cert', pki, 'client-a', 'urn:qkd:sae:A')
        cert = (pki / 'client-a.crt').read_bytes()
        run('gen-client-cert', pki, 'client-a', ok=False)
        assert cert == (pki / 'client-a.crt').read_bytes()
        run('gen-client-cert', pki, '../escape', ok=False)
        run('gen-client-cert', pki, 'bad-uri', 'urn:qkd:A,DNS:injected', ok=False)
        run('gen-certs', root / 'invalid', 'bad,host', ok=False)
        assert not (root / 'invalid').exists()
        secret = pki / 'shared.psk'
        run('gen-psk', secret)
        before = secret.read_bytes()
        assert len(before) == 32
        run('gen-psk', secret, ok=False)
        assert secret.read_bytes() == before
        if os.name != 'nt':
            for name in ['ca.key', 'server.key', 'client-a.key', 'shared.psk']:
                assert (pki / name).stat().st_mode & 0o077 == 0
    print('PASS: setup scripts, paths with spaces, overwrite protection, input validation, PSK generation')


if __name__ == '__main__':
    main()
