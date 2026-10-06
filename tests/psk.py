#!/usr/bin/env python3
"""PSK derivation checked independently over HTTPS, with and without SAE auth."""
import base64
import hmac
import secrets
import subprocess
import tempfile
import uuid
from pathlib import Path

import https
import mtls
from https import BINARY, ROOT, free_port, stop
from mtls import context, fetch


def expand(psk, domain, data, size):
    prk = hmac.digest(b'qkd-stub:psk\0', psk, 'sha512')
    info = domain + data
    output, previous = b'', b''
    for i in range(1, (size + 63) // 64 + 1):
        previous = hmac.digest(prk, previous + info + bytes([i]), 'sha512')
        output += previous
    return output[:size]


def check(psk, raw):
    return expand(psk, b'qkd-stub:id-check:v6\0', raw[:15], 1)[0]


def expected(psk, key_id):
    raw = uuid.UUID(key_id).bytes
    size = int.from_bytes(raw[:2], 'big')
    return base64.b64encode(expand(psk, b'qkd-stub:key:v6\0', raw, size)).decode()


def main():
    with tempfile.TemporaryDirectory(prefix='qkd-stub-psk-') as temp:
        root = Path(temp)
        pki = root / 'pki'
        subprocess.run([str(ROOT / 'scripts/gen-certs.sh'), str(pki), 'localhost', '127.0.0.1'], check=True)
        for name, uri in [('client-a', None), ('client-b', 'urn:qkd:sae:B')]:
            subprocess.run([str(ROOT / 'scripts/gen-client-cert.sh'), str(pki), name]
                           + ([uri] if uri else []), check=True)
        secret = secrets.token_bytes(32)
        psk = root / 'shared.psk'
        psk.write_bytes(secret)
        psk.chmod(0o600)
        wrong = root / 'wrong.psk'
        wrong.write_bytes(bytes(b ^ 255 for b in secret))
        command = [str(BINARY), '--tls-cert', str(pki / 'server.crt'),
                   '--tls-key', str(pki / 'server.key'), '--no-sae-binding', '--psk-file']
        invalid = root / 'invalid.psk'
        for size in [0, 31, 33, 64]:
            invalid.write_bytes(b'x' * size)
            result = subprocess.run(command + [str(invalid)], capture_output=True, timeout=5)
            assert result.returncode != 0 and b'exactly 32 raw bytes' in result.stderr
        result = subprocess.run(command + [str(root / 'missing')], capture_output=True, timeout=5)
        assert result.returncode != 0 and b'cannot read PSK file' in result.stderr

        for bound in [False, True]:
            ctx_a = context(pki, 'client-a' if bound else None)
            ctx_b = context(pki, 'client-b' if bound else None)
            procs = []
            with (root / 'server.log').open('w+') as log:
                def start(port, path):
                    if bound:
                        return mtls.start(port, pki, ROOT / 'examples/sae-map.toml', log, ctx_a, path)
                    return https.start(port, pki, log, ctx_a, path)

                try:
                    a = free_port()
                    procs.append(start(a, psk))
                    b = free_port()
                    procs.append(start(b, psk))
                    for size in [8, 256, 65536]:
                        for source, target, master, slave, master_ctx, slave_ctx in [
                            (a, b, 'A', 'B', ctx_a, ctx_b), (b, a, 'B', 'A', ctx_b, ctx_a)
                        ]:
                            for body in [None, {'number': 2, 'size': size}]:
                                status, issued = fetch(source, f'{slave}/enc_keys?size={size}', master_ctx, body)
                                assert status == 200
                                for key in issued['keys']:
                                    raw = uuid.UUID(key['key_ID']).bytes
                                    assert int.from_bytes(raw[:2], 'big') == size // 8
                                    assert raw[2:6] == (bytes([0, 1 if master == 'A' else 2, 0, 2 if slave == 'B' else 1]) if bound else bytes(4))
                                    assert raw[15] == check(secret, raw)
                                    assert raw[6] >> 4 == 8 and raw[8] >> 6 == 2
                                    assert key['key'] == expected(secret, key['key_ID'])
                                    assert fetch(target, f'{master}/dec_keys?key_ID={key["key_ID"].upper()}', slave_ctx) == (200, {'keys': [key]})
                                ids = {'key_IDs': [{'key_ID': k['key_ID']} for k in issued['keys']]}
                                assert fetch(target, f'{master}/dec_keys', slave_ctx, ids) == (200, issued)
                    status, issued = fetch(a, 'B/enc_keys', ctx_a)
                    assert status == 200
                    key_id = issued['keys'][0]['key_ID']
                    path = f'A/dec_keys?key_ID={key_id}'
                    damaged = bytearray(uuid.UUID(key_id).bytes)
                    damaged[15] ^= 1
                    mixed = {'key_IDs': [{'key_ID': key_id}, {'key_ID': str(uuid.UUID(bytes=bytes(damaged)))}]}
                    status, error = fetch(b, 'A/dec_keys', ctx_b, mixed)
                    assert status == 400 and 'keys' not in error
                    if bound:
                        assert fetch(b, path, ctx_a, header='B')[0] == 401
                        assert fetch(b, f'C/dec_keys?key_ID={key_id}', ctx_b)[0] == 401
                    # Choose a wrong secret whose check differs, avoiding a flaky 1/256 collision.
                    raw = uuid.UUID(key_id).bytes
                    while check(wrong.read_bytes(), raw) == raw[15]:
                        wrong.write_bytes(secrets.token_bytes(32))
                    # Restart with a wrong secret: fail before returning key material.
                    stop(procs[1])
                    procs[1] = start(b, wrong)
                    status, different = fetch(b, path, ctx_b)
                    assert status == 400 and 'checksum mismatch' in different['message']
                    assert 'keys' not in different
                    stop(procs[1])
                    procs[1] = start(b, psk)
                    assert fetch(b, path, ctx_b) == (200, issued)
                    log.flush()
                    log.seek(0)
                    assert 'PSK-derived keys' in log.read()
                except Exception:
                    log.flush()
                    log.seek(0)
                    print(log.read())
                    raise
                finally:
                    for proc in procs:
                        stop(proc)
            print(f'PASS: PSK HTTPS (SAE={bound}), independent HKDF vectors, full size range, both methods/directions, checksum validation, mismatch and restart')
    print('PASS: invalid and missing PSK files fail at startup')


if __name__ == '__main__':
    main()
