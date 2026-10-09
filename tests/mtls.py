#!/usr/bin/env python3
"""Real mTLS/SAE authorization tests: cargo build && python3 tests/mtls.py."""
import concurrent.futures
import http.client
import json
import socket
import ssl
import subprocess
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
import common
from common import ROOT, BINARY, free_port, script, stop


def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True)


def client(pki, name, subject, san=None, days=1):
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', subject,
            '-keyout', pki / f'{name}.key', '-out', pki / f'{name}.csr')
    ext = pki / f'{name}.ext'
    ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n'
                   + (f'subjectAltName={san}\n' if san else ''))
    openssl('x509', '-req', '-in', pki / f'{name}.csr', '-CA', pki / 'ca.crt', '-CAkey', pki / 'ca.key',
            '-set_serial', '0x'+__import__('secrets').token_hex(16), '-days', str(days), '-sha256',
            '-extfile', ext, '-out', pki / f'{name}.crt')


def context(pki, name=None, identity_dir=None):
    ctx = ssl.create_default_context(cafile=str(pki / 'ca.crt'))
    if name:
        identity_dir = identity_dir or pki
        ctx.load_cert_chain(identity_dir / f'{name}.crt', identity_dir / f'{name}.key')
    return ctx


def fetch(port, path, ctx, body=None, header=None):
    headers = {'Content-Type': 'application/json'}
    if header:
        headers['Request-SAE-ID'] = header
    req = urllib.request.Request(f'https://127.0.0.1:{port}/api/v1/keys/{path}',
                                 data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)


def start(port, pki, mapping, log, ctx, psk):
    return common.start(port, pki, mapping, log, ctx, psk, fetch)


def main():
    procs = []
    with tempfile.TemporaryDirectory(prefix='qkd-stub-mtls-') as tmp:
        root = Path(tmp)
        psk = root / 'shared.psk'
        psk.write_bytes(bytes([7]) * 32)
        pki = root / 'pki'
        subprocess.run([script('gen-certs'), str(pki), 'localhost', '127.0.0.1'], check=True)
        for name, uri in [('client-a', None), ('client-b', 'urn:qkd:sae:B'), ('client-c', None), ('client-d', 'urn:qkd:sae:D')]:
            subprocess.run([script('gen-client-cert'), str(pki), name] + ([uri] if uri else []), check=True)
        cert_before = (pki / 'client-a.crt').read_bytes()
        assert subprocess.run([script('gen-client-cert'), str(pki), 'client-a'], capture_output=True).returncode != 0
        assert cert_before == (pki / 'client-a.crt').read_bytes()
        client(pki, 'unmapped', '/CN=unknown')
        client(pki, 'ambiguous', '/CN=client-a', 'URI:urn:qkd:sae:D')
        client(pki, 'dns', '/CN=dns', 'DNS:SAE-E.Example')
        client(pki, 'ip', '/CN=ip', 'IP:2001:db8::1')
        client(pki, 'email', '/CN=email', 'email:sae-g@example.test')
        client(pki, 'escaped', '/O=Example/CN=client-a,OU=Other')
        client(pki, 'expired', '/CN=client-a', days=0)
        # Certificate validity has second precision; leave its issuance second.
        time.sleep(1.1)
        mapping = (ROOT / 'examples/sae-map.toml').read_text()
        assert len(tomllib.loads(mapping)['sae']) == 4
        for i, name, field, value in [(5,'E','san_dns','sae-e.example'), (6,'F','san_ip','2001:0db8:0:0::1'), (7,'G','san_email','sae-g@example.test')]:
            mapping += f'\n[[sae]]\nid = "{name}"\ncode = {i}\nidentities = [{{ {field} = "{value}" }}]\n'
        for name, expected in [('client-a', {'subject_dn':'CN=client-a'}),
                               ('client-b', {'san_uri':'urn:qkd:sae:B'}),
                               ('escaped', {'subject_dn':r'CN=client-a\,OU\=Other,O=Example'})]:
            result = subprocess.run([str(BINARY), 'cert', 'inspect', str(pki / f'{name}.crt')], check=True, capture_output=True)
            selectors = [tomllib.loads('s = ' + line.split(': ', 1)[1])['s']
                         for line in result.stdout.decode().splitlines() if line.startswith('  Selector ')]
            assert expected in selectors, result.stdout
        map_path = root / 'saes.toml'
        map_path.write_text(mapping)
        contexts = {name: context(pki, cert) for name, cert in [('A','client-a'), ('B','client-b'), ('C','client-c'), ('D','client-d'), ('E','dns'), ('F','ip'), ('G','email')]}
        untrusted = root / 'other-pki'
        subprocess.run([script('gen-certs'), str(untrusted), 'localhost'], check=True)
        subprocess.run([script('gen-client-cert'), str(untrusted), 'client-a'], check=True)
        a, b = free_port(), free_port()
        while b == a:
            b = free_port()
        with (root / 'server.log').open('w+') as log:
            try:
                procs.append(start(a, pki, map_path, log, contexts['A'], psk))
                procs.append(start(b, pki, map_path, log, contexts['A'], psk))
                for name, ctx in contexts.items():
                    status, data = fetch(a, 'B/status', ctx, header='forged')
                    assert status == 200 and data['master_SAE_ID'] == name, (name, status, data)
                for name in ['unmapped', 'ambiguous', 'escaped']:
                    assert fetch(a, 'B/enc_keys', context(pki, name), header='A')[0] == 401
                for ctx in [context(pki), context(pki,'client-a',untrusted), context(pki,'server'), context(pki,'expired')]:
                    try:
                        result = fetch(a, 'B/status', ctx, header='A')
                    except (ssl.SSLError, urllib.error.URLError, http.client.RemoteDisconnected, ConnectionResetError):
                        pass
                    else:
                        raise AssertionError(f'Invalid client passed TLS handshake: {result}')
                keys = {}
                for master, slave in [('A','B'), ('C','D')]:
                    status, issued = fetch(a, f'{slave}/enc_keys', contexts[master], {'number':3, 'size':512})
                    assert status == 200
                    ids = {'key_IDs':[{'key_ID':k['key_ID']} for k in issued['keys']]}
                    assert fetch(b, f'{master}/dec_keys', contexts[slave], ids) == (200, issued)
                    keys[master] = issued
                id_ab = keys['A']['keys'][0]['key_ID']
                assert fetch(b, f'A/dec_keys?key_ID={id_ab}', contexts['D'], header='B')[0] == 401
                assert fetch(b, f'C/dec_keys?key_ID={id_ab}', contexts['B'])[0] == 401
                assert fetch(b, f'A/dec_keys?key_ID={id_ab}', contexts['A'])[0] == 401
                mixed = {'key_IDs':[{'key_ID':id_ab}, {'key_ID':keys['C']['keys'][0]['key_ID']}]}
                status, data = fetch(b, 'A/dec_keys', contexts['B'], mixed)
                assert status == 401 and 'keys' not in data
                old = '00200000-0000-8678-9abc-def012345679'
                assert fetch(b, f'A/dec_keys?key_ID={old}', contexts['B'])[0] == 400
                stop(procs.pop())
                procs.append(start(b, pki, map_path, log, contexts['A'], psk))
                assert fetch(b, f'A/dec_keys?key_ID={id_ab}', contexts['B'])[1]['keys'][0] == keys['A']['keys'][0]
                # Multiple pairs in flight on the same two processes, both directions.
                def roundtrip(pair):
                    master, slave = pair
                    status, issued = fetch(b, f'{slave}/enc_keys?size=256', contexts[master])
                    assert status == 200
                    key_id = issued['keys'][0]['key_ID']
                    assert fetch(a, f'{master}/dec_keys?key_ID={key_id}', contexts[slave]) == (200, issued)
                    return key_id
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    ids = list(pool.map(roundtrip, [('A','B'),('C','D'),('B','A'),('D','C')] * 4))
                    assert len(set(ids)) == len(ids)
                for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                    ctx = context(pki,'client-a')
                    ctx.minimum_version = ctx.maximum_version = version
                    assert fetch(a, 'B/status', ctx)[0] == 200
                print('PASS: certificate mapping (DN/all supported SAN types), mTLS validation, ambiguous/unmapped rejection')
                print('PASS: concurrent independent SAE pairs, recipient/master enforcement, spoofed header rejection, restart recovery')
            except Exception:
                log.flush()
                log.seek(0)
                print(log.read())
                raise
            finally:
                for proc in procs:
                    stop(proc)
        print('PASS: client certificate overwrite protection')


if __name__ == '__main__':
    main()
