#!/usr/bin/env python3
"""Test PKI and PSK generation shared by the .sh and .bat entry points."""
import argparse
import ipaddress
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True)
    if result.returncode:
        raise ValueError(result.stderr.decode(errors='replace'))


def check_outputs(out, names, force=False):
    for name in names:
        path = out / name
        if path.is_dir() or ((path.exists() or path.is_symlink()) and not force):
            raise ValueError(f'Refusing to overwrite {path}')


def host_san(host):
    try:
        return 'IP:' + str(ipaddress.ip_address(host))
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                                      for label in host.split('.')):
            raise ValueError(f'Invalid DNS name or IP address: {host!r}') from None
        return 'DNS:' + host


def server(out, hosts, force):
    sans = ','.join(map(host_san, hosts))
    names = ['ca.crt', 'ca.key', 'server.crt', 'server.key']
    check_outputs(out, names, force)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.gen-certs.', dir=out) as temp:
        tmp = Path(temp)
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '3650',
                '-subj', '/CN=QKD Stub Test CA', '-keyout', tmp / 'ca.key', '-out', tmp / 'ca.crt',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
                '-subj', '/CN=QKD Stub Test Server', '-keyout', tmp / 'server.key', '-out', tmp / 'server.csr')
        ext = tmp / 'server.ext'
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                       f'extendedKeyUsage=serverAuth\nsubjectAltName={sans}\n', encoding='utf-8')
        sign(tmp, tmp, 'server', ext)
        for name in names:
            (tmp / name).replace(out / name)
    print(f'Created CA and server certificate in {out}\nSANs: {sans}')


def sign(ca, tmp, name, ext):
    openssl('x509', '-req', '-in', tmp / f'{name}.csr', '-CA', ca / 'ca.crt', '-CAkey', ca / 'ca.key',
            '-set_serial', '0x' + secrets.token_hex(16), '-days', '365', '-sha256',
            '-extfile', ext, '-out', tmp / f'{name}.crt')


def client(out, name, uri):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', name):
        raise ValueError('NAME must contain only letters, digits, underscores, and hyphens')
    if uri is not None and not re.fullmatch(r'[A-Za-z][A-Za-z0-9+.-]*:[^,\s\x00-\x1f\x7f]+', uri):
        raise ValueError('URI_SAN must be a URI without commas, whitespace, or control characters')
    if not all((out / file).is_file() for file in ['ca.crt', 'ca.key']):
        raise ValueError('Missing ca.crt or ca.key; run gen-certs first')
    check_outputs(out, [f'{name}.crt', f'{name}.key'])
    with tempfile.TemporaryDirectory(prefix='.gen-client.', dir=out) as temp:
        tmp = Path(temp)
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-subj', f'/CN={name}',
                '-keyout', tmp / 'client.key', '-out', tmp / 'client.csr')
        ext = tmp / 'client.ext'
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                       'extendedKeyUsage=clientAuth\n' + (f'subjectAltName=URI:{uri}\n' if uri else ''), encoding='utf-8')
        sign(out, tmp, 'client', ext)
        for suffix in ['key', 'crt']:
            (tmp / f'client.{suffix}').replace(out / f'{name}.{suffix}')
    print(f'Created {name}.crt and {name}.key in {out}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    certs = modes.add_parser('server')
    certs.add_argument('directory', type=Path)
    certs.add_argument('hosts', nargs='+')
    certs.add_argument('--force', action='store_true')
    cert = modes.add_parser('client')
    cert.add_argument('directory', type=Path)
    cert.add_argument('name')
    cert.add_argument('uri', nargs='?')
    psk = modes.add_parser('psk')
    psk.add_argument('path', type=Path)
    args = parser.parse_args()
    # POSIX secrets are owner-only; Windows files inherit directory ACLs.
    if os.name != 'nt':
        os.umask(0o077)
    try:
        if args.mode == 'server':
            server(args.directory, args.hosts, args.force)
        elif args.mode == 'client':
            client(args.directory, args.name, args.uri)
        else:
            secret = secrets.token_bytes(32)
            with args.path.open('xb') as file:
                file.write(secret)
            print(f'Created {args.path} (32 raw bytes)')
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f'{exc}\n')


if __name__ == '__main__':
    main()
