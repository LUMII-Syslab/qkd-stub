#!/usr/bin/env python3
"""Compare keys from two running stubs in --no-sae-binding mode."""
import argparse
import base64
import json
import ssl
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ca_cert')
    parser.add_argument('a_url')
    parser.add_argument('b_url')
    args = parser.parse_args()
    urls = [url.rstrip('/') for url in [args.a_url, args.b_url]]
    if not all(url.startswith('https://') for url in urls):
        parser.error('Both URLs must use HTTPS')
    context = ssl.create_default_context(cafile=args.ca_cert)

    def fetch(url, path, body=None):
        req = urllib.request.Request(url + '/api/v1/keys/' + path,
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, context=context, timeout=20) as response:
            return json.load(response)

    a, b = urls
    for source, target, slave, master, count, bits in [(a, b, 'B', 'A', 3, 512), (b, a, 'A', 'B', 1, 256)]:
        if count > 1:
            issued = fetch(source, slave + '/enc_keys', {'number': count, 'size': bits})
            retrieved = fetch(target, master + '/dec_keys',
                              {'key_IDs': [{'key_ID': k['key_ID']} for k in issued['keys']]})
        else:
            issued = fetch(source, slave + f'/enc_keys?size={bits}')
            retrieved = fetch(target, master + '/dec_keys?' + urllib.parse.urlencode(
                {'key_ID': issued['keys'][0]['key_ID']}))
        assert issued == retrieved
        assert len(issued['keys']) == len({k['key_ID'] for k in issued['keys']}) == count
        assert all(len(base64.b64decode(k['key'], validate=True)) == bits // 8 for k in issued['keys'])
    print('PASS: certificate-verified HTTPS; A->B batch and B->A single-key agreement')


if __name__ == '__main__':
    main()
