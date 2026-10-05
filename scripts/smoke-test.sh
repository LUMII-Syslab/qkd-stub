#!/usr/bin/env bash
# Usage: smoke-test.sh CA_CERT A_URL B_URL
# Requires curl and Python 3. Both endpoint certificates must chain to CA_CERT,
# which may be a PEM bundle of the independently generated A and B test CAs.
set -euo pipefail
if (( $# != 3 )); then
    echo "Usage: $0 CA_CERT A_URL B_URL" >&2
    exit 2
fi
ca=$1
a=${2%/}
b=${3%/}
[[ $a == https://* && $b == https://* ]] || { echo 'Both URLs must use HTTPS' >&2; exit 2; }
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
fetch() { curl --silent --show-error --fail --connect-timeout 5 --max-time 20 --cacert "$ca" "$@"; }
fetch -H 'Content-Type: application/json' -d '{"number":3,"size":512}' \
    "$a/api/v1/keys/B/enc_keys" > "$tmp/issued.json"
python3 - "$tmp" <<'PY'
import json,sys,pathlib
p=pathlib.Path(sys.argv[1])
keys=json.loads((p/'issued.json').read_text())['keys']
(p/'ids.json').write_text(json.dumps({'key_IDs':[{'key_ID':k['key_ID']} for k in keys]}))
PY
fetch -H 'Content-Type: application/json' --data-binary "@$tmp/ids.json" \
    "$b/api/v1/keys/A/dec_keys" > "$tmp/retrieved.json"
fetch "$b/api/v1/keys/A/enc_keys?size=256" > "$tmp/reverse-issued.json"
id=$(python3 - "$tmp/reverse-issued.json" <<'PY'
import json,sys,uuid
print(uuid.UUID(json.load(open(sys.argv[1]))['keys'][0]['key_ID']))
PY
)
fetch --get --data-urlencode "key_ID=$id" "$a/api/v1/keys/B/dec_keys" > "$tmp/reverse-retrieved.json"
python3 - "$tmp" <<'PY'
import base64,json,pathlib,sys
p=pathlib.Path(sys.argv[1])
for prefix,count,size in [('',3,64),('reverse-',1,32)]:
    issued=json.loads((p/(prefix+'issued.json')).read_text())['keys']
    retrieved=json.loads((p/(prefix+'retrieved.json')).read_text())['keys']
    assert len(issued)==len(retrieved)==count
    assert len({k['key_ID'] for k in issued})==count
    for a,b in zip(issued,retrieved):
        assert a['key_ID']==b['key_ID']
        x,y=(base64.b64decode(k['key'],validate=True) for k in (a,b))
        assert x==y and len(x)==size
print('PASS: certificate-verified HTTPS; A→B batch and B→A single-key agreement')
PY
