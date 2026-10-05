#!/usr/bin/env bash
# Usage: gen-client-cert.sh PKI_DIR NAME [URI_SAN]
# Creates NAME.crt / NAME.key signed by PKI_DIR/ca.crt and ca.key.
set -euo pipefail
umask 077
if (( $# < 2 || $# > 3 )); then
    echo "Usage: $0 PKI_DIR NAME [URI_SAN]" >&2
    exit 2
fi
pki=$1
name=$2
uri=${3:-}
[[ $name =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'NAME must contain only letters, digits, underscores, and hyphens' >&2; exit 2; }
[[ -r $pki/ca.crt && -r $pki/ca.key ]] || { echo 'Missing ca.crt or ca.key; run gen-certs.sh first' >&2; exit 1; }
for ext in crt key; do
    [[ ! -e $pki/$name.$ext && ! -L $pki/$name.$ext ]] || { echo "Refusing to overwrite $pki/$name.$ext" >&2; exit 1; }
done
if [[ -n $uri ]]; then
    python3 - "$uri" <<'PY'
import re,sys
value=sys.argv[1]
if not re.fullmatch(r'[A-Za-z][A-Za-z0-9+.-]*:[^,\s\x00-\x1f\x7f]+',value):
    sys.exit('URI_SAN must be a URI without commas, whitespace, or control characters')
PY
fi
tmp=$(mktemp -d "$pki/.gen-client.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=$name" \
    -keyout "$tmp/client.key" -out "$tmp/client.csr" >/dev/null 2>&1
cat > "$tmp/client.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EXT
if [[ -n $uri ]]; then printf 'subjectAltName=URI:%s\n' "$uri" >> "$tmp/client.ext"; fi
openssl x509 -req -in "$tmp/client.csr" -CA "$pki/ca.crt" -CAkey "$pki/ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days 365 -sha256 \
    -extfile "$tmp/client.ext" -out "$tmp/client.crt" >/dev/null 2>&1
mv -- "$tmp/client.key" "$pki/$name.key"
mv -- "$tmp/client.crt" "$pki/$name.crt"
printf 'Created %s/%s.crt and %s/%s.key\n' "$pki" "$name" "$pki" "$name"
