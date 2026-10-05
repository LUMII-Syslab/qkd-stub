#!/usr/bin/env bash
# Usage: gen-certs.sh OUTPUT_DIR HOST [HOST ...] [--force]
# Requires OpenSSL and Python 3. One server certificate covers all given hosts.
set -euo pipefail
umask 077
if (( $# < 2 )); then
    echo "Usage: $0 OUTPUT_DIR HOST [HOST ...] [--force]" >&2
    exit 2
fi
out=$1
shift
force=false
hosts=()
for arg in "$@"; do
    if [[ $arg == --force ]]; then force=true; else hosts+=("$arg"); fi
done
(( ${#hosts[@]} > 0 )) || { echo 'At least one hostname or IP address is required' >&2; exit 2; }
# Validate before creating files; prevent OpenSSL config injection.
sans=$(python3 - "${hosts[@]}" <<'PY'
import ipaddress,re,sys
result=[]
for host in sys.argv[1:]:
    try:
        result.append('IP:'+str(ipaddress.ip_address(host)))
    except ValueError:
        if len(host)>253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in host.split('.')):
            sys.exit('Invalid DNS name or IP address: '+repr(host))
        result.append('DNS:'+host)
print(','.join(result))
PY
)
mkdir -p -- "$out"
for name in ca.crt ca.key server.crt server.key; do
    if [[ -e $out/$name || -L $out/$name ]]; then
        if [[ $force != true ]]; then
            echo "Refusing to overwrite $out/$name; use --force to replace this test PKI" >&2
            exit 1
        fi
        [[ ! -d $out/$name ]] || { echo "Refusing to replace directory $out/$name" >&2; exit 1; }
    fi
done
# Generate completely before replacing any existing output.
tmp=$(mktemp -d "$out/.gen-certs.XXXXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -subj '/CN=QKD Stub Test CA' -keyout "$tmp/ca.key" -out "$tmp/ca.crt" \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -subj '/CN=QKD Stub Test Server' -keyout "$tmp/server.key" -out "$tmp/server.csr" >/dev/null 2>&1
cat > "$tmp/server.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$sans
EXT
openssl x509 -req -in "$tmp/server.csr" -CA "$tmp/ca.crt" -CAkey "$tmp/ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days 365 -sha256 \
    -extfile "$tmp/server.ext" -out "$tmp/server.crt" >/dev/null 2>&1
for name in ca.crt ca.key server.crt server.key; do
    mv -f -- "$tmp/$name" "$out/$name"
done
printf 'Created %s/{ca.crt,ca.key,server.crt,server.key}\nSANs: %s\n' "$out" "$sans"
