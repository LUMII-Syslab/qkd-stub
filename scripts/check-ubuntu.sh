#!/usr/bin/env bash
# Usage: check-ubuntu.sh [IMAGE]   (default: ubuntu:24.04)
# Verifies the README prerequisites and quickstart on a fresh Ubuntu container:
# installs the minimal packages, builds, runs the quickstart and all tests.
# Requires Docker and network access. The working tree is mounted read-only.
set -euo pipefail
image=${1:-ubuntu:24.04}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
docker run --rm -v "$root":/src:ro "$image" bash -euxo pipefail -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    ca-certificates gcc libc6-dev curl openssl python3 rustc-1.91 cargo-1.91 >/dev/null
export PATH=/usr/lib/rust-1.91/bin:$PATH
mkdir /w
(cd /src && tar --exclude=./target --exclude=./pki -cf - .) | tar -xf - -C /w
cd /w
cargo build --release --locked
cargo build --locked
./scripts/gen-certs.sh pki localhost 127.0.0.1 ::1
(umask 077; set -C; openssl rand 32 > pki/shared.psk)
./scripts/gen-client-cert.sh pki client-a
./scripts/gen-client-cert.sh pki client-b urn:qkd:sae:B
for p in "8443 KME-A KME-B" "8444 KME-B KME-A"; do
    set -- $p
    ./target/release/qkd-stub --listen 127.0.0.1:$1 \
        --tls-cert pki/server.crt --tls-key pki/server.key --psk-file pki/shared.psk \
        --tls-client-ca pki/ca.crt --sae-map examples/sae-map.toml \
        --kme-id $2 --peer-kme-id $3 &
done
sleep 1
curl --fail --cacert pki/ca.crt --cert pki/client-a.crt --key pki/client-a.key \
    https://127.0.0.1:8443/api/v1/keys/B/enc_keys > issued.json
id=$(python3 -c "import json; print(json.load(open(\"issued.json\"))[\"keys\"][0][\"key_ID\"])")
curl --fail --cacert pki/ca.crt --cert pki/client-b.crt --key pki/client-b.key \
    "https://127.0.0.1:8444/api/v1/keys/A/dec_keys?key_ID=$id"
kill %1 %2
cargo test --release --locked
python3 tests/https.py
python3 tests/mtls.py
python3 tests/psk.py
echo "CHECK OK"
'
