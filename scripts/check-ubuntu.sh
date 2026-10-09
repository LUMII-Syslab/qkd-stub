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
(cd /src && tar --exclude=./target --exclude=./qkd-demo -cf - .) | tar -xf - -C /w
cd /w
cargo build --release --locked
cargo build --locked
./target/release/qkd-stub demo init
for n in a b; do
    ./target/release/qkd-stub --config qkd-demo/$n.toml serve &
done
sleep 1
curl --fail --cacert qkd-demo/ca.pem --cert qkd-demo/client-a.pem --key qkd-demo/client-a.key.pem \
    https://localhost:8443/api/v1/keys/B/enc_keys > issued.json
id=$(python3 -c "import json; print(json.load(open(\"issued.json\"))[\"keys\"][0][\"key_ID\"])")
curl --fail --cacert qkd-demo/ca.pem --cert qkd-demo/client-b.pem --key qkd-demo/client-b.key.pem \
    "https://localhost:8444/api/v1/keys/A/dec_keys?key_ID=$id"
./target/release/qkd-stub demo verify
kill %1 %2
cargo test --release --locked
python3 tests/setup.py
python3 tests/https.py
python3 tests/mtls.py
python3 tests/psk.py
echo "CHECK OK"
'
