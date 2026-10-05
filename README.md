# QKD stub

A small Rust HTTPS server for testing TLS/KEM integrations that use the ETSI GS
QKD 014 V1.1.1 key delivery API. Run one independent copy beside each application.
Neither stub contacts the other. No QKD hardware, database, synchronized state,
shared secret, or connection between the two LANs is needed by the stubs.

1. Application A calls its local stub's `enc_keys`, receiving key bytes and a UUID.
2. A passes that UUID to application B using the integration's existing protocol.
3. B calls its local stub's `dec_keys` with the UUID and receives identical bytes.

Both endpoints can issue keys, in any order. Retrieval is repeatable and survives
restarts. Clients must treat key IDs as opaque UUID strings.

**This is test material: anyone with the UUID can reproduce the key.** It is not
QKD and provides no quantum or cryptographic secrecy. HTTPS protects transport.
Client authentication and SAE authorization are opt-in;
the default mode requires no client certificate.

## Compatibility

The routes and JSON formats follow [ETSI GS QKD 014 V1.1.1](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf).
HTTPS uses TLS 1.2 or 1.3. The stub is API-compatible for integration testing,
**not fully ETSI-compliant**. The default mode omits mutual authentication and SAE
access control; the optional SAE mode implements these checks for integration tests.
There is no simulated key
consumption, expiration, storage, or generation rate. IDs belonging to this stub's
format are reproducible even if never previously issued by a running server.

## Build and quickstart

Requirements: a current stable Rust toolchain (tested with Rust 1.95), a C compiler
for the TLS dependency, and OpenSSL, Python 3, and curl for the helper scripts.
Run these commands from this directory:

```sh
cargo build --release --locked
./scripts/gen-certs.sh pki localhost 127.0.0.1 ::1
```

The script creates a test CA (`ca.crt`, `ca.key`) and a server certificate/key
(`server.crt`, `server.key`). Every supplied DNS name or IP address is included in
the server certificate's subject alternative names. Existing outputs are preserved;
add `--force` to explicitly replace the test PKI. Regenerating the CA requires
updating client trust. Private keys are created with owner-only permissions.

Start A in one terminal:

```sh
./target/release/qkd-stub --listen 127.0.0.1:8443 \
  --tls-cert pki/server.crt --tls-key pki/server.key \
  --sae-id A --kme-id KME-A --peer-kme-id KME-B
```

Start B in another terminal:

```sh
./target/release/qkd-stub --listen 127.0.0.1:8444 \
  --tls-cert pki/server.crt --tls-key pki/server.key \
  --sae-id B --kme-id KME-B --peer-kme-id KME-A
```

Then exercise both directions, including a batch:

```sh
./scripts/smoke-test.sh pki/ca.crt https://127.0.0.1:8443 https://127.0.0.1:8444
```

The smoke test verifies certificate trust and hostnames; it does not disable TLS
verification. Stop a server with Ctrl-C or SIGTERM; it allows up to five seconds
for active connections to finish.

### Two separate machines / LANs

On machine A, generate its own local certificate and start the server:

```sh
./scripts/gen-certs.sh pki localhost 127.0.0.1
./target/release/qkd-stub --tls-cert pki/server.crt --tls-key pki/server.key \
  --sae-id A --kme-id KME-A --peer-kme-id KME-B
```

On machine B, independently run:

```sh
./scripts/gen-certs.sh pki localhost 127.0.0.1
./target/release/qkd-stub --tls-cert pki/server.crt --tls-key pki/server.key \
  --sae-id B --kme-id KME-B --peer-kme-id KME-A
```

Configure each application to use `https://127.0.0.1:8443` on its own machine and
trust that machine's `pki/ca.crt` for the KME connection. No certificate or CA key
needs to be shared between the stubs. In the default mode, KME and SAE identifiers
are status metadata;
they do not affect key derivation. If applications check KME identity in server
certificates, supply certificates satisfying their identity convention; the test
certificate has the generic CN `QKD Stub Test Server`.

If the application is on another host in the same LAN, include the stub's actual
DNS name/IP when generating its certificate, bind with `--listen 0.0.0.0:8443`,
and configure that HTTPS address and CA trust in the application. This exposes an
unauthenticated test service on the selected interface. For a smoke test from a
host that can reach both stubs, concatenate their public CA certificates into a
PEM bundle and pass that as `CA_CERT` to the smoke-test script.

## Optional certificate-based SAE authorization

Enable this mode on both simulators with `--tls-client-ca` and `--sae-map`.
It supports multiple SAE pairs on the same two processes. A client must present a
certificate signed by a trusted client CA, valid for client authentication. Its
subject DN or a supported SAN is matched against the configured SAE registry.
Missing, untrusted, expired, or wrong-purpose certificates fail the TLS handshake;
valid certificates with no mapping or conflicting SAE mappings receive HTTP 401.

The example registry is in [`examples/sae-map.json`](examples/sae-map.json):

```json
{
  "saes": [
    {"id":"A", "code":1, "identities":[{"field":"subject_dn", "value":"CN=client-a"}]},
    {"id":"B", "code":2, "identities":[{"field":"san_uri", "value":"urn:qkd:sae:B"}]}
  ]
}
```

Both simulators must assign the **same unique numeric code to each SAE ID**.
Codes are integers from 1 to 65,535. Keep assignments stable while any key IDs may
still be used: changing a code changes the meaning of existing IDs. Both endpoints
need registry entries for all participating SAEs, but their certificate selectors
and trusted client CAs may differ. Remote-only entries may omit `identities`.
The file is read at startup; restart after changes.

Any mapped SAE can request a key for any registered SAE. On `enc_keys`, the master
is the certificate's SAE and the slave is the SAE in the URL. Both codes are
embedded in the returned UUID. On `dec_keys`, the caller must match that UUID's
slave code, and the URL's master SAE must match its master code. The entire batch
is rejected with 401 if any ID belongs to another pair. This also prevents the
master from retrieving its own issued key through `dec_keys`, unless master and
slave are explicitly the same SAE. `Request-SAE-ID` cannot impersonate another SAE.
There is no additional pair allowlist.

### Certificate mapping rules

Use the built-in inspector to obtain exact selector values from an existing
certificate; it prints metadata only and does not verify trust:

```sh
./target/release/qkd-stub --inspect-cert path/to/client.crt
```

Supported `field` values are `subject_dn`, `san_dns`, `san_uri`, `san_email`, and
`san_ip`. DN, URI, and email matching is exact and case-sensitive. DNS matching is
ASCII case-insensitive; IP addresses are normalized. There are no wildcard,
substring, or regex matches. DN values use a deterministic RFC4514-style rendering
with escaped attribute values; use inspector output rather than hand-translating
another tool's DN formatting. Unsupported non-UTF8 DN attributes require a SAN
selector. Other SAN types are ignored.

Multiple selectors are alternatives. A certificate may match several selectors
for the same SAE, but matching different SAEs is an error; there is no DN/SAN
precedence. Duplicate IDs, numeric codes, selectors, and invalid configuration
fields are rejected at startup. Client certificate renewal works without changing
key IDs when the replacement certificate maps to the same SAE code.

### Local mTLS example with two SAE pairs

Generate the server PKI as in the quickstart, then four client certificates:

```sh
./scripts/gen-client-cert.sh pki client-a
./scripts/gen-client-cert.sh pki client-b urn:qkd:sae:B
./scripts/gen-client-cert.sh pki client-c
./scripts/gen-client-cert.sh pki client-d urn:qkd:sae:D
```

The helper signs client certificates using the existing test CA and never
overwrites existing keys/certificates. Run each server in its own terminal:

```sh
./target/release/qkd-stub --listen 127.0.0.1:8443 \
  --tls-cert pki/server.crt --tls-key pki/server.key \
  --tls-client-ca pki/ca.crt --sae-map examples/sae-map.json \
  --kme-id KME-A --peer-kme-id KME-B
```

```sh
./target/release/qkd-stub --listen 127.0.0.1:8444 \
  --tls-cert pki/server.crt --tls-key pki/server.key \
  --tls-client-ca pki/ca.crt --sae-map examples/sae-map.json \
  --kme-id KME-B --peer-kme-id KME-A
```

A requests a key for B, then B retrieves it at the other endpoint:

```sh
curl --fail --cacert pki/ca.crt --cert pki/client-a.crt --key pki/client-a.key \
  'https://127.0.0.1:8443/api/v1/keys/B/enc_keys' > issued.json
KEY_ID=$(python3 -c 'import json; print(json.load(open("issued.json"))["keys"][0]["key_ID"])')
curl --fail --cacert pki/ca.crt --cert pki/client-b.crt --key pki/client-b.key \
  "https://127.0.0.1:8444/api/v1/keys/A/dec_keys?key_ID=$KEY_ID"
```

C and D can use the same servers with their respective certificates and SAE URLs.
Trying B's key with D's certificate returns 401, even if a `Request-SAE-ID: B`
header is supplied. `scripts/smoke-test.sh` remains the anonymous-mode quickstart;
`python3 tests/mtls.py` runs a complete temporary two-pair mTLS test.

On separate LANs, distribute the common SAE code assignments to both simulators
and configure each to trust the CA(s) issuing its local clients' certificates.
No CA private key needs to be shared between the simulators. Each application
still separately trusts its server's CA and presents its own client certificate.

### Authorization format and limits

Anonymous mode continues issuing and accepting v1 `QK` UUIDs unchanged.
SAE mode issues and accepts only v2 `QA` UUIDs. It rejects old unrestricted UUIDs
with 401; anonymous mode rejects `QA` UUIDs with 400. Both endpoints must therefore
run the same mode. Existing unbound IDs cannot be upgraded to SAE-bound IDs.

The v2 UUID keeps the v1 length, version, and variant fields, replacing the marker
with ASCII `QA`. Bytes 4–5 contain the master's unsigned big-endian 16-bit code;
bytes 10–11 contain the slave's code. The remaining 58 bits are OS-generated
randomness. Derivation is:

```text
SHAKE256(ASCII("qkd-stub:v2") || 0x00 || UUID_RAW_16_BYTES, output_length = size_in_bytes)
```

A fixed vector for master 1, slave 2, size 256 bits is UUID
`51410020-0001-8678-9abc-000212345678`, yielding Base64
`sx6nXvDWKRGtMIRlScPphJ86hrNSCQLPBOs/cyvF6aU=`.
Changing either embedded SAE code changes the derived key.

This mode tests certificate identity and API access checks; it does not make the
publicly deterministic key material secret. UUIDs are not signed proof of issuance,
and a correctly formatted ID can still be constructed offline. No shared secret
or key state is added, and restart/repeat-retrieval behavior stays deterministic.

## Command-line interface

```text
qkd-stub --tls-cert CERT.pem --tls-key KEY.pem [OPTIONS]

--listen ADDRESS       Default: 127.0.0.1:8443 (numeric IP:port)
--sae-id ID            Default: sae-local
--kme-id ID            Default: kme-local
--peer-kme-id ID       Default: kme-peer
--tls-client-ca FILE   Opt-in: PEM CA bundle for verifying client certificates
--sae-map FILE         Opt-in: JSON SAE code registry and certificate mapping
--inspect-cert FILE   Print selectors from a PEM leaf certificate and exit
--help / --version
```

The certificate file may contain a PEM chain; the key must be unencrypted PEM.
There is no HTTP listener. Invalid or missing TLS files cause startup to fail.
Client verification is enabled only when both `--tls-client-ca` and `--sae-map`
are supplied; supplying only one is an error.

## API

All paths begin with `/api/v1/keys/{SAE_ID}`. URL-encode SAE identifiers.
The default mode requires no authorization header or client certificate. In SAE
mode, all three APIs require a verified, unambiguously mapped client certificate;
SAE IDs in the URL must be present in the registry.

| Method | Suffix | Parameters |
| --- | --- | --- |
| GET | `/status` | Peer slave SAE in the path; master from certificate in SAE mode, otherwise optional `Request-SAE-ID` header |
| GET | `/enc_keys` | Optional `number` and `size` query parameters |
| POST | `/enc_keys` | JSON object with optional `number`, `size`, extension fields |
| GET | `/dec_keys` | Required `key_ID` query parameter |
| POST | `/dec_keys` | JSON `{"key_IDs":[{"key_ID":"UUID"}, ...]}` |

`number` defaults to 1 and must be 1–128. `size` defaults to 256 bits and must be
8–65,536 bits, divisible by 8. A POST issuance request with defaults uses `{}`.
Retrieval accepts 1–128 IDs, preserving order and duplicates. The UUID carries the
key length; `dec_keys` needs no size parameter or prior issuance on that endpoint.
Key values use standard padded Base64. IDs are returned in lowercase hyphenated
UUID format; retrieval also accepts uppercase hyphenated UUIDs.

```sh
curl --cacert pki/ca.crt 'https://127.0.0.1:8443/api/v1/keys/B/status'
curl --cacert pki/ca.crt 'https://127.0.0.1:8443/api/v1/keys/B/enc_keys?number=2&size=256'
curl --cacert pki/ca.crt -H 'Content-Type: application/json' \
  -d '{"number":2,"size":512}' 'https://127.0.0.1:8443/api/v1/keys/B/enc_keys'
curl --cacert pki/ca.crt \
  'https://127.0.0.1:8444/api/v1/keys/A/dec_keys?key_ID=514b0020-1234-8678-9abc-def012345678'
```

A key response has this shape:

```json
{"keys":[{"key_ID":"514b0020-1234-8678-9abc-def012345678","key":"JfPEJ1sm6M8pfH4gkH8Cg3XZMB+GrfDs91tVTcYkRwo="}]}
```

Status returns all required ETSI fields. `stored_key_count` and `max_key_count`
are fixed at 1,024: a synthetic, non-depleting availability indicator, not a real
pool or lifetime issuance limit. `max_key_per_request` is 128, `key_size` is 256,
`min_key_size` is 8, `max_key_size` is 65,536, and `max_SAE_ID_count` is 0.
`master_SAE_ID` comes from the client certificate in SAE mode; `Request-SAE-ID`
and `--sae-id` cannot override it. In default mode it comes from `Request-SAE-ID`
if supplied, otherwise `--sae-id`.

Nonempty `additional_slave_SAE_IDs` is rejected because multicast is not
advertised. Optional extension objects are ignored. Nonempty mandatory extensions
are rejected with `not all extension_mandatory parameters are supported`.
Malformed requests return HTTP 400 and `{"message":"..."}`; non-byte-aligned sizes
use `size shall be a multiple of 8`. Unsupported key formats use
`one or more keys specified are not found on KME`. No partial key batch is returned
on error. Responses carry `Cache-Control: no-store`. JSON bodies are limited to 64 KiB (HTTP 413); issuance failures return
503. Unknown routes and unsupported methods return JSON 404/405 errors.

## Deterministic format, version 1

The UUID's 16 raw bytes, in standard UUID/network byte order, contain:

| Bytes / bits | Value |
| --- | --- |
| 0–1 | ASCII `QK` (`51 4b` hex) |
| 2–3 | Key length **in bytes**, unsigned big-endian, 1–8,192 |
| High nibble of byte 6 | UUID version 8 (`1000`) |
| High two bits of byte 8 | RFC UUID variant (`10`) |
| Remaining 90 bits | OS-generated randomness |

Issuance fills 16 random bytes and overwrites the marker, size, version, and variant
fields. The format marker and UUID version identify this derivation format; a
future incompatible format must use a different marker or version.

Derivation is exactly:

```text
SHAKE256(ASCII("qkd-stub:v1") || 0x00 || UUID_RAW_16_BYTES, output_length = size_in_bytes)
```

For the default v1 format, no SAE IDs, hostnames, seeds, TLS certificates, or
issuance timestamps participate.
The domain separator is the 12-byte sequence `71 6b 64 2d 73 74 75 62 3a 76 31 00`.
The UUID in the API example is a fixed 256-bit-key test vector; tests verify its
Base64 result independently of ID generation. UUIDs with invalid markers,
versions, variants, or out-of-range encoded lengths are rejected.

## Validation

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --locked
python3 tests/https.py
python3 tests/mtls.py
```

Rust tests cover derivation, IDs, sizes, batches, concurrent requests, both methods,
status, malformed requests, extensions, and response limits. The Python test
launches two real HTTPS processes using temporary certificates, runs the smoke
test, restarts B and retrieves the same keys, checks TLS 1.2/1.3, rejects an untrusted
certificate, checks invalid TLS configuration and certificate overwrite protection,
and verifies graceful shutdown. Set `QKD_STUB_BIN` to test another built binary.

The mTLS test covers subject-DN and all supported SAN mappings, ambiguous and
unmapped identities, expired/untrusted/missing/wrong-purpose client certificates,
header spoofing, cross-pair and wrong-master rejection, concurrent bidirectional
pairs, restart recovery, TLS 1.2/1.3, and mandatory opt-in flag pairing.
