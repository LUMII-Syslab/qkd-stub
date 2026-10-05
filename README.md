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
QKD and provides no quantum or cryptographic secrecy. HTTPS protects transport,
but the server intentionally performs no client authentication or authorization.

## Compatibility

The routes and JSON formats follow [ETSI GS QKD 014 V1.1.1](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/01.01.01_60/gs_qkd014v010101p.pdf).
HTTPS uses TLS 1.2 or 1.3. The stub is API-compatible for integration testing,
**not fully ETSI-compliant**: the standard's mutual authentication and SAE
access-control requirements are deliberately omitted. There is no simulated key
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
needs to be shared between the stubs. KME and SAE identifiers are status metadata;
they do not affect key derivation. If applications check KME identity in server
certificates, supply certificates satisfying their identity convention; the test
certificate has the generic CN `QKD Stub Test Server`.

If the application is on another host in the same LAN, include the stub's actual
DNS name/IP when generating its certificate, bind with `--listen 0.0.0.0:8443`,
and configure that HTTPS address and CA trust in the application. This exposes an
unauthenticated test service on the selected interface. For a smoke test from a
host that can reach both stubs, concatenate their public CA certificates into a
PEM bundle and pass that as `CA_CERT` to the smoke-test script.

## Command-line interface

```text
qkd-stub --tls-cert CERT.pem --tls-key KEY.pem [OPTIONS]

--listen ADDRESS       Default: 127.0.0.1:8443 (numeric IP:port)
--sae-id ID            Default: sae-local
--kme-id ID            Default: kme-local
--peer-kme-id ID       Default: kme-peer
--help / --version
```

The certificate file may contain a PEM chain; the key must be unencrypted PEM.
No HTTP listener or client-certificate configuration exists. Invalid or missing
TLS files cause startup to fail.

## API

All paths begin with `/api/v1/keys/{SAE_ID}`. URL-encode SAE identifiers.
No authorization header or client certificate is required.

| Method | Suffix | Parameters |
| --- | --- | --- |
| GET | `/status` | Peer slave SAE in the path; optional `Request-SAE-ID` header identifies the master for this response only |
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
`master_SAE_ID` comes from `Request-SAE-ID` if supplied, otherwise `--sae-id`.

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

No SAE IDs, hostnames, seeds, TLS certificates, or issuance timestamps participate.
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
```

Rust tests cover derivation, IDs, sizes, batches, concurrent requests, both methods,
status, malformed requests, extensions, and response limits. The Python test
launches two real HTTPS processes using temporary certificates, runs the smoke
test, restarts B and retrieves the same keys, checks TLS 1.2/1.3, rejects an untrusted
certificate, checks invalid TLS configuration and certificate overwrite protection,
and verifies graceful shutdown. Set `QKD_STUB_BIN` to test another built binary.
