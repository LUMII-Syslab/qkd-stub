# QKD endpoint simulator for integration testing

[![Tests (Ubuntu)](https://github.com/LUMII-Syslab/qkd-stub/actions/workflows/ubuntu.yml/badge.svg?branch=main)](https://github.com/LUMII-Syslab/qkd-stub/actions/workflows/ubuntu.yml)
[![Tests (Windows)](https://github.com/LUMII-Syslab/qkd-stub/actions/workflows/windows.yml/badge.svg?branch=main)](https://github.com/LUMII-Syslab/qkd-stub/actions/workflows/windows.yml)

Two independent HTTPS endpoints simulate the ETSI GS QKD 014 V1.1.1 key delivery
API without QKD hardware. Both endpoints derive matching keys from the same
pre-shared key (PSK), providing computational rather than information-theoretic
security.

**Main idea.** Give both stubs the same pre-shared key (PSK). Each key ID is a
UUID that encrypts the authorized SAE pair, a random seed, the key length, and a
checksum. Both stubs derive the same key from the PSK and the full UUID, without
communicating with each other or storing a shared key pool. Without the PSK,
the UUID reveals neither the embedded SAE pair nor the key.

Retrieval requires a client certificate
mapped to the UUID's receiving SAE, and the request must name its sending SAE.
An attacker holding a valid certificate for a different SAE cannot retrieve the
key through the stub using that UUID. The UUID alone is insufficient to calculate
the key without the PSK.

Two independent Rust HTTPS servers simulate the ETSI GS QKD 014 V1.1.1 key
delivery API. Application A obtains a key and UUID from its local stub, sends the
UUID to application B, and B retrieves the same key from its own stub. The stubs
never contact each other and need no shared database or synchronized clock.

![Two clients obtain the same SAE-bound key from independent KME stubs using a shared PSK and UUID.](docs/qkd-client-flow.png)

Both servers use the same 32-byte pre-shared key (PSK) to independently derive
identical key material from a UUID. Client certificates identify each
application as a Secure Application Entity (SAE), and the UUID binds the key to
the sending and receiving SAEs. Both servers must assign the same numeric codes
to those SAEs.

The PSK and client-certificate SAE authorization are mandatory.
Anyone with the PSK can reconstruct keys and decrypt their UUID metadata. This is
a software test stub, not real QKD, and PSK-derived keys do not have forward secrecy.

**Computational security without QKD.** QKD is not required for this design's
computational key secrecy: a securely provisioned, uniformly random 256-bit PSK
and HKDF-HMAC-SHA-512 provide strong computational protection for derived keys,
under the assumptions in the [security argument](docs/security.md). This claim
requires secret PSKs, protected endpoints, authenticated TLS, SAE authorization,
and suitably long output keys (at least 128 bits). It is conditional key secrecy,
not information-theoretic security or a proof of the whole service. The
[wiki proof sketch](https://github.com/LUMII-Syslab/qkd-stub/wiki/Computational-Security)
explains why HKDF pseudorandomness, rather than SHA preimage resistance alone,
is the relevant assumption.

## Quickstart

Download the signed `qkd-stub.exe` (Windows) or the static
`qkd-stub-x86_64-linux.tar.gz` (Linux; verification in
[Linux releases](docs/linux-release.md)) from
[GitHub Releases](https://github.com/LUMII-Syslab/qkd-stub/releases), or build
with `cargo build --release --locked` (`target/release/qkd-stub`).
No OpenSSL, Python, or source checkout is needed to run or provision endpoints.

```sh
qkd-stub demo init
qkd-stub --config qkd-demo/a.toml serve
# In a second terminal:
qkd-stub --config qkd-demo/b.toml serve
# In a third terminal:
qkd-stub demo verify
```

On Windows use `.\qkd-stub.exe`; the release also contains `qkd-stub-gui.exe`, a
[dashboard](docs/gui.md) that serves a configuration and shows client activity
(`qkd-stub-gui --config qkd-demo/a.toml --start`). Provisioning stays in the CLI. `demo init` creates a `qkd-demo` directory in the
**current working directory** (`--dir` changes it; an existing directory is refused)
with a test CA, two server configurations (ports 8443 and 8444), a shared PSK, and
client certificates for SAEs `A` and `B`. It holds private keys, so run it from a
private location. `demo verify` retrieves matching keys in both directions over
mTLS.

A requests a key for B at the first server, then B retrieves it at the second:

```sh
curl --fail --cacert qkd-demo/ca.pem \
  --cert qkd-demo/client-a.pem --key qkd-demo/client-a.key.pem \
  'https://localhost:8443/api/v1/keys/B/enc_keys' > issued.json
KEY_ID=$(python3 -c 'import json; print(json.load(open("issued.json"))["keys"][0]["key_ID"])')
curl --fail --cacert qkd-demo/ca.pem \
  --cert qkd-demo/client-b.pem --key qkd-demo/client-b.key.pem \
  "https://localhost:8444/api/v1/keys/A/dec_keys?key_ID=$KEY_ID"
```

Stop with Ctrl-C or SIGTERM (Ctrl-Break on Windows). Windows' bundled Schannel
curl may not accept PEM client certificates; use `demo verify` there.

For device-style provisioning with your own CA, start with `qkd-stub configure`.
It generates a local private key and CSR, saves the configuration, and can resume
after your CA signs the request. Use `check` to validate setup and `serve` to start
the endpoint. Scriptable commands cover TLS certificates/trust, PSKs, and SAE
mappings. See [standalone provisioning](docs/setup.md) for the full workflow and
command reference.

Separate machines: copy the same PSK and the same SAE code assignments to both
machines. Each server may use its own TLS certificate and client CA. Details:
[Deployment notes](https://github.com/LUMII-Syslab/qkd-stub/wiki/Deployment-Notes).

## Building and testing from source

Windows: [Windows quickstart](docs/windows.md). GitHub Actions runs the full test
suite on Windows and Linux. The
[signed Windows build workflow](docs/windows-signing.md) produces an x64
`qkd-stub.exe` and `qkd-stub-gui.exe`, with tagged builds stored in GitHub Releases
after publication. Build the dashboard from source with
`cargo build --release --locked --features gui`.

On Linux: Rust 1.89+, a C compiler, and, for the integration tests, OpenSSL 3,
Python 3.11+, and curl. On Ubuntu 24.04 (verified on a fresh container):

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    ca-certificates gcc libc6-dev curl openssl python3 rustc-1.91 cargo-1.91
export PATH=/usr/lib/rust-1.91/bin:$PATH
cargo build --locked
cargo test --locked
for t in setup https mtls psk; do python3 tests/$t.py; done
```

Other versions, rustup and the version notes: [Ubuntu prerequisites](https://github.com/LUMII-Syslab/qkd-stub/wiki/Ubuntu-Prerequisites).
The Python tests use `scripts/gen-*.sh` to create OpenSSL test credentials.

## Key IDs and derivation

Key IDs are AES-256 ciphertext formatted with UUIDv4 version/variant bits.
The encrypted payload holds the key length, SAE pair, 72 random bits and a
one-byte checksum. Generation retries with fresh randomness until the ciphertext
itself has the required six bits (64 attempts on average); no ciphertext bits
are overwritten. This retains approximately 66 bits of randomness per fixed
SAE pair and key length. Retrieval needs one decryption.

Authorized repeat retrieval of the same ID returns the same key while the PSK
remains unchanged, including after a restart. This supports retries; retrieval
does not consume the ID, and IDs do not expire.

The PSK hides the embedded pair and length from observers of the ID. It does not
hide network endpoints or traffic patterns, or authenticate issuance. The checksum
remains an 8-bit configuration/error check, not a security boundary. See [encrypted ID format](docs/encrypted-key-ids.md) for the exact layout,
derivation and limits. The [editable three-page diagram](docs/qkd-stub-architecture.drawio)
contains the current exchange flow, [ID layout](docs/key-id-layout.drawio.png),
and [key derivation](docs/key-derivation.drawio.png). Older `qkd-uuid-layout.png`
and `qkd-key-derivation.png` images describe the previous format.

## Certificate-based SAE authorization

Both configurations need a trusted client CA bundle (`tls trust add`) and an SAE
registry (`sae add`). A client must present a certificate signed by that CA. Its subject DN or a SAN is matched against the
registry. Invalid certificates fail the TLS handshake; unmapped or ambiguous ones
get HTTP 401.

The registry is a TOML file (`sae_map` in the configuration). An example is in
[`examples/sae-map.toml`](examples/sae-map.toml):

```toml
[[sae]]
id = "A"
code = 1
identities = [{ subject_dn = "CN=client-a" }]

[[sae]]
id = "B"
code = 2
identities = [{ san_uri = "urn:qkd:sae:B" }]
```

Each identity is a table with exactly one selector (`subject_dn`, `san_dns`,
`san_uri`, `san_email` or `san_ip`). Both servers must assign the **same unique
code (1–65535) to each SAE ID**, and the codes must stay stable while any key ID
may still be used. Remote-only entries may omit `identities`. The file is read at
startup.

On `enc_keys`, the master is the certificate's SAE and the slave is the SAE in the
URL; both codes go into the UUID. On `dec_keys`, the certificate's SAE must be the
UUID's slave and the URL's SAE its master, otherwise HTTP 401 for the whole batch.
`Request-SAE-ID` cannot impersonate another SAE. Details:
[SAE authorization details](https://github.com/LUMII-Syslab/qkd-stub/wiki/SAE-Authorization).

To get exact selector values from a client certificate (metadata only, trust is
not verified), use `cert inspect`; `sae add --cert FILE --selector N` records one,
or paste a selector into an `[[sae]]` entry:

```sh
qkd-stub cert inspect path/to/client.crt
```

## Command-line interface

Saved configuration and provisioning: `configure`, `serve`, `check`, `tls`,
`cert`, `psk`, `sae`, and `demo`. Use `--config FILE` to select a configuration
(default `qkd-stub-data/config.toml`); paths inside it are configuration-relative.
See [command reference](docs/setup.md#command-reference).

HTTPS only (TLS 1.2 and 1.3). Routes and JSON follow ETSI GS QKD 014 V1.1.1 but
the stub is not fully compliant.

## API

All paths begin with `/api/v1/keys/{SAE_ID}`. All calls require a
mapped client certificate and SAE IDs in the URL must be in the registry.

| Method | Suffix | Parameters |
| --- | --- | --- |
| GET | `/status` | Peer slave SAE in the path; master from the client certificate (`Request-SAE-ID` is ignored) |
| GET | `/enc_keys` | Optional `number` and `size` query parameters |
| POST | `/enc_keys` | JSON object with optional `number`, `size`, extension fields |
| GET | `/dec_keys` | Required `key_ID` query parameter |
| POST | `/dec_keys` | JSON `{"key_IDs":[{"key_ID":"UUID"}, ...]}` |

Examples, using the `demo init` credentials (A is `client-a`):

```sh
A="--cacert qkd-demo/ca.pem --cert qkd-demo/client-a.pem --key qkd-demo/client-a.key.pem"
curl $A 'https://localhost:8443/api/v1/keys/B/status'
curl $A 'https://localhost:8443/api/v1/keys/B/enc_keys?number=2&size=256'
curl $A -H 'Content-Type: application/json' \
  -d '{"number":2,"size":512}' 'https://localhost:8443/api/v1/keys/B/enc_keys'
```

Parameters, defaults, response format, errors and limits:
[API details](https://github.com/LUMII-Syslab/qkd-stub/wiki/API-Details).

## More

[Wiki](https://github.com/LUMII-Syslab/qkd-stub/wiki/Home): key derivation, SAE authorization rules, deployment notes, testing.
