# Encrypted key IDs (format revision 7)

Both stubs need the same 32-byte PSK and SAE numeric assignments. The public ID
is a single AES-256 ciphertext block in lowercase, hyphenated UUID notation.
Uppercase input is accepted. Its version/variant fields match UUIDv4, but its
collision budget is smaller than an ordinary UUIDv4 generator's 122 random bits.

For the computational key-secrecy claim, assumptions and conditional proof
sketch, see [Computational security without QKD](security.md). SHA preimage
resistance alone is not the security argument for this HKDF construction.

## Plaintext layout

Two-byte integers are unsigned big-endian; offsets are zero-based.

| Bytes | Contents |
| --- | --- |
| 0–1 | Key length in bytes, 1–8192 |
| 2–3 | Master SAE code |
| 4–5 | Slave SAE code |
| 6–14 | 72 OS-random bits, with no reserved version/variant bits |
| 15 | One-byte keyed checksum |

The server binary always issues with the nonzero codes of the authenticated
SAE pair and checks the decrypted codes on retrieval against the certificate's
slave SAE and the URL's master SAE. Only the library's registry-less mode (used
by Rust API tests, not reachable from the CLI) issues zero for both SAE codes.

## Exact derivation

Concatenation is denoted by ||; slices exclude the upper bound. Labels are ASCII,
with a trailing zero byte. All cryptographic inputs are raw bytes, not UUID text.

```text
PRK = HKDF-Extract-SHA512(salt = "qkd-stub:psk" || 0x00, IKM = PSK)
AES_key = HKDF-Expand-SHA512(PRK, "qkd-stub:id-encryption:v7" || 0x00, 32)
P[15] = HKDF-Expand-SHA512(PRK, "qkd-stub:id-check:v7" || 0x00 || P[0..15], 1)[0]
C = AES-256-Encrypt-Block(AES_key, P)
key = HKDF-Expand-SHA512(PRK, "qkd-stub:key:v7" || 0x00 || C, key_length_bytes)
```

Accept C only if (C[6] >> 4) == 4 and (C[8] >> 6) == 2.
Otherwise replace all nine random bytes, recompute the checksum, and encrypt
again. Never overwrite ciphertext bits. Acceptance probability is approximately
1/64, with 64 attempts on average. After 4096 unsuccessful attempts issuance
fails (HTTP 503); the idealized probability is about 10^-28 per ID.

Retrieval validates the external representation and version/variant, decrypts
once, validates length and checksum, then performs SAE authorization. Invalid
IDs return HTTP 400; valid IDs for another pair return HTTP 401. Batches remain
atomic. Keys are derived from the accepted ciphertext, including all 128 bits.

## Limits and migration

Filtering leaves approximately 2^66 accepted IDs per fixed pair and length,
assuming AES behaves as a pseudorandom permutation. Thus collisions reach
birthday scale around 2^33 issuances for that pair/length; this does not provide
the collision budget of ordinary UUIDv4. Reclaiming the six internal UUID bits
compensates for the six bits consumed by filtering. Repeated plaintext produces
repeated ciphertext and the same key.

The checksum is not authentication or proof of issuance. Conditional on a
plausible decrypted length, a wrong PSK passes this 8-bit check with probability
about 1/256; length validation rejects additional wrong-key decryptions.

Authorized repeat retrieval of the same ID returns the same key while the PSK
remains unchanged, including after a restart. This supports retries; retrieval
does not consume the ID, and IDs do not expire. The stub keeps no issuance history.

PSK-derived keys do not have forward secrecy. PSK holders can recover metadata
and keys; observers may still learn
communication partners through endpoints, request paths or traffic patterns.

Previous plaintext UUIDv8 IDs and older formats are rejected. Upgrade both
servers and obtain new IDs. Revision v7 in labels is unrelated to UUIDv7.
Current diagrams: [ID layout](key-id-layout.drawio.png),
[key derivation](key-derivation.drawio.png), and
[editable three-page source](qkd-stub-architecture.drawio).
The older `qkd-uuid-layout.png` and `qkd-key-derivation.png` images are historical.

## Independent test vectors

PSK: 32 bytes of 07. Each vector has a 32-byte output key.
The Python HTTPS test reproduces these using OpenSSL AES and Python HMAC.

| Plaintext (hex) | Public ID | Key (Base64) |
| --- | --- | --- |
| 0020000000000000000000000000070e | ab531e5f-28fd-4f93-b7cf-f49a723babac | 29dcgpL9WDwAf/0CfUUAm5JptfBv9w7mr7mvu0ZYfo8= |
| 00200001000200000000000000002807 | 0a142bd6-b238-400c-9bf3-3dc2cdef20fd | GuyWf9LhOQDfzpjOFM9DVYYa2UWRk3b5RtZchFiK1jE= |
