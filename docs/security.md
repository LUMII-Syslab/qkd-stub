# Computational security without QKD

For format revision 7, QKD is not required to obtain strong computational
secrecy of derived keys from a securely shared, uniformly random 32-byte PSK.
This is a conditional claim about key derivation. It does not establish
information-theoretic security, forward secrecy, or security of the entire
server implementation. QKD and this PSK design offer different guarantees;
this design assumes the initial secret has already been distributed securely.

## Construction and assumptions

The implementation is in `src/keys.rs`; the exact byte layout and formulas are
in [Encrypted key IDs](encrypted-key-ids.md). Writing `C` for the public 16-byte
UUID ciphertext and `L` for the output length in bytes:

```text
PRK = HKDF-Extract-SHA512("qkd-stub:psk" || 0x00, PSK)
K(C, L) = HKDF-Expand-SHA512(PRK, "qkd-stub:key:v7" || 0x00 || C, L)
```

Separate labels derive the AES-256 ID-encryption key and the one-byte ID
checksum. All inputs above are raw bytes; `L` is recovered from the encrypted ID.

The argument assumes:

1. The PSK is uniformly sampled from 256 bits, independent of attacker inputs,
   securely provisioned, and never disclosed. A 32-byte password does not qualify.
2. HKDF-Extract with this **fixed public salt** and this random PSK produces a
   computationally pseudorandom PRK. This is an explicit extraction assumption,
   not a consequence of HMAC being a PRF under a secret key: here the salt is
   the public HMAC key and the PSK is its message. The 512-bit PRK does not
   create 512 bits of entropy from a 256-bit seed.
3. Under a uniform secret PRK, HKDF-Expand-SHA512 is jointly pseudorandom across
   the three distinct labels and their permitted inputs, including adaptively
   chosen inputs. Repeated `info` yields the same stream; shorter requests are
   prefixes, not independent outputs. This is the HKDF expansion assumption,
   motivated by the PRF security of HMAC-SHA-512.
4. Endpoints and their random generators are uncompromised; TLS authenticates
   peers and protects key responses; default SAE authorization is correctly
   configured. The attacker cannot obtain the target key through an authorized
   recipient, API access, logs, memory disclosure, or a side channel.

[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) specifies HKDF.
[Krawczyk's HKDF analysis](https://www.iacr.org/archive/crypto2010/62230625/62230625.pdf)
develops its extraction and pseudorandomness foundations. These references
support the building block; they do not certify this service or remove the
explicit assumptions above.

## Key-secrecy game and conditional proof sketch

Consider a computationally bounded classical attacker who sees public IDs,
knows the algorithm, and can learn keys for other IDs, including through its
own authorized SAE. It selects a valid target ID `C*` of length `L*` for which
no key material has been disclosed, and receives either `K(C*, L*)` or an
independent uniform `8 L*`-bit string. It must distinguish the two. No query
before or after the challenge may reveal key material for the same raw `C*`,
including an alternate textual spelling or a repeated issuance of that ID.
Length and metadata may be given to the attacker; their secrecy is not needed
for this game. The challenge key has no other use exposed to the attacker in
this game; application-protocol security requires its own analysis.

Let `epsilon_extract` bound the distinguishing advantage for assumption 2 and
`epsilon_expand` that for assumption 3, at the attacker's running time and total
query/output volume, including simulated issuance and validation operations.
Use advantage defined as the absolute difference of output probabilities in
the real-key and random-key experiments. A hybrid argument gives:

```text
Adv_key <= 2 * (epsilon_extract + epsilon_expand)
```

1. In each experiment, replace the extracted PRK by a uniform 64-byte secret.
   Each replacement changes the attacker's output probability by at most
   `epsilon_extract`.
2. Replace the expansion interface by an independent random byte stream for
   each distinct `info`, with consistent repeated queries and prefixes. Each
   replacement costs at most `epsilon_expand`. The AES-key label, checksum
   label, and key-material label have disjoint encodings.
3. In this final hybrid, ID generation uses only the independent AES-key and
   checksum streams. It can still encrypt, reject non-v4 ciphertexts, decrypt,
   and check authorization exactly as before. Even though real IDs depend on
   the PSK, their generation in this hybrid never consults the target
   key-material stream. Adaptive selection of an unexposed ID therefore
   leaves its key stream uniform and independent of the visible transcript.
4. The real-key and random-key experiments in the final hybrid have identical
   distributions. Apply the triangle inequality across both sets of
   replacements to obtain the bound above.

This is a reduction-style proof sketch under stated assumptions, not a
machine-checked proof or a numerical security bound for SHA-512. AES security
is needed for the separate metadata-hiding claim, not to keep the final
hybrid's independently sampled key stream secret. Metadata hiding additionally
requires a pseudorandom-permutation assumption for AES-256 and its own leakage
analysis; this key-secrecy proof does not establish it.

## Why this is not simply finding a SHA preimage

An attacker need not recover a SHA-512 preimage to win: it could distinguish
HKDF output, guess the PSK, exploit key delivery, or compromise a recipient.
Preimage resistance alone does not imply pseudorandomness of derived keys.
Nor does finding a SHA collision generally reveal the PSK or a derived key.

Exhaustive search over a uniform PSK has a space of `2^256` candidates; a known
ID/key pair lets an attacker test candidates offline. That is a generic attack
cost, **not a proven lower bound** for this construction. A shorter target key
can also be guessed directly. Generic single-target classical search strength
is therefore capped by `min(256, 8 L)` bits, and may be lower if assumptions
fail. Use at least 128-bit keys for a strong-security claim; the API also allows
8-bit test keys. Requesting more than 256 output bits adds no PSK entropy.
This argument is classical and makes no end-to-end post-quantum security claim.

## Limits that remain

- **No forward secrecy or fresh shared entropy.** PSK compromise exposes past
  and future keys for available IDs under that PSK. All stubs sharing it belong
  to the same compromise domain. Replacing it makes old IDs unusable with the
  new configuration; it does not protect old keys from a leaked old PSK.
- **ID collisions and replay.** For a fixed SAE pair and key length, UUID
  filtering leaves about `2^66` accepted IDs under the AES permutation model.
  For `q` independent issuances in that group, the birthday approximation is
  `Pr[repeat] ~ q(q-1) / 2^67` while the probability is small. Repeats become
  significant around `2^33` issuances. Sum the group bounds when tracking many
  pairs or lengths. A repeat gives the same key, so a previously disclosed
  repeat cannot be a fresh challenge in the proof. This is a key-reuse limit,
  not a `2^66` PSK search space. The service does not track collisions, expire
  IDs, consume keys, or prevent replay; applications must manage key/nonce reuse.
- **No issuance authentication.** The 8-bit checksum is an error check, not a
  MAC. AES encryption and format checks do not prove that an ID was issued.
  Validation responses are not covered by an integrity or metadata-secrecy
  theorem here. SAE checks control retrieval of the target ID; they do not
  turn this format into authenticated encryption.
- **API access matters.** With `--no-sae-binding`, anyone able to reach the
  retrieval API can obtain a key for a valid ID without knowing the PSK. This
  violates the target-key non-disclosure assumption. Incorrect certificate
  validation, leaked credentials, or a compromised authorized SAE also bypass
  the cryptographic problem.
- **Computational, not information-theoretic.** Deterministically expanding a
  shared PSK creates no additional shared secret entropy. These outputs do not
  provide information-theoretic one-time-pad security. The project remains an
  integration-test stub; this argument is not a production security audit.
