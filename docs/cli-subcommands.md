# CLI subcommands (proposal)

Status: **historical proposal, superseded.** The implemented command surface is
`configure`, `serve`, `check`, `tls`, `cert`, `psk`, `sae` and `demo`; see
[setup.md](setup.md). The original flag-only server invocation (`--listen`,
`--tls-cert`, ..., `--no-sae-binding`, `--inspect-cert`) has been removed.
The text below is the original rationale; its command names (`init`,
`gen-certs`, `inspect-cert`) were not adopted.

## Motivation

Setting up the stubs today needs more than the server itself:

| Tool | Used for |
| --- | --- |
| Rust / release binary | the endpoints |
| Python 3.11+ | `scripts/pki.py` and `tests/*.py` helpers |
| OpenSSL 3 CLI | certificate generation invoked by `scripts/pki.py` |
| `.sh` / `.bat` wrappers | `gen-certs`, `gen-psk`, `gen-client-cert`, `smoke-test`, `check-*` |

A developer integrating against the stubs already has these tools. A tester who
only wants to download a release binary does not. Folding certificate and PSK
generation into the binary removes Python and OpenSSL from the runtime path and
makes the Windows release a single `.exe`.

The server itself already has no OpenSSL dependency: it uses `rustls` + `ring`.
Only the setup scripts need the OpenSSL CLI.

## Proposed command surface

Add setup subcommands:

```
qkd-stub serve          run one endpoint
qkd-stub init [DIR]     generate CA, server cert/key, PSK and a sample SAE map
qkd-stub gen-certs      CA + server certificate (replaces scripts/gen-certs.*)
qkd-stub gen-psk FILE   exactly 32 raw random bytes (replaces scripts/gen-psk.*)
qkd-stub gen-client-cert NAME [SAE]
                        client certificate (replaces scripts/gen-client-cert.*)
qkd-stub inspect-cert FILE
                        certificate identity selectors (replaced the former --inspect-cert)
qkd-stub demo           generate creds, run both endpoints, print URLs, block
```

### `init`

The plug-and-play entry point. Creates a directory (default `pki/`) containing
the CA, server certificate and key, the shared PSK, and a sample `sae-map.toml`.
Refuses to overwrite existing credentials unless `--force` is given, matching
the current scripts' overwrite protection.

### `demo`

One process, both endpoints. Generates credentials into a local directory, starts
listeners on `127.0.0.1:8443` and `127.0.0.1:8444` with matching SAE assignments,
prints the ready-to-use HTTPS URLs, and blocks until Ctrl-C. This is intended as
the "download and run" path for a release, removing the two-terminal setup.

## Implementation notes

- Add the `rcgen` crate for certificate generation. `ring` is already a
  dependency, so prefer `rcgen`'s `ring` backend to avoid pulling in a second
  crypto provider. `x509-parser` stays for `inspect-cert`.
- Port the logic in `scripts/pki.py` (currently shelling out to the OpenSSL CLI)
  into a Rust module so the release binary needs no Python or OpenSSL.
- The `.sh` / `.bat` scripts can become thin wrappers that delegate to the
  binary, or stay as fallbacks. `scripts/pki.py` remains the reference for the
  certificate extensions and SAN handling until the Rust port is verified by the
  existing integration tests.

## Release and distribution

Folding `init` / `demo` into the binary is what lets a release run without Python
or OpenSSL. Packaging and publishing (GitHub Releases, winget, Scoop) are covered
in [distribution.md](distribution.md).

## Non-goals

- **No GUI.** The audience is integrators wiring the stubs into test suites, not
  end users. A native Windows GUI also inherits SmartScreen and code-signing
  costs, plus per-platform maintenance, for little benefit. If a friendlier
  surface is ever needed, a small local web dashboard served by the existing
  `axum` dependency is the preferred middle ground.
- No change to the ETSI GS QKD 014 HTTP API or the encrypted key ID format.

## Open questions

- Should `demo` run both listeners inside one process, or spawn a child per
  endpoint (simpler isolation, harder shutdown)?
- Is `scripts/pki.py` retired once the Rust generation is covered by tests, or
  kept as an independent cross-check?
