# Standalone provisioning

Starting with v0.4.0, `qkd-stub.exe` can configure and test endpoints without
OpenSSL, Python, shell scripts, or a source checkout. Download the signed Windows
x64 executable from [Releases](https://github.com/LUMII-Syslab/qkd-stub/releases).
The same commands work with a Linux build (`qkd-stub` instead of `qkd-stub.exe`).

## Try it with one executable

In PowerShell, from the directory containing the executable:

```powershell
.\qkd-stub.exe demo init
.\qkd-stub.exe --config qkd-demo/a.toml serve
```

In a second terminal:

```powershell
.\qkd-stub.exe --config qkd-demo/b.toml serve
```

In a third terminal:

```powershell
.\qkd-stub.exe demo verify
```

Verification requests and retrieves matching keys in both directions over mTLS.
It prints success/failure without printing key material. No curl is needed.
Stop servers with Ctrl-C (or Ctrl-Break on Windows).

`demo init --dir DIRECTORY` (default `qkd-demo` in the current working
directory) creates two configurations on localhost ports 8443
and 8444, separate server keys/certificates, client A/B keys/certificates,
`ca.pem`, `shared.psk`, and the shared SAE registry. Existing directories are
refused. Certificates last one year. The test CA's private key is not retained;
create a new demo directory when new credentials are needed. These are test
credentials, not an organizational PKI.

To change ports, edit `listen` in each generated configuration and pass matching
`--url-a https://localhost:PORT` and `--url-b https://localhost:PORT` to
`demo verify`. Use `--dir` there too when using a custom demo directory.

## Guided device-style provisioning

```powershell
.\qkd-stub.exe configure
```

The wizard asks for KME IDs and the listening address, generates a local private
key and CSR (or imports an existing key/certificate), provisions or imports a PSK,
and helps configure client CA trust and SAE identities. You can leave the CA,
PSK, and SAE steps pending, obtain a CA-signed certificate, then rerun the wizard.
An incomplete saved setup is normal; `check` reports what remains to be done.
Existing keys, PSKs, and SAE entries are preserved. To change an existing SAE,
remove it explicitly and re-add it; keep numeric codes stable while key IDs exist.

The default configuration is `qkd-stub-data/config.toml`. Select another with
`--config FILE`, before or after the subcommand. It is printed when loaded.
Paths stored **inside the configuration** are resolved relative to the
configuration file, not the working directory. Paths supplied on the command
line are relative to the working directory. No environment-variable expansion
or system-wide configuration discovery occurs.

## Scriptable provisioning

Create a saved configuration without prompting:

```powershell
.\qkd-stub.exe configure --non-interactive --kme-id KME-A --peer-kme-id KME-B --listen 0.0.0.0:8443
.\qkd-stub.exe tls csr --dns kme-a.example.org --ip 192.0.2.10 --out server.csr.pem
```

CSR generation uses an ECDSA P-256 private key stored locally in PKCS#8 PEM.
Repeat `--dns` or `--ip` for multiple SANs; at least one is required. The CSR
requests server-authentication usage. Only send the CSR to your CA. This is a
software-stored private key, not a hardware-backed/non-exportable key.

An existing private key is reused. An existing CSR output is never overwritten;
use a new `--out` path for renewal. Without `--out`, the CSR is written as
`server.csr.pem` beside the configuration.

Have your CA sign the CSR, then install its response:

```powershell
.\qkd-stub.exe tls install signed-server.pem --chain intermediates.pem
.\qkd-stub.exe tls trust add client-ca.pem
.\qkd-stub.exe psk generate
```

The certificate input can itself contain a leaf-first PEM chain. Installation
checks the key match, validity, DNS/IP SAN presence, server usage, and supplied
chain order/signatures before atomically replacing the server certificate.
It does not establish trust in the server's CA: applications must trust that CA.
The `--chain` input is optional; include intermediates needed by your clients.
The separate `tls trust` bundle authenticates **client** certificates. Trust
inputs must be currently valid CA certificates; duplicate certificates are ignored.

Generate the PSK **once per endpoint pair**. Transfer `qkd-stub-data/shared.psk`
securely to the peer and run `psk import FILE` there instead of generating another.
Both commands refuse to overwrite an existing PSK. Imports require exactly 32
raw bytes; passwords, hex, and Base64 are not accepted. Existing configurations
can point to externally provisioned PSK and private-key files.

Register the same SAE IDs and codes at both endpoints:

```powershell
.\qkd-stub.exe cert inspect client-a.pem
.\qkd-stub.exe sae add A --code 1 --cert client-a.pem --selector 1
.\qkd-stub.exe sae add B --code 2
.\qkd-stub.exe check
.\qkd-stub.exe serve
```

Choose the appropriate selector number from `cert inspect`; `--selector` is
required when the certificate has multiple selectors. Inspection/extraction does
not establish trust or pin the certificate. Renewed certificates with the same
identity can match, subject to client CA validation. A remote-only SAE can omit
`--cert`. Configure B's local certificate identity at endpoint B. Adding a
duplicate SAE ID, numeric code, or normalized identity is rejected.

`check` reports PSK, certificate/key, trusted client CA, and SAE registry problems,
including missing local client identities. It exits nonzero for an incomplete
setup. It does not test listening-port availability, client trust in the server,
hostname agreement with a client's URL, or peer PSK/SAE agreement. `serve` performs
the same checks before starting. Saved-config serving always requires mTLS and
SAE authorization. Settings and credentials are loaded at startup; restart the
server after provisioning changes.

## Command reference

| Command | Purpose |
| --- | --- |
| `configure [--non-interactive]` | Create or resume saved configuration |
| `serve` | Start from saved configuration |
| `check` | Validate local setup |
| `tls csr --dns NAME / --ip ADDRESS [--out FILE]` | Generate/reuse private key and emit CSR |
| `tls install FILE [--chain FILE]` | Install the signed server certificate |
| `tls trust add FILE` | Add trusted client CAs |
| `tls trust list` | Inspect trusted CA certificates/fingerprints |
| `tls trust remove SHA256` | Remove a CA by fingerprint |
| `cert inspect FILE` | Show subject, issuer, validity, fingerprint, and numbered selectors |
| `psk generate` / `psk import FILE` | Provision the pair's shared secret |
| `sae add ID --code N [--cert FILE --selector N]` | Register a local or remote SAE |
| `sae list` / `sae remove ID` | Inspect or remove SAE entries |
| `demo init [--dir DIRECTORY]` | Generate a complete local test environment |
| `demo verify [--dir DIRECTORY] [--url-a URL --url-b URL]` | Test both running demo endpoints |

Every command supports `--help`. Only `configure` prompts; it requires a terminal
unless `--non-interactive` is set. Provision one configuration from one process
at a time. File writes are atomic, but a multi-step wizard/demo is resumable state,
not a single transaction. If demo creation fails, inspect the partial directory
and choose a new one for a retry.

New data directories are owner-only (0700) on Unix. On Windows they have a
protected, inheritable ACL granting access to the owner and SYSTEM. New Unix
files use 0600. Existing directories retain their permissions; choose a private
location for credentials. An endpoint running under another service account
needs appropriate access provisioned by its administrator.

The former flag-only server invocation (`--listen`, `--tls-cert`, ...,
`--no-sae-binding`, `--inspect-cert`) has been removed. All configuration comes
from the saved configuration; use `cert inspect FILE` instead of `--inspect-cert`.
