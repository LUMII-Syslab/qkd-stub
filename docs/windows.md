# Windows quickstart

Run the commands below in **Command Prompt (cmd.exe)** from the repository root.
No WSL or Bash is required. GitHub Actions tests the native Windows build and all
integration tests on Windows Server 2022, alongside Ubuntu 24.04.

## Signed executable

Once a release is published, download `qkd-stub.exe` and its SHA-256 checksum from
[GitHub Releases](https://github.com/LUMII-Syslab/qkd-stub/releases).
You can skip Rust and Visual Studio Build Tools when using this executable.
Place it in `target\release\qkd-stub.exe` in a matching source checkout to use
the commands below, and skip `cargo build`. The scripts, examples, Python and
OpenSSL are still needed to generate the test credentials shown here.

Maintainers: see [Windows signing and releases](windows-signing.md) for Azure
setup, manual builds and release storage.

## Prerequisites

- Rust via [rustup](https://rustup.rs/), using the MSVC toolchain.
- Visual Studio Build Tools with **Desktop development with C++**, including the
  Windows SDK. See [Microsoft's Rust setup guide](https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup).
- Python 3.11 or newer, available as `python` on PATH.
- OpenSSL 3, available as `openssl` on PATH. This is a command-line prerequisite
  for generating test certificates and running the tests; the server uses Rustls.

Open a new terminal after installation and check:

```bat
rustc --version
cargo --version
python --version
openssl version
```

CI uses tools available on GitHub's Windows runner. It verifies builds, scripts
and behavior, not installation on a blank Windows machine.

## Build and create test credentials

```bat
cargo build --release --locked
scripts\gen-certs.bat pki localhost 127.0.0.1 ::1
scripts\gen-psk.bat pki\shared.psk
scripts\gen-client-cert.bat pki client-a
scripts\gen-client-cert.bat pki client-b urn:qkd:sae:B
```

The batch files use the same Python implementation as the Linux shell scripts.
Paths containing spaces must be quoted. Existing credentials are preserved:
only `gen-certs.bat` accepts `--force` to explicitly replace the server PKI.
Generate the PSK once and share that same file between both servers. Windows
files inherit the parent directory's ACLs; keep private keys and the PSK in a
directory accessible only to the intended account.

## Start the two endpoints

In the first terminal:

```bat
target\release\qkd-stub.exe --listen 127.0.0.1:8443 ^
  --tls-cert pki\server.crt --tls-key pki\server.key ^
  --psk-file pki\shared.psk ^
  --tls-client-ca pki\ca.crt --sae-map examples\sae-map.toml ^
  --kme-id KME-A --peer-kme-id KME-B
```

In a second terminal, from the same repository directory:

```bat
target\release\qkd-stub.exe --listen 127.0.0.1:8444 ^
  --tls-cert pki\server.crt --tls-key pki\server.key ^
  --psk-file pki\shared.psk ^
  --tls-client-ca pki\ca.crt --sae-map examples\sae-map.toml ^
  --kme-id KME-B --peer-kme-id KME-A
```

Stop either server with Ctrl-C or Ctrl-Break. The APIs and certificate mappings
are the same as on Linux. The PEM client-certificate curl examples in the main
README require an OpenSSL-compatible curl build; Windows' bundled Schannel curl
can handle certificates differently. The Python tests below avoid that dependency.

## Verify Windows support

```bat
scripts\check-windows.bat
```

This runs formatting, Clippy, Rust tests, a debug build, setup-script checks, and
all three integration suites. It starts its own temporary endpoints and checks
TLS 1.2/1.3, client-certificate authorization, encrypted ID derivation, both
communication directions, restarts and graceful shutdown. It does not use or
replace your credentials in `pki`.

For two already-running endpoints configured with `--no-sae-binding`, use:

```bat
scripts\smoke-test.bat pki\ca.crt https://127.0.0.1:8443 https://127.0.0.1:8444
```

That smoke test deliberately targets the unrestricted test mode. The full
integration suite also covers the default certificate-authenticated mode.
