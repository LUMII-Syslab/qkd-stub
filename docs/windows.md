# Windows quickstart

The downloaded executable can provision and test endpoints on its own. No WSL,
Bash, OpenSSL, Python, or Rust is needed. GitHub Actions tests the native Windows build and all
integration tests on Windows Server 2022, alongside Ubuntu 24.04.

## Signed executable

Download `qkd-stub.exe` and its SHA-256 checksum from
[GitHub Releases](https://github.com/LUMII-Syslab/qkd-stub/releases).
In PowerShell, from the directory containing the executable:

```powershell
.\qkd-stub.exe demo init
.\qkd-stub.exe --config qkd-demo/a.toml serve
```

Run `.\qkd-stub.exe --config qkd-demo/b.toml serve` in a second terminal and
`.\qkd-stub.exe demo verify` in a third. This checks both directions over mTLS.
Stop with Ctrl-C or Ctrl-Break.

For your own CA, use `.\qkd-stub.exe configure` to generate a local private key
and CSR. Resume after CA signing, then use `check` and `serve`.
See [standalone provisioning](setup.md) for scriptable commands, certificate
installation, trusted client CAs, PSK import, SAE management, and file permissions.

Maintainers: see [Windows signing and releases](windows-signing.md) for Azure
setup, manual builds and release storage.

## Developer prerequisites (source builds and tests)

The remaining examples use **Command Prompt (cmd.exe)** from the repository root.

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

## Build

```bat
cargo build --release --locked
```

Run the built executable exactly as the downloaded one, starting with
`target\release\qkd-stub.exe demo init`. The `scripts\gen-*.bat` helpers create
OpenSSL-based test credentials for the Python test suite only; they use the same
Python implementation as the Linux shell scripts. Paths containing spaces must be
quoted. Existing credentials are preserved: only `gen-certs.bat` accepts
`--force` to explicitly replace the server PKI.

## Verify Windows support

```bat
scripts\check-windows.bat
```

This runs formatting, Clippy, Rust tests (including executable-only provisioning
and demo verification), a debug build, setup-script checks, and
all three integration suites. It starts its own temporary endpoints and checks
TLS 1.2/1.3, client-certificate authorization, encrypted ID derivation, both
communication directions, restarts and graceful shutdown. It does not use or
replace your credentials in `pki`.

To check two already-running demo endpoints, use
`target\release\qkd-stub.exe demo verify`.
