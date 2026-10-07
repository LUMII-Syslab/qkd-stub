# Distribution (proposal)

Status: **proposed, not implemented.** How to ship `qkd-stub` so testers can
install and run it without a Rust or Python toolchain. Complements the CLI
subcommands in [cli-subcommands.md](cli-subcommands.md).

## GitHub Releases

The baseline. A tag-triggered (`v*`) workflow builds a release binary per
platform and attaches it to the release. This is also the download source that
package managers point at, so the asset URLs must be versioned and stable.

```
qkd-stub-<version>-x86_64-pc-windows-msvc.zip
  qkd-stub.exe
  start.bat
  examples/sae-map.toml
  README.md
qkd-stub-<version>-x86_64-unknown-linux-gnu.tar.gz
  qkd-stub
  start.sh
  examples/sae-map.toml
  README.md
```

With `init` / `demo` folded into the binary, the extracted release needs no
Python and no OpenSSL.

## winget

winget is not a hosting service; it is a catalog of YAML manifests in the
`microsoft/winget-pkgs` repository. Publishing means opening a PR that adds the
manifest. GitHub Releases is an accepted `InstallerUrl` as long as it is the
versioned asset, HTTPS, and direct (no redirector).

Requirements that matter here:

- The repository now requires **multi-file manifests** (`version`, `defaultLocale`,
  `installer`) under
  `manifests/<letter>/<Publisher>/<Package>/<version>/`, with a unique
  `PackageIdentifier` such as `LUMII-Syslab.qkd-stub`.
- **`InstallerType: portable`** is the natural fit for a single-file CLI:

  ```yaml
  InstallerType: portable
  InstallerUrl: https://github.com/LUMII-Syslab/qkd-stub/releases/download/v0.4.0/qkd-stub.exe
  InstallerSha256: <sha256>
  Commands: [qkd-stub]
  ```

  If the release bundles `start.bat` and `examples/`, use a zip with
  `NestedInstallerType: portable` instead.
- The installer must install and uninstall unattended on every architecture it
  claims. Portable installers need no silent switches.

Submission and validation:

- Add the manifest, run `winget validate --manifest <path>`, test in Windows
  Sandbox (`Tools/SandboxTest.ps1` or `winget install --manifest`), then open the
  PR.
- Automated validation scans the binary with several antivirus engines, runs a
  sandbox install/uninstall, then a moderator reviews manually. Labels such as
  `Binary-Validation-Error`, `Validation-VCRuntime-Dependency` and
  `Error-Hash-Mismatch` indicate what to fix.
- The first submission is a manual PR. Later versions can be automated with
  `wingetcreate update`, [Komac](https://github.com/russellbanks/Komac), or the
  `vedantmgoyal2009/winget-releaser` GitHub Action triggered on release.

Caveats:

- **winget does not bypass SmartScreen.** An unsigned `.exe` still warns on first
  run. Code signing is a separate decision and cost.
- **VCRuntime dependency.** winget has a `Validation-VCRuntime-Dependency`
  failure label, so either build with `+crt-static` or declare the dependency.
  This makes the static-build question in [cli-subcommands.md](cli-subcommands.md)
  operationally relevant.
- **Antivirus false positives.** Small Rust binaries are occasionally flagged as
  potentially unwanted applications by one of the scan engines. Low risk, but it
  can block a submission until resolved.

## Scoop and Chocolatey

Lighter alternatives if raw install convenience matters more than discovery:

- **Scoop**: a self-hosted bucket (a small JSON manifest per version in this
  repository or a companion one). No external review, no AV gate, and updates can
  be automated directly from the release workflow. Easiest to maintain.
- **Chocolatey**: a community package repository, closer to winget in process.

## Recommended order

1. Tag-triggered GitHub Release with the zip/tarball above.
2. Scoop bucket generated from the release (cheapest automation).
3. winget manifest once the release is stable and the binary is static or the
   runtime dependency is declared.

## Open questions

- Static (`+crt-static`) Windows build, or declare the VC++ runtime dependency?
- Sign the release binaries, or accept the SmartScreen warning?
- Bundle the `.bat` helpers and `examples/` in the zip, or ship the bare `.exe`
  and rely on `init` / `demo`?
