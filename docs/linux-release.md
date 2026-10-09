# Linux releases

`.github/workflows/linux-release.yml` runs the Ubuntu test suite, then builds a
**static musl** executable for x86-64 with `Cargo.lock`. It has no glibc or OpenSSL
dependency and runs on any x86-64 Linux distribution. Before upload, the workflow
checks that the binary is statically linked, runs `--version`, and starts a
two-endpoint demo that must pass `demo verify`.

Assets, attached to the same draft GitHub Release as the Windows executable:

- `qkd-stub-x86_64-linux.tar.gz` containing `qkd-stub` (the tarball preserves the
  execute bit)
- `qkd-stub-x86_64-linux.tar.gz.sha256`

Unlike Windows, there is no Authenticode-style signature. Instead the tarball has a
[GitHub build attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
tying it to this repository, workflow, and commit. The checksum only detects
corruption: it is hosted next to the file it covers.

Verify and install:

```sh
sha256sum -c qkd-stub-x86_64-linux.tar.gz.sha256
gh attestation verify qkd-stub-x86_64-linux.tar.gz --repo LUMII-Syslab/qkd-stub
tar -xzf qkd-stub-x86_64-linux.tar.gz
./qkd-stub demo init
```

## Releasing

Push a `v*` tag matching `Cargo.toml`. The Windows and Linux workflows run
independently; whichever finishes first creates the **draft** release and the other
adds its assets. Review and publish the draft from
[Releases](https://github.com/LUMII-Syslab/qkd-stub/releases) only after both sets
of assets are present. A rerun for an existing tag fails at upload rather than
replacing assets. Manual runs (`workflow_dispatch`) on `main` only produce the
`qkd-stub-linux-x86_64` Actions artifact, kept for 30 days.

Unlike the Windows job, this job uses no `release` environment, so no approval
gate applies. Restrict who can create `v*` tags with repository rulesets.
