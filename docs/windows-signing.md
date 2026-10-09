# Windows signing and releases

`.github/workflows/windows-release.yml` runs the Windows test suite, builds the
x64 MSVC release executable with `Cargo.lock`, signs it using Azure Artifact
Signing (formerly Trusted Signing), and checks the signature, timestamp and
expected institute publisher before uploading. It also runs the signed binary's
`--version`, `demo init`, and `check` commands and calculates its SHA-256 checksum
after signing. The release statically links the C runtime so users do not need
to install the Visual C++ redistributable.

## One-time configuration

Signing uses a dedicated Microsoft Entra app, `qkd-stub-github-signing`, with
OpenID Connect (OIDC). GitHub stores only non-secret configuration variables;
no client secret is needed.

1. In `LUMII-Syslab/qkd-stub`, create a GitHub environment named **release**.
   Restrict its deployment branches and tags to branch `main` and tags `v*`.
   Add required reviewers if releases need approval; restrict who can create
   release tags using repository rulesets.
2. In Microsoft Entra ID, open the `qkd-stub-github-signing` app registration.
   Under **Certificates & secrets → Federated credentials → Add credential**,
   select **Other issuer** and use an explicit subject (not a matching expression).
   Name the credential `qkd-stub-release`. The exact values are:

   - Issuer: `https://token.actions.githubusercontent.com`
   - Subject: `repo:LUMII-Syslab@14790263/qkd-stub@1405879590:environment:release`
   - Audience: `api://AzureADTokenExchange`

   This repository uses GitHub's immutable OIDC subject format, which includes
   owner and repository IDs. The older name-only subject will fail with
   `AADSTS700213`. See [Microsoft's migration guide](https://learn.microsoft.com/en-us/entra/workload-id/workload-identities-github-immutable-subjects).

   Grant the app's service principal **Artifact Signing Certificate Profile
   Signer** on the intended certificate profile. The Azure portal may still show
   the former Trusted Signing name.
3. In the GitHub `release` environment, set these **variables**:

   | Variable | Value |
   | --- | --- |
   | `AZURE_CLIENT_ID` | `7dadb396-f104-4459-b5ba-9db9c81ea3a4` |
   | `AZURE_TENANT_ID` | `56bebab0-1dd7-4b53-8589-dc4a93534d66` |
   | `ARTIFACT_SIGNING_ENDPOINT` | `https://neu.codesigning.azure.net/` |
   | `ARTIFACT_SIGNING_ACCOUNT` | Your Azure signing account name |
   | `ARTIFACT_SIGNING_PROFILE` | Your certificate profile name |

   No client secret or subscription ID is needed: the workflow uses tenant-level
   Azure login with `allow-no-subscriptions: true`. The expected publisher is
   `CN=Latvijas Universitātes Matemātikas un informātikas institūts`; if choosing
   a profile with another publisher, update `SIGNER_SUBJECT` in the workflow.

See [Azure's OIDC signing setup](https://github.com/Azure/artifact-signing-action/blob/main/docs/OIDC.md)
and [GitHub's secret scopes](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets).

## Build and download

- **Manual build:** Actions → Signed Windows executable → Run workflow on `main`.
  Download the `qkd-stub-windows-x64-signed` artifact from the successful run.
  It contains `qkd-stub.exe` and `qkd-stub.exe.sha256` and expires after 30 days.
- **Versioned release:** push a tag matching `Cargo.toml`, for example `v0.4.0`
  when the package version is `0.4.0`. The workflow creates a **draft** GitHub
  Release with those two files attached. Review the notes and publish it from
  [Releases](https://github.com/LUMII-Syslab/qkd-stub/releases). Mark preview
  versions as prereleases before publishing. The [Linux workflow](linux-release.md)
  adds its assets to the same draft, whichever workflow finishes first. Release
  assets remain until deleted and provide public downloads for this public
  repository.

Signing is limited to this repository's `main` branch and `v*` tags and is never
triggered by pull requests. A failed login, signature check or timestamp check
prevents uploads; there is no unsigned fallback. A rerun for a tag with an existing
release fails at asset upload rather than replacing its assets.

Verify a downloaded executable in PowerShell:

```powershell
Get-AuthenticodeSignature .\qkd-stub.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
Get-FileHash .\qkd-stub.exe -Algorithm SHA256
Get-Content .\qkd-stub.exe.sha256
```

The artifact is a standalone command-line executable, not an installer. It
includes `configure`, CSR generation, certificate/PSK/SAE provisioning, and
`demo init` / `demo verify`; no external setup tools are required. Credentials
are generated locally; no private keys or PSKs are packaged. See
[standalone provisioning](setup.md).
