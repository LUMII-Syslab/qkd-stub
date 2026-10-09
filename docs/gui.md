# Dashboard (`qkd-stub-gui`)

`qkd-stub-gui` is a desktop window for inspecting a saved configuration and
watching client activity. It is a second executable next to the command-line
`qkd-stub`; the CLI is unchanged and remains the only way to provision.

The Windows release includes both signed executables. The dashboard is not
part of the Linux release or of default builds: it needs the `gui` Cargo feature.

```sh
cargo build --release --locked --features gui   # target/release/qkd-stub-gui
```

## Running

Double-click `qkd-stub-gui.exe`, or pass a configuration:

```powershell
.\qkd-stub.exe demo init
.\qkd-stub-gui.exe --config qkd-demo/a.toml --start
```

| Option | Meaning |
| --- | --- |
| `--config FILE` | Saved configuration. Default `qkd-stub-data/config.toml`, relative to the working directory, as for the CLI. |
| `--start` | Start serving immediately if all local checks pass. |

The window has a path field and **Reload** (disabled while the server runs),
plus four tabs:

- **Status:** listen address, KME IDs, file paths, the same four checks as
  `qkd-stub check`, and Start/Stop.
- **SAEs:** SAE IDs, codes, and certificate identity selectors.
- **Certificates:** server certificate chain and trusted client CAs (subject,
  issuer, validity, SHA-256).
- **Activity:** live request log: time (UTC), authenticated SAE, method, route,
  status, and duration.

## Behavior and limits

- **The dashboard hosts the server.** Start serves the configuration inside the
  GUI process, using the same code as `qkd-stub serve`. Closing the window stops
  it. It cannot show activity of a separately started `qkd-stub serve`.
- **Do not run both** on the same listen address.
- **Activity is in-memory:** the latest 1000 requests since the window opened.
  The request log shows the matched route template (for example
  `/api/v1/keys/{sae}/enc_keys`), never query strings, request bodies, key IDs,
  or key material. Unauthenticated requests show as `unauthenticated`.
- **Failed TLS handshakes are not shown** (for example a client whose certificate
  is not signed by a trusted CA). Those connections end before any HTTP request.
- **Secrets are never displayed.** The window shows file paths and certificate
  fingerprints, not the PSK or private keys.
- **Read-only configuration.** To change certificates, CAs, PSK or SAEs use the
  CLI (see [standalone provisioning](setup.md)), then press **Reload**.
- **Graphics:** the window uses OpenGL 2 or later. Sessions that only offer
  basic software rendering (some virtual machines and remote desktops) may be
  unable to open it; an error dialog is shown, and the CLI remains available.
- On Windows the GUI has no console, so startup errors appear in a dialog.
