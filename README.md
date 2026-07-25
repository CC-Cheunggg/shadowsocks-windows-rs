# Shadowsocks Windows RS

A modern, MIT-licensed Windows Shadowsocks client built with Vue 3,
TypeScript, Tauri 2, and Rust.

The project is account-free and local-first. It does not include login,
registration, cloud accounts, telemetry, or copied code and visual assets from
`shadowsocks/shadowsocks-windows`.

> Project status: the current implementation covers the Rust configuration
> model and local persistence only. It does not establish real proxy
> connections.

## Implemented slice

- Versioned JSON configuration (`version: 1`)
- Shadowsocks server profiles with host, port, password, method, timeout,
  plugin, plugin options, group, and source
- An explicit cipher allowlist limited to `2022-blake3-chacha20-poly1305`,
  `chacha20-ietf-poly1305`, and `xchacha20-ietf-poly1305`
- Direct, rule, and global connection-mode model
- DNS configuration model
- Placeholder TUN and Kill Switch configuration models
- Subscription-source model
- Field validation with password-safe error messages
- Atomic configuration writes in the Tauri application configuration directory
- Automatic backup and default recovery for malformed or invalid configuration
- Restricted Tauri commands for reading/saving configuration and adding,
  updating, deleting, or selecting a server
- Separated Rust modules for configuration models, persistence, and Tauri
  command boundaries
- Browser-only, visibly labelled preview data for frontend development
- Rust tests for defaults, validation, loading, saving, mutation persistence,
  and corrupt-file recovery
- Windows build and test workflow in GitHub Actions

## Configuration location

The desktop application resolves its configuration directory through Tauri's
`app_config_dir` API and stores the file as `config.json`. It never writes
configuration into the installation directory.

On Windows, the expected path is:

```text
%APPDATA%\dev.shadowsocks-windows-rs.app\config.json
```

If the file contains invalid JSON, uses an unsupported version, or fails
validation, the original file is moved alongside it using this pattern before
defaults are restored:

```text
config.corrupt-<timestamp>-<counter>.json
```

The configuration contains server credentials in plain JSON because
credential-vault integration is outside this slice. Restrict access to the
current Windows user and do not share configuration files.

## Development

Prerequisites:

- Node.js 22 or newer
- Current stable Rust toolchain
- Tauri 2 platform prerequisites

```sh
npm ci
npm run build
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo check --manifest-path src-tauri/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml
```

Run the browser preview:

```sh
npm run dev
```

Run the desktop shell on a supported development machine:

```sh
npm run tauri dev
```

Windows compilation is validated by
`.github/workflows/windows.yml` on pushes, pull requests, and manual dispatch.

## Tauri configuration commands

The Vue application can call only the following configuration operations:

- `get_config`
- `save_config`
- `add_server`
- `update_server`
- `delete_server`
- `select_server`

Paths are never accepted from the frontend. All writes target the single
application-owned configuration file, and passwords are not written to logs or
included in validation errors.

## Not implemented yet

- Shadowsocks protocol engine and real proxy connections
- Wintun installation or packet capture
- Windows Service
- Routing-rule execution
- DNS proxying
- Kill Switch enforcement
- Subscription fetching
- OS credential-vault integration

## License and dependency policy

Source code in this repository is available under the [MIT License](LICENSE).
The application does not accept GPL or AGPL runtime dependencies. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for direct dependency notices.
