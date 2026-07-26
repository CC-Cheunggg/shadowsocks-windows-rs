# Third-party notices

This project is licensed under the MIT License. Third-party components retain
their own licenses. The project policy rejects GPL and AGPL dependencies in
the application codebase.

## Wintun prebuilt binary

The Windows x86_64 application uses only WireGuard LLC's official, precompiled
Wintun DLL. The pinned DLL has an Authenticode-valid WireGuard LLC outer
signature and carries the Microsoft-signed Wintun driver package:

| Field | Recorded value |
| --- | --- |
| Component | Wintun |
| Version | 0.14.1 |
| Purpose | Windows layer-3 adapter and packet rings |
| Official archive | `https://www.wintun.net/builds/wintun-0.14.1.zip` |
| Archive SHA-256 | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| File inside archive | `wintun/bin/amd64/wintun.dll` |
| DLL size | 427,552 bytes |
| DLL SHA-256 | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| Binary license inside archive | `wintun/LICENSE.txt` |
| Binary license SHA-256 | `183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2` |
| Binary license | WireGuard LLC Wintun **Prebuilt Binaries License** |

The binary-license text is retained for source review at
`third_party/wintun/LICENSE.txt`. The pinned archive's original
`wintun/LICENSE.txt` bytes are extracted during the verified Windows build and
staged as `WINTUN-LICENSE.txt` with Windows media.
The repository review copy uses LF line endings; the recorded binary-license
hash applies to the archive's original CRLF bytes and to the staged artifact
copy, not to that line-ending-normalized review copy.
Among other terms, it allows the unmodified prebuilt DLL to be distributed
alongside software that uses only the permitted Wintun API, subject to its
restrictions and notices. Review the complete text before distribution.

`scripts/fetch-wintun.ps1` pins the URL and verifies the archive, AMD64 DLL,
and original-license hashes before copying the DLL and license into the ignored
build-resource directory. The DLL must never be accepted solely because its
filename or version string matches.

Windows CI additionally requires `Get-AuthenticodeSignature` to report
`Valid`, records the approved signer subject, copies the DLL only beside the
release executables, and verifies the pinned DLL hash again in the final
artifact. Runtime loading is limited to the fixed application-directory name
`wintun.dll`; there is no System32, current-directory, `PATH`, or
frontend-selected path fallback. The isolated Wintun smoke test must
successfully load the bundled driver before the artifact is uploaded.

Wintun source code is GPLv2, but this project does **not** compile, copy,
modify, translate, or redistribute that source. It uses only the official
unmodified prebuilt DLL through the published API and under the separate
Prebuilt Binaries License. The binary license must not be described as MIT.

## Direct Rust dependencies

Exact resolved versions and registry checksums are authoritative in
`src-tauri/Cargo.lock`. Direct Rust dependencies relevant to this slice include:

| Component | Locked version | Purpose | License |
| --- | ---: | --- | --- |
| `smoltcp` | 0.13.1 | User-space IPv4/IPv6 TCP state machine and bounded TCP socket buffers | 0BSD |
| `windows-sys` | 0.61.2 | Windows API bindings for Wintun loading, native route/address management, sockets, read-only system-proxy discovery, files, and synchronization | MIT OR Apache-2.0 |
| `tauri` | 2.11.5 | Desktop runtime | Apache-2.0 OR MIT |
| `serde` | 1.0.229 | Serialization framework | MIT OR Apache-2.0 |
| `serde_json` | 1.0.151 | JSON serialization | MIT OR Apache-2.0 |
| `thiserror` | 2.0.19 | Rust error definitions | MIT OR Apache-2.0 |

`smoltcp` is used as a thin, direct dependency rather than copying or
hand-writing a complete TCP implementation. It owns TCP sequence numbers,
retransmission, windows, FIN/RST state, and protocol timers; project code owns
the Wintun/session/outbound adaptation and resource limits.

Transitive dependency versions and license texts must be audited before each
release. A lockfile entry or SPDX identifier does not replace distribution of
license text when a dependency's license requires it.

## Frontend and build dependencies

| Component | Purpose | License |
| --- | --- | --- |
| Vue | User interface framework | MIT |
| Vue Router | Client-side routing | MIT |
| Pinia | Vue state management | MIT |
| Vite | Frontend build tooling | MIT |
| TypeScript | Type checking and language tooling | Apache-2.0 |
| Tauri CLI and Tauri Build | Desktop build integration | Apache-2.0 OR MIT |

Exact JavaScript versions are recorded in `package-lock.json`.

## Reference-only projects

The GPLv3 `shadowsocks/shadowsocks-windows` project may be consulted only for
observable compatibility research and interoperability testing. Its source is
not included, translated, linked, or incorporated into this MIT-licensed
repository.

The project does not depend on or copy `shadowsocks-rust`, nor does it copy
another tun2socks implementation. Future protocol and networking code must be
independently implemented from published specifications and permissively
licensed library APIs. Reference-only projects are not application
dependencies and do not contribute source code to this repository.

## Artwork

The application icon uses the classic Shadowsocks logo shape with a modified
color treatment and background. The original Shadowsocks logo is attributed to
Clowwindy and distributed under the Apache License 2.0:

https://commons.wikimedia.org/wiki/File:Shadowsocks-Logo.svg
