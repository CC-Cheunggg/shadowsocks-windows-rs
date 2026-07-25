# Third-party notices

This project is licensed under the MIT License. Third-party components retain
their own licenses. The project policy rejects GPL and AGPL dependencies in the
application codebase.

The current direct application and build dependencies include:

| Component | Purpose | License |
| --- | --- | --- |
| Vue | User interface framework | MIT |
| Vue Router | Client-side routing | MIT |
| Pinia | Vue state management | MIT |
| Vite | Frontend build tooling | MIT |
| TypeScript | Type checking and language tooling | Apache-2.0 |
| Tauri and Tauri Build | Desktop runtime and build integration | Apache-2.0 and MIT |
| Serde | Rust serialization framework | Apache-2.0 and MIT |
| serde_json | JSON serialization | Apache-2.0 and MIT |
| thiserror | Rust error definitions | Apache-2.0 and MIT |
| windows-sys | Windows atomic file replacement bindings | Apache-2.0 and MIT |

Transitive dependency license texts and exact versions are recorded by the
package lockfiles and must be audited before each release.

No Wintun binaries, Windows Service implementation, or Shadowsocks protocol
engine are included in the current project slice.

The application icon uses the classic Shadowsocks logo shape with a modified
color treatment and background. The original Shadowsocks logo is attributed to
Clowwindy and distributed under the Apache License 2.0:

https://commons.wikimedia.org/wiki/File:Shadowsocks-Logo.svg
