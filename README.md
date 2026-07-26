# Shadowsocks Windows RS

A modern, MIT-licensed Windows network client built with Vue 3, TypeScript,
Tauri 2, and Rust.

The project is account-free and local-first. It does not include login,
registration, cloud accounts, telemetry, or copied code and visual assets from
`shadowsocks/shadowsocks-windows`.

> Current slice: a Windows x86_64 Wintun-to-DIRECT data path is implemented in
> Rust. `PROXY` remains deliberately unimplemented and fails closed. The code,
> unit tests, and isolated Wintun smoke test are not a substitute for the
> recorded real-Windows acceptance procedure described below.

## Fixed traffic model

This software never enables or modifies the Windows system proxy. An existing
system proxy can still change the connection target selected by a proxy-aware
application. A confirmed local-network system-proxy endpoint is captured by
Wintun first and then selected as a necessary DIRECT exception by the
user-space router.

All supported traffic follows the same pipeline, including `direct` mode:

```text
Windows applications
    -> Wintun capture
    -> IPv4/IPv6 parsing
    -> TCP session or UDP association
    -> DNS metadata and ConnectionMode routing
    -> DIRECT physical-interface socket
    -> destination
    -> session reconstruction
    -> Wintun injection
```

`direct`, `rule`, and `global` are routing policies applied only after Wintun
capture. They never mean “turn TUN off” or ask this software to enable or
rewrite the Windows system proxy.

The proxy exception is deliberately narrow. Each capture pass uses a single
bounded, cancellable worker to read WinHTTP/WinINet state without modifying it
and resolve concrete proxy names within one five-second total deadline. Raw
proxy strings and any embedded credentials are discarded before DNS
resolution. The resulting endpoints and pre-capture physical-network snapshot
are used for confirmation; the application does not exempt every private
address. It does not install a physical host route that would bypass Wintun.
Only the replacement DIRECT socket is bound to the original physical
interface. A `127.0.0.1` or `::1` proxy stays on loopback, while that local
proxy's subsequent external connections remain eligible for Wintun capture.

PAC/AutoConfig presence is detected without retaining its URL, but this slice
does not execute PAC JavaScript or infer its per-destination result. Therefore
only concrete endpoints from manual/protocol-specific or WinHTTP named-proxy
lists can receive the exact DIRECT exception.

For a remote system proxy, the router sees the proxy endpoint rather than the
website behind it. This slice does not parse HTTP CONNECT or SOCKS, so it
cannot apply domain rules to the proxy's final destination.

Route, interface, or unicast-address notifications invalidate the current
network epoch. The runtime blocks new DIRECT sockets, closes old workers, and
publishes that it is leaving `running` before restoring its owned network
state. It then re-runs proxy discovery and `GetBestRoute2` selection on the
settled physical network. Existing flows are intentionally interrupted instead
of being hot-migrated across adapters. Before publishing `running` for the new
epoch, it repeats bounded proxy capture and revalidates the cached physical,
management, and confirmed system-proxy route bindings after the change monitor
is active. It also takes a fresh route snapshot, excludes only rows matching
the exact Wintun ifIndex and LUID, rebuilds the complete external shadow-prefix
set, and compares it with the installed plan. It separately fingerprints every
external IPv4/IPv6 default route together with its route and interface metrics,
so a metric-only default selection change is also detected. Any difference
cleans the epoch and retries before `running`.

## DIRECT slice

The repository now contains:

- An official-Wintun dynamic API wrapper for adapter create/open, packet-session
  start, receive-ring reads, send-ring injection, and RAII cleanup.
- Volatile Windows `ActiveStore` split-default capture routes
  (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, and `8000::/1`), exact route-field
  matching, snapshot-derived shadow routes, pre-mutation adapter/route/DNS
  snapshots, stable LUID/GUID ownership checks, and an atomic write-ahead
  journal that durably records `Prepared` before each owned
  route/address/interface-setting mutation and `Applied` after native success.
- A nonblocking global recovery lease shared by desktop startup and recovery,
  plus cancellation gates before mutation-capable startup stages.
- External recovery treats the user-writable journal as an untrusted recovery
  request. Before any recorded network mutation, the application-local Wintun
  API must open the journal's adapter alias and prove its opened LUID/ifIndex
  plus fully resolved ifIndex/LUID/GUID/alias identity. Missing, unopenable, or
  mismatched adapters cause zero network mutation and retain the journal as
  `RecoveryRequired`.
- Even after that provenance proof, external recovery mutates only routes whose
  `route.interface` is the verified Wintun identity, plus that adapter's
  addresses and interface settings. It never mutates a journal-selected
  physical-interface route, including a management host exclusion. It may
  first restore safe Wintun-owned objects, but any such external route keeps
  the journal and returns `RecoveryRequired`.
- Normal epoch cleanup uses its trusted in-memory route transaction rather
  than replaying the journal, so it still removes physical management
  exclusions created by that live transaction. After exact rollback and
  `remove_owned`, it polls every 50 ms for at most five seconds until both
  alias and LUID are absent; only complete rollback and verified adapter
  absence permit journal removal.
- IPv4 and IPv6 parsing plus TCP/UDP checksums. Unsupported protocols,
  fragmented IPv4/IPv6, and unsupported IPv6 extension headers are counted and
  dropped rather than bypassing Wintun.
- A thin transparent TCP-session adapter over `smoltcp 0.13.1`, with bounded
  buffers, partial I/O, backpressure, FIN/EOF/RST handling, cancellation,
  timeouts, and reaping.
- Bounded five-tuple UDP associations with queue limits, idle expiry, and
  cancellation.
- DIRECT TCP and UDP sockets bound to the discovered physical source address
  and Windows interface index. The loop guard is registered after bind and
  before connect and matches transport plus both endpoints.
- Native route/interface/address notifications invalidate the active network
  epoch. New DIRECT operations fail closed, existing workers are cancelled,
  owned state is restored, and startup discovery—including system-proxy DNS,
  route, interface, gateway, and source selection—is rerun after a bounded
  debounce.
- Runtime-manager startup cleanup is generation-scoped: a late timeout or
  failure from startup A cannot cancel, join, or mark failed a newer startup B.
- UDP DNS capture and DIRECT forwarding, bounded expiring domain-to-IP metadata,
  A/AAAA/CNAME response parsing, custom or original-system resolver behavior,
  and TCP DNS handling when configured.
- Deterministic ordered routing rules for domain exact, domain suffix, IPv4
  CIDR, and IPv6 CIDR matching.
- Safe runtime state and counters that do not retain packet payloads.
- A Windows Actions workflow definition that compiles x86_64 MSVC code and
  runs an isolated Wintun receive/send-ring smoke test without changing the
  runner's default routes. Its first successful run must be linked before
  claiming Windows CI success.

The detailed dependency direction, platform limitations, and status matrix are
in [docs/WINTUN_DIRECT_ARCHITECTURE.md](docs/WINTUN_DIRECT_ARCHITECTURE.md).
The `/1` routes are supplemented by snapshot-derived child routes for
pre-existing more-specific LAN, host, VPN, and enterprise prefixes. Existing
host-prefix collisions are accepted only when the planned Wintun route is
proven to win by effective metric; configured management hosts remain explicit
physical exceptions.

## Connection modes in this slice

- `direct`: every supported ordinary TCP or UDP flow is routed to DIRECT after
  capture and session processing.
- `rule`: enabled rules are evaluated in configuration order and the first
  match wins. A DIRECT decision is usable. A PROXY decision returns
  `ProxyNotImplemented`, is dropped, and never falls back to DIRECT.
- `global`: loopback, explicitly configured management hosts, and confirmed
  local-network system-proxy endpoints are centralized auditable DIRECT
  exceptions. All other ordinary traffic selects PROXY and therefore fails
  closed in this slice.

The built-in global exclusions are centralized as `127.0.0.0/8` and `::1/128`.
Additional management exclusions must be explicit hosts (`/32` or `/128`).
System-proxy exceptions are exact endpoints that passed local-network route
validation; they never widen into a blanket LAN exemption. DNS servers,
arbitrary targets, and future proxy servers are not silently exempted.

## Protocol support

| Area | Current status |
| --- | --- |
| Wintun adapter/session/rings | Implemented for Windows x86_64; real-machine evidence is required |
| Default-routed IPv4/IPv6 capture | Implemented with split-default routes |
| Pre-existing route more specific than `/1` | Snapshot-derived shadow capture implemented with host-prefix priority validation |
| IPv4 unfragmented TCP/UDP | Implemented |
| IPv4 fragments | Unsupported; counted and dropped |
| IPv6 unfragmented TCP/UDP without extension headers | Implemented when IPv6 is enabled |
| IPv6 disabled in configuration | Still captured, then counted and dropped to prevent leakage |
| IPv6 fragments and extension headers | Unsupported; counted and dropped |
| ICMP, ICMPv6, ESP, GRE, and other IP protocols | Unsupported; counted and dropped |
| TCP | Session reconstruction, DIRECT forwarding, half-close, EOF/RST, timeout, cancellation, and backpressure implemented |
| UDP | Five-tuple DIRECT association, generation isolation, bounded packet/byte queues, response injection, timeout, and cancellation implemented |
| DNS over UDP | Captured and forwarded through DIRECT; custom forwarding requires a same-family resolver |
| DNS over TCP | Uses the captured TCP path when `tcp_fallback` is enabled; no independent retry from a truncated UDP response |
| DNS cache | Bounded expiring A/AAAA metadata with CNAME association from UDP responses; full DNS messages are not retained |
| DNS in `rule`/`global` | Recognized only after Wintun capture, then uses the centralized mandatory DIRECT resolver path before ordinary mode/rule PROXY decisions |
| Shadowsocks/PROXY | Not implemented; fails closed |

The packet builder does not perform IP fragmentation. It enforces the
configured TUN MTU, and Wintun send-ring pressure uses bounded retries before
counting a flow-local drop. The validated IPv6-safe MTU is applied to both
Wintun IP families and its previous values are journaled for exact rollback.
After each Wintun address create, startup polls native DAD state every 500 ms
for at most 12 seconds and proceeds only when the address is `Preferred`.

## Configuration and migration

The desktop application resolves its configuration directory through Tauri's
`app_config_dir` API and stores `config.json` there. It never writes
configuration into the installation directory.

On Windows, the expected path is:

```text
%APPDATA%\dev.shadowsocks-windows-rs.app\config.json
```

The current schema is version 2. A version-1 configuration is migrated
explicitly:

- when the migrated value passes version-2 validation, the original bytes are
  first preserved as
  `config.pre-migration-v1-<timestamp>-<counter>.json` and known version-1
  server fields, selection, passwords, DNS, TUN, subscriptions, and Kill Switch
  fields are retained;
- the formerly inert version-1 `tun.enabled` field is set to `true` because
  Wintun is the sole Windows traffic entry point;
- new routing, DNS, and TUN fields receive validated defaults.

Future/unknown versions fail without overwriting the file. Malformed or invalid
known-version files are preserved as
`config.corrupt-<timestamp>-<counter>.json` before defaults are written.

Version 1 allowed some values that version 2 now rejects, including MTUs below
1280, DNS hostnames instead of literal IP addresses, and a wider interface-name
character set. Such a file is currently preserved as a corrupt backup but its
active configuration falls back to defaults. This is a known migration
compatibility gap; active server/password preservation is not claimed for those
cases until explicit normalization/migration tests are added.

Server credentials are still plain JSON because Windows Credential Manager is
outside this slice. Restrict file access to the current Windows user and never
share the configuration or its backups.

Frontend commands do not accept arbitrary DLL or filesystem paths. Wintun is
loaded only by the fixed name `wintun.dll` with
`LOAD_LIBRARY_SEARCH_APPLICATION_DIR`. There is no current-directory, `PATH`,
or System32 fallback.

The restricted Tauri boundary exposes only:

- `get_config`
- `save_config`
- `add_server`
- `update_server`
- `delete_server`
- `select_server`
- `get_runtime_snapshot`
- `start_tunnel`
- `stop_tunnel`
- `recover_network`

Configuration writes target the single application-owned file. Recovery
targets the fixed application-owned journal; the frontend cannot select a
system file or DLL.

## Wintun binary acquisition

Only the official precompiled AMD64 DLL from Wintun 0.14.1 is used. The GPLv2
Wintun source is not compiled, copied, modified, or linked into this
repository.

On Windows:

```powershell
./scripts/fetch-wintun.ps1
```

The script downloads the fixed official ZIP, verifies both the archive and DLL
SHA-256 values, and places the DLL at
`src-tauri/resources/wintun/amd64/wintun.dll`. It also copies the archive's
original `LICENSE.txt` bytes to the ignored Windows resource directory. Both
generated files are intentionally ignored by Git.
`src-tauri/tauri.windows.conf.json` declares the intended resource mapping for
the verified DLL and the repository's review copy of the license. The Windows
workflow independently checks the DLL hash and outer Authenticode signature;
its acceptance artifact explicitly uses and verifies the original license
extracted from the pinned ZIP.
The official DLL has a WireGuard LLC outer code-signing signature and carries
the Microsoft-signed Wintun driver package used by the isolated smoke test.

Version, byte size, hashes, official URL, and license terms are recorded in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

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

Platform-independent packet, router, DNS-cache, session-lifecycle,
backpressure/cancellation, loop-detection, recovery-journal, and safe-error
tests run on macOS/Linux. Windows-specific route, socket-binding, Wintun, and
desktop-bundle behavior is compiled and exercised on Windows.

Development builds may use Tauri's default development protocol. Every
release/acceptance desktop binary must be built with the Cargo
`custom-protocol` feature so it serves packaged application assets rather than
depending on a development server.

Run the browser-only frontend preview:

```sh
npm run dev
```

The preview is visibly labelled and cannot operate Wintun. Run the desktop
shell on Windows only when the network-recovery prerequisites are satisfied:

```sh
npm run tauri dev
```

## Windows verification and build media

The Windows Actions workflow:

1. rejects Rust source that generates PowerShell, `pwsh`, `netsh`, `route.exe`,
   or `wmic` network commands;
2. builds the Vue frontend;
3. downloads the fixed Wintun ZIP and verifies the pinned ZIP and DLL hashes;
4. requires a valid approved Wintun Authenticode signature;
5. checks formatting and compiles/tests all Rust targets for
   `x86_64-pc-windows-msvc`;
6. builds the desktop app with `custom-protocol`, plus the recovery helper and
   smoke executable, in release mode with the MSVC CRT linked statically;
7. rejects any packaged EXE or DLL that imports a dynamic MSVC/UCRT DLL, so
   the acceptance machine does not need the Visual C++ x64 Redistributable;
8. creates a uniquely named temporary Wintun adapter;
9. assigns only TEST-NET addresses and two isolated `/32` routes through the
   native IP Helper/NetIO layer;
10. verifies UDP capture/response injection and a TCP SYN/SYN-ACK/ACK exchange;
11. always runs route/address cleanup and residual-adapter verification; normal
   Rust error unwinding also releases the session/owned adapter;
12. verifies the hosted runner's default-route fingerprint is unchanged; and
13. stages and uploads uniquely named acceptance media with `BUILD-INFO` and
    `SHA256SUMS`.

The isolated Actions smoke test intentionally does not install full-capture
routes and does not prove the complete DIRECT runtime.

A hard process termination can prevent normal adapter cleanup;
`--cleanup-only` removes the known isolated routes/address and the workflow
fails if a residual adapter is detected, but that mode does not itself delete
an arbitrary residual adapter.

The uploaded directory contains the desktop executable,
`network_recover.exe`, `wintun_smoke.exe`, application-local `wintun.dll`,
`WINTUN-LICENSE.txt`, `WINDOWS_RECOVERY.md`, `BUILD-INFO`, and `SHA256SUMS`.
The three Rust executables statically link the MSVC CRT and therefore do not
require a separate Visual C++ x64 Redistributable installation. Windows system
components and the separately verified application-local Wintun DLL remain
normal platform/runtime dependencies.
The workflow definition is not evidence that a run passed: Windows test media
must be taken only from a completed successful Actions run, and its
`SHA256SUMS` must be verified before upload to an acceptance VM. Do not copy an
ad hoc locally built executable to that VM. Preserve the Actions run URL and
artifact digest with the acceptance record.

Real-machine acceptance begins with read-only inspection in Microsoft Remote
Desktop. The Actions-built isolated Wintun smoke should then be repeated on the
test machine, followed by full DIRECT acceptance only after explicit approval,
RDP-peer exclusion, an out-of-band console, saved snapshots, and an automatic
rollback watchdog are confirmed. See:

- [docs/WINDOWS_RECOVERY.md](docs/WINDOWS_RECOVERY.md)
- [docs/WINDOWS_ACCEPTANCE_TEMPLATE.md](docs/WINDOWS_ACCEPTANCE_TEMPLATE.md)

An Actions success or a web page opening is not, by itself, acceptance. The
out-of-band recovery and action-time authorization gates documented in those
files still apply to full-route real-machine testing.

## Diagnostics

The runtime exposes only non-sensitive state and counters:

- `tun_rx_packets`
- `tun_tx_packets`
- `captured_tcp_sessions`
- `captured_udp_datagrams`
- `route_direct`
- `route_proxy`
- `system_proxy_detected`
- `route_direct_system_proxy`
- `direct_tcp_connections`
- `direct_udp_associations`
- `unsupported_packets`
- `dropped_packets`
- `loop_prevention_drops`

An optional process-local `flow_id` may correlate
`captured -> route decision -> outbound -> completed/failed`. Packet payloads,
passwords, keys, cookies, authorization headers, and complete DNS wire messages
must never be logged.

## Deliberately not implemented

- Shadowsocks handshake, framing, encryption, or decryption
- PROXY outbound
- Windows Service
- Kill Switch enforcement
- Windows system-proxy mode
- Subscription downloads
- Login, registration, users, cloud accounts, or telemetry
- Windows Credential Manager

The allowed Shadowsocks methods remain configuration metadata only in this
slice. Their future design constraints are retained in
[docs/PROTOCOL_ENGINE_DESIGN.md](docs/PROTOCOL_ENGINE_DESIGN.md).

## License

Source code in this repository is available under the [MIT License](LICENSE).
The application does not accept GPL or AGPL application dependencies. Wintun's
official unmodified prebuilt binary is redistributed separately under its
Prebuilt Binaries License; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
