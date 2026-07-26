# Protocol engine design and implementation status

This document records the fixed architecture shared by the implemented Wintun
DIRECT slice and a future Shadowsocks PROXY slice. It does not claim that
Shadowsocks framing, encryption, or the PROXY outbound exists.

For the concrete DIRECT implementation and support matrix, see
[WINTUN_DIRECT_ARCHITECTURE.md](WINTUN_DIRECT_ARCHITECTURE.md).
All Windows implementation work is also governed by the normative
[Windows native API policy](WINDOWS_NATIVE_API_POLICY.md): when a documented
Win32/WinSock/IP Helper API exists, compiled code must not replace it by
spawning PowerShell or another command-line network tool.

## Current implementation status

| Layer | Status |
| --- | --- |
| Windows Wintun adapter/session/rings | Implemented in code; first successful Windows CI and real-machine evidence are tracked separately |
| IPv4/IPv6 split-default, shadow routes, and rollback | Implemented with host-prefix priority checks, stable identity, and recorded ownership |
| IPv4/IPv6 TCP/UDP parsing and checksums | Implemented for the documented unfragmented subset |
| TCP session handling | Implemented through a thin `smoltcp 0.13.1` adapter |
| UDP association handling | Implemented |
| DNS DIRECT forwarding/cache | Implemented within the documented limits |
| `direct`/`rule`/`global` routing decisions | Implemented |
| DIRECT physical-interface outbound | Implemented |
| Shadowsocks handshake and protocol framing | Not implemented |
| Shadowsocks encryption/decryption | Not implemented |
| PROXY outbound | Typed placeholder only; fails closed |

The application never enables or modifies the Windows system proxy. Existing
system-proxy configuration can nevertheless change the endpoint selected by a
proxy-aware application. All three connection modes remain post-capture
routing policies.

## Fixed product model

- The Windows client always captures network traffic through Wintun.
- The client does not enable, rewrite, or use the Windows system proxy as an
  alternative traffic entry point or outbound fallback.
- A confirmed local-network system-proxy endpoint remains inside the Wintun
  path and is then selected as a necessary DIRECT exception by the user-space
  router.
- `direct`, `rule`, and `global` select routing behavior after capture. They do
  not enable or disable traffic capture.
- `direct` still traverses Wintun, the session/association layer, DNS metadata,
  and the router.
- The future protocol engine may support exactly these configured methods:
  - `2022-blake3-chacha20-poly1305`
  - `chacha20-ietf-poly1305`
  - `xchacha20-ietf-poly1305`
- These method names are configuration metadata in the current DIRECT slice;
  none is currently operational.
- The application remains account-free and local-first. Protocol work must not
  introduce login, registration, cloud accounts, telemetry, or credential
  manager integration.

## Traffic pipeline

The implemented routing boundary is:

```text
Windows applications
    -> Wintun capture
    -> IP/TCP/UDP parsing and session handling
    -> DNS metadata and routing decision
    -> DIRECT outbound OR PROXY boundary
```

The current DIRECT branch continues:

```text
DIRECT
    -> physical-interface-bound native TCP/UDP socket
    -> destination
    -> return bytes/datagram
    -> TCP/UDP and IP reconstruction
    -> Wintun injection
```

The future PROXY branch will continue:

```text
PROXY
    -> destination-address encoding
    -> Shadowsocks framing/encryption
    -> physical-interface-bound transport to selected server
    -> decrypt/verify response
    -> session reconstruction
    -> Wintun injection
```

All three modes use the same capture pipeline:

- `direct`: route all supported ordinary sessions through DIRECT.
- `rule`: evaluate deterministic ordered rules and choose DIRECT or PROXY.
- `global`: choose PROXY except for centrally defined mandatory exclusions.

Because PROXY is not implemented, every PROXY decision currently returns
`ProxyNotImplemented` and fails closed. It never falls back to DIRECT.

## Auditable exclusions

The current built-in global DIRECT exclusions are centralized as:

```text
127.0.0.0/8
::1/128
```

Explicit management peers may be added as host CIDRs (`/32` or `/128`) and
become both route-plan and global-router exclusions. This supports a protected
RDP/control path during approved testing.

Read-only WinHTTP/WinINet state identifies manual, protocol-specific, and
WinHTTP-default named-proxy endpoints and detects AutoConfig/PAC presence.
Each capture pass and its sequential DNS resolution run in one bounded,
cancellable worker under a single five-second total deadline; raw strings and
embedded credentials are discarded before DNS resolution. This slice does not
execute PAC JavaScript, so PAC-only dynamic results are not granted an
exception. A concrete named candidate becomes DIRECT only after the
pre-capture network snapshot and `GetBestRoute2` confirm that the exact
endpoint is reachable through the original local network. It is not converted
into a physical host route: the application packet first enters Wintun, and
only the replacement DIRECT socket binds the physical interface. Private
address ranges are not exempted merely for being private.

Loopback proxy endpoints stay on loopback. A local proxy's subsequent external
connections remain subject to Wintun capture. For a remote proxy connection,
the router sees the proxy endpoint, not the final website. HTTP CONNECT and
SOCKS parsing are outside this slice, so domain routing cannot inspect the
destination hidden behind such a proxy.

Native route, interface, and unicast-address notifications define a network
epoch. A notification invalidates every DIRECT clone immediately, interrupts
existing workers, and moves runtime state out of `running` before restoring the
epoch's owned routes/address/interface settings and removing the owned adapter.
After the runtime debounces, it repeats the complete snapshot, proxy
resolution, `GetBestRoute2`, router, and outbound construction sequence. It
registers the new monitor, repeats bounded proxy capture, and revalidates
cached physical, management, and confirmed system-proxy route bindings before
publishing `running`. It also snapshots routes again, excludes only the exact
current Wintun ifIndex+LUID generation, rebuilds the complete external
shadow-prefix set, and compares it with the installed plan. It also compares
all external IPv4/IPv6 default-route identities, gateways, route metrics, and
interface metrics with the pre-mutation fingerprint. A difference cleans the
epoch and retries. The design deliberately reconnects rather than hot-migrating
sockets with stale interface, source, or gateway state.

Runtime-manager startup cleanup carries a generation token. Timeout or failure
from startup A can cancel, join, retire, or publish failure only if A is still
the active generation; a late A cleanup cannot interfere with startup B.

The exclusion-reason vocabulary is centralized:

- management connection;
- local control;
- DIRECT DNS;
- confirmed local-network system proxy;
- future proxy server.

The current runtime installs only explicit management exclusions. It does not
silently exempt arbitrary LAN ranges, DNS servers, destinations, or a future
proxy server. Before a real full-capture test, the current RDP peer must be an
explicit host exclusion and an automatic rollback watchdog must be active.

When PROXY is implemented, the selected Shadowsocks server endpoint will need
an explicit physical-interface exclusion/binding so its transport cannot be
captured recursively. That exclusion must be resolved, bounded, audited, and
restored like current management exclusions.

## Module and dependency direction

The current dependency direction is:

```text
tun -> packet -> session -> DNS/router -> direct outbound
                                      -> proxy placeholder
```

The future extension is:

```text
tun -> packet -> session -> DNS/router -> direct outbound
                                      -> Shadowsocks outbound
                                           -> address/framing
                                           -> method-specific cipher modules
```

The concerns remain separate:

- Wintun owns packet capture and injection, not encryption.
- Packet modules own IP/TCP/UDP representation and checksums.
- Session handling owns TCP/UDP state, cancellation, and backpressure.
- DNS owns resolver forwarding and bounded name/address metadata.
- The router owns mode and ordered-rule decisions.
- DIRECT owns unencrypted physical-interface destination sockets.
- The future Shadowsocks outbound will own server transport and protocol
  framing.
- Future cipher modules will own key derivation, nonce handling, encryption,
  decryption, and authentication without knowing about Wintun.

Routing always occurs before the future encryption boundary.

## Current TCP-stack decision

The project uses `smoltcp 0.13.1` directly under the 0BSD license. It was
selected to avoid an unreviewed handwritten TCP state machine and owns TCP
sequence numbers, retransmission, windows, FIN/RST behavior, and timers.

Project code remains responsible for:

- translating complete Wintun IP packets into the IP-medium device;
- creating a bounded exact listener only for an initial captured SYN;
- exposing bounded reconstructed byte streams;
- coupling backpressure to DIRECT worker channels;
- mapping DIRECT EOF/error/cancellation to FIN or RST;
- timing out and reaping session resources; and
- returning generated packets through Wintun.

This choice does not import another tun2socks implementation or GPL/AGPL code.
Its version and license are recorded in `THIRD_PARTY_NOTICES.md`.

## Encryption boundary

Routing happens before Shadowsocks encryption. Only traffic selected for the
future PROXY outbound will be encoded and encrypted.

For future outbound PROXY traffic:

1. capture the original traffic;
2. recover the TCP byte stream or UDP datagram and destination;
3. apply the routing decision;
4. encode the destination and payload using the applicable Shadowsocks
   protocol;
5. encrypt and authenticate the Shadowsocks payload; and
6. send the ciphertext through a physical-interface-bound transport to the
   selected Shadowsocks server.

The inbound path will reverse these operations: receive ciphertext,
authenticate and decrypt it, restore proxied TCP/UDP data, update the session,
and return the result through Wintun.

Captured IP packets will not be encrypted verbatim. TCP is handled as a stream
and UDP as datagrams at the protocol boundary.

## Future protocol compatibility requirements

Behavioral compatibility includes more than selecting the same primitive. A
future implementation and tests must cover:

- key, salt, nonce, and authentication-tag sizes;
- password-to-master-key derivation where required by the selected protocol;
- subkey derivation and protocol context strings;
- TCP request framing, encrypted length fields, payload chunks, and chunk
  limits;
- nonce initialization, increment order, and exhaustion handling;
- UDP packet framing and per-packet cryptographic state;
- destination-address encoding;
- partial reads, coalesced reads, timeouts, EOF, authentication failure, and
  malformed input;
- replay protection wherever required by the applicable protocol;
- network switching and cancellation;
- selected-server route/binding changes without capture recursion; and
- connection cleanup without logging passwords or key material.

`2022-blake3-chacha20-poly1305` is a Shadowsocks 2022 protocol and must not be
implemented by merely substituting a cipher into the classic AEAD stream
format. Its identity/key handling, framing, headers, replay defenses, and time
requirements must follow the applicable Shadowsocks 2022 specification.

The two classic AEAD methods also require separate method metadata:

| Method | Key | Salt | Nonce | Tag |
| --- | ---: | ---: | ---: | ---: |
| `chacha20-ietf-poly1305` | 32 bytes | 32 bytes | 12 bytes | 16 bytes |
| `xchacha20-ietf-poly1305` | 32 bytes | 32 bytes | 24 bytes | 16 bytes |

These values alone are not a complete implementation specification. Before
implementation, the exact published specifications, RustCrypto APIs, dependency
versions/licenses, and independent test vectors must be recorded in the
protocol module documentation.

## Source and license boundary

This repository is MIT licensed and must not contain copied or translated GPL
or AGPL code.

The GPLv3 `shadowsocks/shadowsocks-windows` project may be used to understand
observable compatibility behavior and to run interoperability comparisons. It
must not be translated line by line, structurally reproduced, or used as the
source expression for code in this repository. Names, comments, class layout,
function decomposition, and control-flow expression must be independently
written.

The implementation must instead be derived from:

- published Shadowsocks protocol specifications;
- published cryptographic specifications;
- RustCrypto public APIs and compatible independent test vectors; and
- independently written interoperability tests.

The project must not add `shadowsocks-rust` as a dependency or copy its
implementation. It also must not copy another tun2socks project. An external
implementation may be used to observe expected network behavior only after its
licensing is understood and without copying source expression.

No GPL or AGPL application dependency may be introduced. Every new
cryptographic or networking dependency must have its exact resolved version,
purpose, and license recorded in `THIRD_PARTY_NOTICES.md` before merging.

Wintun is a special binary distribution boundary. This project uses only the
official unmodified prebuilt, Microsoft-signed Wintun 0.14.1 AMD64 DLL under
WireGuard LLC's Prebuilt Binaries License. It does not use the GPLv2 source.
The URL, ZIP hash, DLL hash/size, and exact license are recorded in
`THIRD_PARTY_NOTICES.md`.

## Security and logging

- Passwords, derived keys, plaintext payloads, and decrypted application data
  must not appear in logs or error messages.
- Packet payloads, cookies, authorization headers, and complete DNS wire
  messages are not diagnostics.
- Authentication failures must expose only safe protocol context.
- Secret-bearing buffers need explicit lifetime and zeroization decisions when
  cipher dependencies are selected.
- Configuration remains plain JSON in the current scope; Windows Credential
  Manager is explicitly out of scope.
- Cryptographic primitives must come from maintained, permissively licensed
  libraries. Do not implement ChaCha20, Poly1305, BLAKE3, HKDF, or hash
  primitives manually.
- Temporary numeric flow IDs may correlate capture, route, outbound, and
  completion/failure but must not encode destinations or secrets.
- A future PROXY transport must use the same physical-interface binding and
  loop protection as DIRECT.

## Current verification status

Platform-independent tests cover the parser/checksum, router, DNS cache,
session lifecycle, backpressure/cancellation, loop-detection, and safe-error
parts of the DIRECT slice.

The Windows workflow compiles/tests x86_64 MSVC code and performs an isolated
Wintun ring smoke test using only TEST-NET `/32` routes. It does not modify
default routes and therefore does not validate full capture. The release
desktop executable is built with Tauri's Cargo `custom-protocol` feature; a
development-protocol binary is not valid acceptance media.

At the time this implementation-status text was written, the first successful
run URL had not yet been recorded. Treat Windows CI as pending until that link,
commit, and artifact identity are added to the acceptance evidence.

Full DIRECT acceptance must use a successful Actions-built artifact in the
real Windows environment. It requires pre/post network snapshots, RDP
exclusion, an out-of-band console, a rollback watchdog, packet captures,
counters, three start/stop cycles, and verified recovery. See
[WINDOWS_RECOVERY.md](WINDOWS_RECOVERY.md).

The `/1` capture routes are supplemented with snapshot-derived child prefixes.
An existing `/32` or `/128` collision is accepted only when the effective
Wintun route plus interface metric is proven to outrank it; management host
exceptions remain physical by design. Formal proof that this behaves as
intended on the acceptance machine still belongs in the real-Windows evidence.

No statement in this document should be read as evidence that real Windows
acceptance has passed unless a completed acceptance record is linked.

## Next protocol slice

The next phase should add PROXY without changing the capture/session/router
semantics:

1. confirm and cite protocol specifications and compatible RustCrypto crates
   for all three configured methods;
2. document the classic AEAD and distinct Shadowsocks 2022 wire formats,
   including independent test vectors;
3. add separate modules for address encoding, key derivation, nonce management,
   TCP framing, UDP framing, and method implementations;
4. implement and test `chacha20-ietf-poly1305` first;
5. implement `xchacha20-ietf-poly1305` from its own specification/API;
6. implement `2022-blake3-chacha20-poly1305` only after its separate framing,
   identity, time, and replay requirements are understood;
7. add malformed-input, tamper, replay, boundary, partial-I/O, network-change,
   cancellation, and password-safe-error tests;
8. bind the proxy-server transport to the original physical interface and add
   an explicit audited exclusion without per-target persistent routes;
9. verify that every PROXY failure remains fail closed; and
10. validate interoperability without copying source from external
    implementations.

Windows Service, Kill Switch enforcement, system-proxy mode, subscriptions,
accounts, telemetry, and credential-manager integration remain outside that
protocol phase.
