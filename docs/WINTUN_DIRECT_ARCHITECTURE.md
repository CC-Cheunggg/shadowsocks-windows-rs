# Wintun and DIRECT architecture

This document describes the implemented DIRECT slice and its explicit
boundaries. It distinguishes code and unit-test coverage from Windows CI and
real-machine acceptance. A feature is not release-accepted merely because the
corresponding module exists or compiles.

## Scope

The slice implements this path on Windows x86_64:

```text
Windows application socket
        |
        v
Wintun split-default capture
        |
        v
IPv4 / IPv6 parser
        |
        +---- TCP -> smoltcp session -> byte stream
        |
        `---- UDP -> bounded five-tuple association
        |
        v
DNS metadata + ConnectionMode router
        |
        +---- DIRECT -> native socket fixed to physical interface
        |
        `---- PROXY -> ProxyNotImplemented, fail closed
        |
        v
remote response -> session/IP reconstruction -> Wintun send ring
```

No module enables or modifies the Windows system proxy. Existing proxy
configuration may change the connection target chosen by a proxy-aware
application; a confirmed local-network proxy endpoint still enters Wintun and
is then selected as a necessary DIRECT exception. `direct`, `rule`, and
`global` remain routing decisions made after capture.

The following are deliberately outside this slice:

- Shadowsocks handshake and destination framing;
- Shadowsocks TCP or UDP encryption/decryption;
- a PROXY outbound;
- Windows Service operation;
- Kill Switch enforcement;
- Windows system-proxy mode;
- subscription downloads;
- login, users, cloud accounts, or telemetry; and
- Windows Credential Manager.

## Rust module boundaries

| Module | Responsibility |
| --- | --- |
| `tun/wintun.rs` | Fixed-name DLL loading, Wintun function table, adapter ownership, packet session, receive-ring guard, send-ring injection, and handle cleanup |
| `tun/routes.rs` | Physical-interface discovery, read-only network snapshots, volatile split-default routes, explicit exclusions, exact rollback |
| `packet/` | IPv4/IPv6, TCP/UDP parsing, checksums, and UDP response packet construction |
| `session/tcp.rs` | Thin transparent-session adapter over `smoltcp` |
| `session/udp.rs` | Bounded five-tuple associations, queues, expiry, and cancellation |
| `dns/` | DNS transport metadata, bounded domain/IP cache, and safe A/AAAA/CNAME response parsing |
| `router/` | `ConnectionMode`, ordered rules, CIDR/domain matching, decisions, and mandatory global exclusions |
| `system_proxy.rs` | Read-only, bounded WinHTTP/WinINet capture, credential-free endpoint parsing/resolution, and exact local-network confirmation |
| `outbound/direct.rs` | Physical-interface TCP/UDP socket creation, cancellation-aware I/O, and active-socket loop guard |
| `outbound/proxy.rs` | Typed `ProxyNotImplemented` placeholder only |
| `runtime/` | Startup, packet driver, worker supervision, state/counters, shutdown, rollback journal, and recovery |
| `diagnostics/` | Saturating non-sensitive counters, temporary flow IDs, and loop-detection primitives |
| `error.rs` | Errors whose display text does not include packet contents, credentials, or destinations |

Windows API code is guarded by `cfg(windows)`. Packet, router, DNS-cache,
session, diagnostics, and recovery-journal tests remain runnable on macOS and
Linux.

## Wintun acquisition and loading

The project pins the official Wintun 0.14.1 distribution:

- URL:
  `https://www.wintun.net/builds/wintun-0.14.1.zip`
- ZIP SHA-256:
  `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`
- AMD64 DLL path in the ZIP: `wintun/bin/amd64/wintun.dll`
- DLL size: 427,552 bytes
- DLL SHA-256:
  `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`
- Prebuilt Binaries License SHA-256:
  `183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2`

`scripts/fetch-wintun.ps1` verifies all three pinned hashes. The binary is not
committed to Git. The script also extracts the original `wintun/LICENSE.txt`
bytes from the pinned archive. The Windows Tauri configuration maps the
verified DLL under the fixed application-local name `wintun.dll` and includes
the repository's review copy of the license. The Actions acceptance artifact
uses the separately hash-verified original license bytes extracted from the
pinned archive.

The loader does not accept a caller or frontend path. It uses the fixed name
`wintun.dll` with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` only; current-directory,
`PATH`, and System32 fallback are excluded. Windows CI verifies the pinned DLL
hash, its outer Authenticode signature, the final application-local copy, and
the uploaded `SHA256SUMS`. The project does not compile, copy, modify, or
redistribute GPLv2 Wintun source code.

## Adapter and packet-session lifecycle

On start, the runtime:

1. checks cancellation before beginning or continuing startup;
2. captures an adapter/route/DNS snapshot;
3. uses one bounded, cancellable worker to read the current-user and WinHTTP
   default proxy configuration and resolve all concrete candidates within one
   five-second total deadline;
4. non-blockingly acquires the fixed global network-recovery lease before the
   first mutation, so a desktop start and recovery helper cannot mutate the
   same journal/network state concurrently;
5. rechecks cancellation, loads the pinned application-local Wintun API, and
   refuses startup if an adapter with the configured name is already openable;
6. rechecks cancellation, creates the adapter, and resolves its
   ifIndex/LUID/GUID/alias identity;
7. atomically creates the initial empty recovery journal as soon as the stable
   adapter identity exists and before route/address/interface mutation;
8. resolves each management host and proxy candidate with `GetBestRoute2`;
9. discovers the default physical DIRECT binding and builds shadow routes;
10. opens a 4 MiB Wintun packet session;
11. installs each MTU/metric, address, and route with the `Prepared`/native
    mutation/`Applied` journal sequence;
12. waits for every created Wintun address to reach native DAD state
    `Preferred`, polling every 500 ms with a 12-second limit;
13. registers native route/interface/address change notifications;
14. repeats bounded read-only proxy capture and revalidates the cached physical
    DIRECT, management, and confirmed system-proxy bindings with constrained
    `GetBestRoute2` and complete stable interface/source/next-hop comparison;
    takes a fresh route snapshot, excludes only the exact Wintun ifIndex+LUID
    generation, rebuilds the complete external shadow-prefix set, and compares
    it with the installed plan; and compares all external IPv4/IPv6 default
    route identities, gateways, route metrics, and interface metrics with the
    pre-mutation selection fingerprint; and
15. publishes `running` and starts the packet driver.

Wintun receive buffers are exposed through a guard and released back to the
ring on drop. Send packets are allocated from the Wintun send ring, filled, and
submitted. Adapter, API library, session, and receive-packet handles use scoped
ownership.

Normal stop cancels workers, joins them, ends the Wintun session, removes the
owned routes and addresses, removes the owned adapter, and clears the recovery
journal only when cleanup succeeds. Startup failures attempt rollback for every
resource already acquired. One epoch resource owner holds the global recovery
lease, monitor, session, route transaction, adapter, and journal lifecycle; its
explicit cleanup path makes rollback failures visible, while drop remains a
best-effort guard for early-return and panic paths.

Normal epoch cleanup trusts the in-memory `RouteTransaction` created by that
epoch; it does not deserialize the user-writable journal for a second recovery
pass. It deregisters the monitor, ends the session, performs exact in-memory
rollback—including physical management exclusion routes created by that
transaction—calls `remove_owned` on the creating adapter handle, and then
polls every 50 ms for at most five seconds until neither the recorded alias nor
LUID is present. The journal is cleared only when rollback ownership remained
verified, route rollback succeeded, adapter removal succeeded, and both
identity lookups prove absence. Any failure retains the journal and returns the
applicable cleanup error.

The independent journal uses write-through temp-file replacement and explicit
write-ahead ownership states. Before each recorded
route/address/interface-setting change, its complete expected identity and
fields are durably recorded as `Prepared`; after native success, the in-memory
state becomes `Applied` before the durable `Applied` transition. Conflicting
pre-existing objects are checked both while planning and immediately before
mutation.

Independent recovery does not trust the journal alone as authority for an
elevated network mutation. Using the fixed application-local Wintun API, it
must first open the journal alias, compare the handle's LUID and ifIndex, resolve
that ifIndex through Windows, and match the complete
ifIndex/LUID/GUID/alias identity. The verified handle remains open throughout
restoration so the adapter cannot disappear and have its index reused between
provenance proof and mutation. If the DLL or adapter cannot be loaded/opened,
the adapter is absent, or any identity field differs, recovery performs zero
recorded network mutations, keeps the journal, and returns
`RecoveryRequired`.

After adapter provenance succeeds, independent recovery removes or restores
or verifies only objects owned by that verified Wintun interface: its
addresses, interface settings, and routes whose `route.interface` equals the
verified TUN identity. It never mutates a route directed to any other
interface, including a physical management host exclusion, because adapter
provenance cannot prove that a user-writable journal's arbitrary physical route
was application-created. Wintun-owned objects may be safely restored first,
but the presence of any external-interface route then retains the journal and
returns `RecoveryRequired`. Normal stop remains able to remove such a physical
exclusion from its trusted in-memory transaction.

Within the adapter-only scope, independent recovery removes or restores exact
`Applied` objects only after complete field checks. A `Prepared` object must
still be absent, and a prepared interface setting must still equal its recorded
original value. An exact-present address/route or an applied-looking interface
setting under `Prepared` is intentionally ambiguous: recovery returns
`RecoveryRequired` and retains the journal instead of claiming or deleting it.
This write-ahead sequence closes the prior post-mutation/pre-journal-record
gap. A normal journal-write failure performs synchronous rollback from the
authoritative in-memory state and reports rollback failure preferentially.
Repeated recovery accepts exact settings already restored to their original
values.

Wintun 0.14.1 has no independent delete API for an adapter reopened after its
creating process is gone. When a journal has no external-interface routes,
independent recovery drops its verified opened handle and polls alias and LUID
every 50 ms for at most five seconds. If either identity remains, the helper
keeps the journal and returns `RecoveryRequired` instead of claiming complete
cleanup. A journal with an external-interface route is already retained and
reported as `RecoveryRequired` after adapter-owned restoration; the helper
does not mutate that route or clear the journal.

## Split-default capture routes

Instead of replacing Windows default routes, the runtime adds more-specific
volatile `ActiveStore` routes:

| Family | Wintun prefixes |
| --- | --- |
| IPv4 | `0.0.0.0/1`, `128.0.0.0/1` |
| IPv6 | `::/1`, `8000::/1` |

The original physical default remains present. The Wintun interface receives
application-owned addresses `198.18.0.1/15` and
`fd00:7373:7273::1/64`. After each address is created, the runtime polls
`GetUnicastIpAddressEntry` until DAD reports `Preferred`; `Tentative` is
accepted only while waiting, and every other state or the 12-second deadline
fails startup and triggers rollback. These addresses and the four split routes
are removed during rollback.

The `/1` routes outrank ordinary defaults. Pre-existing longer LAN, host, VPN,
or enterprise prefixes from the snapshot are converted into one-level-longer
child/shadow routes owned by Wintun, closing longest-prefix bypasses without
deleting the original routes.

A pre-existing IPv4 `/32` or IPv6 `/128` has no longer child prefix. Before a
same-prefix Wintun shadow is installed, the planner proves that its route plus
interface metric is lower than each conflicting route's effective metric.
Configured management hosts are removed from the shadow set and intentionally
remain physical.

IPv6 split routes are installed even when `tun.ipv6` is false. In that case
captured IPv6 is counted and dropped. This intentionally prevents an
unsupported-family leak through the physical default route.

Every intended object enters the write-ahead recovery plan as `Prepared` before
mutation and advances to `Applied` after native success. Recovery deletes exact
unambiguously owned objects rather than replaying an old route table, so
unrelated network changes made after startup are preserved.

## Physical-interface DIRECT bypass

The original physical adapter is discovered with Windows route selection,
excluding the new Wintun interface. The runtime records:

- interface index and alias;
- IPv4 and, when available on the same adapter, IPv6 source address;
- IPv4/IPv6 gateways;
- system DNS server addresses; and
- route metric.

Each DIRECT socket is created for the destination address family and:

1. binds the discovered physical source address;
2. sets `IP_UNICAST_IF` for IPv4 or `IPV6_UNICAST_IF` for IPv6; and
3. connects to the original destination, or to the declared DNS resolver for
   captured DNS.

Windows requires the IPv4 interface index for `IP_UNICAST_IF` in network byte
order and the IPv6 index for `IPV6_UNICAST_IF` in host byte order. The outbound
module handles that difference.

This binding keeps the socket on the original interface while the process-wide
split-default routes capture ordinary application traffic. The runtime does
not add a permanent host route for every destination.

As a second safety layer, each DIRECT socket registers its transport, bound
local endpoint, and destination after bind assigns the source port but before
connect can emit a SYN or UDP datagram. If Wintun captures that exact TCP/UDP
tuple, the packet is counted in `loop_prevention_drops` and `dropped_packets`
and is never routed again. Unrelated traffic that merely reuses one endpoint
does not match. A non-zero loop counter is a failure signal to investigate, not
expected steady state.

## TCP session handling

The project uses `smoltcp 0.13.1` under its 0BSD license instead of
hand-writing a complete TCP stack. `smoltcp` is maintained as an independent
direct dependency and owns:

- sequence and acknowledgment numbers;
- retransmission and timers;
- receive/transmit windows;
- SYN/SYN-ACK/ACK state;
- FIN and RST state; and
- TCP checksum validation and generation.

The project adapter creates a bounded exact listener only for a captured
initial SYN. Each flow has bounded receive and transmit buffers and a configured
idle timeout. The runtime:

- drains reconstructed client bytes only when the outbound channel has
  capacity, applying TCP-window backpressure otherwise;
- retries partial writes and retains unsent response suffixes;
- maps client FIN to DIRECT write-half shutdown after pending data;
- maps DIRECT EOF to client-facing FIN after pending response data;
- maps connection refusal and active outbound-worker errors to RST;
- caps pending response bytes per worker; and
- cancels and reaps terminal or idle sessions.

The direct session adapter supports both unfragmented IPv4 and unfragmented
IPv6 packets without IPv6 extension headers. The present code still requires
real-Windows tests for connection refusal, timeout, network changes, and
long-lived cancellation behavior. Runtime-wide stop and idle reaping do not
promise that a final RST is emitted before state is released.

## UDP associations

UDP state is keyed by source address/port and destination address/port plus the
UDP transport protocol: a five-tuple association. The table has explicit caps
for association count, queued datagrams, queued bytes, and datagram size.

The first accepted datagram creates one native connected UDP socket on the
physical interface. Later datagrams for the same tuple reuse it. Response
datagrams are rebuilt with source and destination reversed, valid IPv4 or IPv6
UDP checksums, and then injected into Wintun. Idle associations expire and
cancel their worker.

Queue overflow or capacity exhaustion is counted and dropped. UDP traffic never
escapes through an untracked fallback socket.

The association table owns the bounded backlog. At most one datagram may be in
the worker's bounded command channel and one in its pending slot; there is no
unbounded second queue. Each tuple has a monotonically changing generation so
late data/failure/completion events from a retired worker cannot affect a
reused tuple.

## DNS

DNS traffic is parsed only after capture like other TCP/UDP traffic.

After capture, recognized DNS is sent through the centralized mandatory DIRECT
resolver path before ordinary `rule` or `global` PROXY decisions can block it.
This exception is auditable and does not bypass Wintun. Resolver selection
still follows the declared system/custom configuration; a forwarding failure
does not silently switch to another resolver or outbound.

For UDP DNS:

- destination port 53 always uses the post-capture mandatory DIRECT path in
  this slice; `dns.enabled = false` keeps the captured resolver destination and
  disables custom destination rewriting;
- `source = "system"` keeps the captured resolver destination;
- `source = "custom"` rewrites the DIRECT destination to the first configured
  resolver with the same address family;
- absence of a same-family custom resolver is an explicit configuration/runtime
  failure, not an undeclared fallback; and
- the DIRECT resolver socket uses the same physical-interface binding and loop
  guard as ordinary UDP.

The runtime does not silently try a second resolver or change from system to
custom on failure. IPv4 DNS uses an IPv4 resolver. IPv6 DNS requires both
`dns.ipv6` and `tun.ipv6` plus an IPv6 resolver. UDP responses on port 53 may
still populate the bounded metadata cache when DNS destination rewriting is
disabled.

TCP port 53 uses the normal captured TCP path when `tcp_fallback` is enabled.
When it is disabled, captured TCP DNS is rejected. The slice does not yet
inspect the UDP DNS `TC` bit and automatically retry the same request over TCP;
therefore “TCP fallback” currently means accepting DNS-over-TCP traffic initiated
by the system/application, not internally synthesizing a retry.

Successful UDP DNS responses are parsed with bounded name-compression traversal
and safe record-count limits. Only normalized domain names, A/AAAA addresses,
CNAME associations, and expiry times are retained. TCP DNS responses currently
traverse the TCP session but do not populate this DNS cache. The cache:

- has a configured domain capacity;
- retains at most 16 addresses per domain;
- caps upstream TTL by `cache_ttl_seconds`; and
- removes expired associations.

The complete DNS query or response payload and transaction ID are not retained
or logged. Domain metadata is used only to evaluate domain routing rules.

## Routing decisions

Routing occurs before the future Shadowsocks encryption boundary.

### Direct

All supported ordinary flows produce DIRECT decisions. They still pass through
Wintun, packet parsing, session/association handling, and the router.

### Rule

Only enabled rules are compiled, preserving configuration order. The first
matching rule wins. Matchers are:

- ASCII domain exact, case-insensitive after normalization;
- domain suffix with label-boundary protection;
- IPv4 CIDR; and
- IPv6 CIDR.

Domain rules use unexpired DNS-cache associations. CIDR rules can match without
DNS metadata. If no rule matches, the explicit `default_action` is used.

A DIRECT result reaches the physical outbound. A PROXY result increments
`route_proxy`, records a safe `ProxyNotImplemented` error, and drops the flow.
It is never translated into DIRECT.

### Global

Ordinary traffic selects PROXY and therefore fails closed in this DIRECT-only
slice. The centrally defined built-in global DIRECT exclusions are:

```text
127.0.0.0/8
::1/128
```

Explicit `tun.management_exclusions` are added to the same global exclusion
set. They must be host CIDRs (`/32` or `/128`), are written to the recovery
plan, and use the discovered physical gateway.

Confirmed local-network system-proxy endpoints are a distinct mandatory
user-space-router exception. One worker performs read-only WinHTTP/WinINet
discovery and sequential DNS resolution behind a bounded, cancellable total
deadline. Raw proxy strings and embedded credentials are discarded before DNS;
only bounded host/port candidates and resolved socket endpoints survive.
`GetBestRoute2` validation against the pre-capture snapshot must resolve an
exact endpoint before it is admitted. This exception does not create a
physical-interface host route: the application connection is captured first,
and only the replacement DIRECT socket bypasses Wintun. Arbitrary private
addresses do not qualify.

AutoConfig/PAC presence is detected, but PAC JavaScript and its
per-destination result are not evaluated in this slice. PAC-only dynamic
endpoints therefore receive no exception; only concrete manual,
protocol-specific, or WinHTTP named-proxy endpoints can be confirmed.

Loopback proxies remain loopback. For a remote proxy, routing observes the
proxy endpoint rather than the final CONNECT/SOCKS destination; this slice
does not parse either proxy protocol. Safe diagnostics distinguish
`system_proxy_detected` from `route_direct_system_proxy`.

Route, IP-interface, and unicast-address notifications invalidate the current
network epoch. The invalid token is shared by every DIRECT clone, so new
connect/associate calls and ongoing I/O fail immediately or at the next bounded
poll. Before rollback begins, the runtime publishes that it is leaving
`running`; the driver then cancels and joins old workers, deregisters
notifications, restores owned state, removes the owned adapter, verifies its
absence for up to five seconds, applies the bounded network debounce, and
performs a fresh snapshot, proxy DNS resolution, stable interface identity,
`GetBestRoute2` gateway/source validation, router build, and outbound binding.
With the new monitor active, it revalidates every cached physical, management,
and confirmed proxy binding before publishing `running`. A fresh route snapshot
also excludes rows only when both ifIndex and LUID match the current Wintun,
then rebuilds the normalized external shadow-prefix set after planned
exclusions. A difference from the installed plan is treated as the same
pre-running network change. The same snapshot compares every external
IPv4/IPv6 default route plus its route and interface metric, catching even a
metric-only change in default selection. The runtime intentionally interrupts
old connections rather than mixing route and socket state from two networks.
If this revalidation detects a change before the first `running` transition,
startup stays pending, cleans the epoch, and retries without emitting a false
startup-success notification.

The exclusion vocabulary in `tun/routes.rs` is auditable:

- `management_connection`;
- `local_control`;
- `direct_dns`;
- `proxy_server_future`.

The current runtime installs only explicitly configured management exclusions.
It does not silently exempt LAN ranges, DNS servers, arbitrary destinations, or
a not-yet-implemented proxy server.

## Packet and protocol limits

| Protocol or condition | Behavior |
| --- | --- |
| Default-routed destination | Captured through a split-default route |
| Destination covered by a pre-existing prefix longer than `/1` | Captured by snapshot-derived child shadow routes; host collisions require effective-metric proof |
| Valid, unfragmented IPv4 TCP | Parsed and handled |
| Valid, unfragmented IPv4 UDP | Parsed and handled |
| Valid, unfragmented IPv6 TCP/UDP with direct next-header | Parsed and handled when enabled |
| IPv4 header checksum failure | Counted and dropped |
| TCP checksum failure or invalid non-zero IPv4 UDP checksum | Rejected; no bypass |
| Zero IPv4 UDP checksum | Accepted as permitted by IPv4 UDP; IPv6 zero checksum is rejected |
| IPv4 fragment | Counted and dropped |
| IPv6 fragment header | Counted and dropped |
| IPv6 hop-by-hop, routing, destination-options, AH, ESP extension | Currently unsupported; counted and dropped |
| ICMP/ICMPv6 and other IP protocols | Counted and dropped |
| UDP response larger than configured MTU | Rejected and counted without fragmentation |
| Disabled IPv6 | Captured and dropped |

The configured MTU is used as the smoltcp IP-medium MTU and by the UDP packet
builder. The TCP adapter requires 1280 through 9000 bytes. The runtime applies
that MTU and a deterministic metric to both Wintun IP families and journals
their previous values for exact, idempotent restoration. Wintun send-ring
pressure receives three bounded attempts before a counted drop. No code in this
slice claims PMTU discovery, IP reassembly, or IPv6-extension-chain support.

## Runtime state and diagnostics

Runtime state is one of:

- `stopped`;
- `starting`;
- `running`;
- `stopping`;
- `recovery-required`; or
- `failed`.

Each managed startup receives a generation identifier. Timeout and failed-start
cleanup may cancel, join, retire, or publish failure only while that same
generation remains active. A delayed cleanup from startup A therefore cannot
cancel or join a newer startup B.

The runtime publishes:

- `tun_rx_packets`;
- `tun_tx_packets`;
- `captured_tcp_sessions`;
- `captured_udp_datagrams`;
- `route_direct`;
- `route_proxy`;
- `direct_tcp_connections`;
- `direct_udp_associations`;
- `unsupported_packets`;
- `dropped_packets`; and
- `loop_prevention_drops`.

Counters saturate rather than wrap. A temporary process-local numeric
`flow_id` can correlate capture, routing, outbound, and completion/failure.
Diagnostics must not include packet bodies, passwords, keys, cookies,
authorization headers, or complete DNS payloads.

The restricted Tauri boundary exposes configuration commands plus:

- `get_runtime_snapshot`;
- `start_tunnel`;
- `stop_tunnel`; and
- `recover_network`.

No command accepts a Wintun DLL path or arbitrary recovery/system path.

## Configuration compatibility

Configuration version 2 adds routing rules and operational TUN/DNS settings.
Version 1 is migrated only after the original bytes are backed up. Existing
server profiles, passwords, and selection are retained when the migrated value
passes version-2 validation. The old placeholder `tun.enabled` value is
explicitly changed to `true`, because Wintun is now the sole supported traffic
entry point.

Unknown future versions are rejected without resetting the file. Invalid known
configurations are backed up before defaults are written.

Version 1 accepted MTUs below 1280, text DNS hostnames, and interface names that
version 2 rejects. Those cases are currently backed up but fall back to an
active default configuration, so full backward-compatible active migration
remains a known gap and must not be described as universally preserving the
live configuration.

## Verification layers

### Platform-independent tests

The Rust tests cover packet parsing, checksums, domain/CIDR routing, rule order,
fail-closed PROXY decisions, DNS-cache expiry and bounds, TCP lifecycle,
UDP lifecycle, backpressure, cancellation, loop detection, recovery-journal
serialization, and safe error messages.

### Windows Actions

The Windows workflow compiles `x86_64-pc-windows-msvc`, runs Rust tests, builds
the release desktop target with Tauri's Cargo `custom-protocol` feature, loads
the verified official DLL, and runs `wintun_smoke` with a unique adapter. A
development-protocol binary is not acceptance media. The smoke test:

- captures pre/post network snapshots;
- records the default-route fingerprint;
- adds only `192.0.2.1/32` to the temporary adapter;
- adds only two TEST-NET `/32` routes;
- captures a real UDP probe and injects a response that reaches the socket;
- captures a TCP SYN, injects a SYN-ACK, and captures the client ACK; and
- uses scoped cleanup for its address, routes, packet session, and owned
  adapter on normal return/error.

It never modifies the runner's default routes or DNS. This test validates the
Wintun DLL/API/rings and local Windows packet path, not full-capture DIRECT.
The workflow's always-run `--cleanup-only` path removes the known test
routes/address and verifies that no named adapter remains. If an adapter from a
hard crash remains, the helper returns an explicit failure: Wintun 0.14.1
cannot delete an adapter through a newly reopened handle.

### Real Windows

Real acceptance must use media downloaded from a successful Actions run after
compilation, tests, Wintun smoke, hash/signature checks, and packaging. The
workflow definition stages and uploads that media with `BUILD-INFO` and
`SHA256SUMS`, but no artifact exists until a particular run completes
successfully. First perform only read-only host inspection in Microsoft Remote
Desktop. Running even the isolated smoke mutates a temporary adapter and two
routes, so it requires the agreed action-time confirmation.

Full capture additionally requires an out-of-band console, RDP peer exclusion,
saved snapshots, an automatic rollback watchdog, and the standalone recovery
binary. Evidence and procedure are defined in
[WINDOWS_RECOVERY.md](WINDOWS_RECOVERY.md) and
[WINDOWS_ACCEPTANCE_TEMPLATE.md](WINDOWS_ACCEPTANCE_TEMPLATE.md).

Until successful run links and the real-machine record exist, the correct
status is “implemented in code, platform-independent tests available, Windows
workflow defined/pending, real-Windows acceptance pending,” not “fully
verified.”
