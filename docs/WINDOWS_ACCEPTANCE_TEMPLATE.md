# Windows DIRECT real-machine acceptance record

Use one copy for one newly built artifact and one Windows acceptance attempt.
Follow [DEVELOPMENT_CONSTRAINTS.md](DEVELOPMENT_CONSTRAINTS.md) and the exact
operator sequence in [WINDOWS_RECOVERY.md](WINDOWS_RECOVERY.md). The design
context is in [WINTUN_DIRECT_ARCHITECTURE.md](WINTUN_DIRECT_ARCHITECTURE.md);
task state is in
[WINDOWS_DIRECT_ACCEPTANCE_TASKS.md](WINDOWS_DIRECT_ACCEPTANCE_TASKS.md).

Every status/evidence field starts as `NOT RUN`. Replace it only with recorded
evidence. Allowed result values are `PASS`, `FAIL`, `BLOCKED`, `DEFERRED`, and
`NOT RUN`; do not leave a cell blank. `DEFERRED` must name its later task or
environment. `BLOCKED` must name the unmet gate. Never reuse an old artifact,
hash, route observation, RDP tuple, OOB proof, or authorization.

## 1. Record identity

| Field | Value | Evidence/status |
| --- | --- | --- |
| Record owner | NOT RUN | NOT RUN |
| Test date/time/time zone | NOT RUN | NOT RUN |
| Repository commit SHA | NOT RUN | NOT RUN |
| Branch/ref | NOT RUN | NOT RUN |
| Windows version/build/architecture | NOT RUN | NOT RUN |
| Machine/VM identifier | NOT RUN | NOT RUN |
| Network environment | NOT RUN | NOT RUN |
| Current Windows user | NOT RUN | NOT RUN |
| Current token SID or redacted fingerprint | NOT RUN | NOT RUN |
| Administrator-role check | NOT RUN | NOT RUN |
| Final disposition | NOT RUN | NOT RUN |

Never record a password, credential, token, private key, or unredacted
application payload.

## 2. New artifact provenance and delivery gates

| Field | Value | Evidence/result |
| --- | --- | --- |
| Actions run URL | NOT RUN | NOT RUN |
| Actions run ID / attempt | NOT RUN | NOT RUN |
| Artifact name | NOT RUN | NOT RUN |
| Artifact ID | NOT RUN | NOT RUN |
| Artifact service digest | NOT RUN | NOT RUN |
| Downloaded ZIP SHA-256 | NOT RUN | NOT RUN |
| `BUILD-INFO` path/hash | NOT RUN | NOT RUN |
| `SHA256SUMS` path/hash | NOT RUN | NOT RUN |
| Manifest inventory/hash verification | NOT RUN | NOT RUN |
| `shadowsocks-windows-rs.exe` SHA-256 | NOT RUN | NOT RUN |
| `network_recover.exe` SHA-256 | NOT RUN | NOT RUN |
| `wintun_smoke.exe` SHA-256 | NOT RUN | NOT RUN |
| Exactly one `*-setup.exe` name | NOT RUN | NOT RUN |
| Setup SHA-256 and `BUILD-INFO` match | NOT RUN | NOT RUN |
| `wintun.dll` SHA-256 | NOT RUN | NOT RUN |
| `wintun.dll` Authenticode signer/status | NOT RUN | NOT RUN |
| `WINTUN-LICENSE.txt` hash | NOT RUN | NOT RUN |
| Project/third-party license files | NOT RUN | NOT RUN |

Pinned Wintun SHA-256:

```text
e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
```

Pinned Wintun binary-license SHA-256:

```text
183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2
```

| Delivery gate | Expected | Evidence/result |
| --- | --- | --- |
| Main EXE PE subsystem | 2 (Windows GUI) | NOT RUN |
| Recovery helper PE subsystem | 3 (console) | NOT RUN |
| Smoke helper PE subsystem | 3 (console) | NOT RUN |
| Static MSVC CRT: main EXE | PASS | NOT RUN |
| Static MSVC CRT: recovery helper | PASS | NOT RUN |
| Static MSVC CRT: smoke helper | PASS | NOT RUN |
| NSIS build | Exactly one setup | NOT RUN |
| NSIS WebView2 mode | `downloadBootstrapper`, silent | NOT RUN |
| Raw EXE present separately | PASS | NOT RUN |
| Raw EXE starts without a CMD window | PASS | NOT RUN |
| Missing-Runtime native progress text | `正在初始化运行环境，请稍候…` | NOT RUN |
| Missing-Runtime install has no separate wizard | PASS | NOT RUN |
| Bootstrap success closes native UI and starts app | PASS | NOT RUN |
| Bootstrap failure blocks Tauri/WebView and shows native error | PASS | NOT RUN |
| Installed-Runtime fast path performs no download/UI/process work | PASS | NOT RUN |
| NSIS installation/resource layout | PASS | NOT RUN |

The last Windows-native rows cannot be marked `PASS` from injected unit tests
or static configuration alone. Do not infer that NSIS installs either helper
unless installation-layout evidence proves it.

## 3. Read-only baseline

| Evidence | Location/hash | Result |
| --- | --- | --- |
| `Get-CimInstance Win32_OperatingSystem` | NOT RUN | NOT RUN |
| Administrator-role output | NOT RUN | NOT RUN |
| `Get-NetAdapter` | NOT RUN | NOT RUN |
| `Get-NetIPAddress` | NOT RUN | NOT RUN |
| `Get-NetRoute -PolicyStore ActiveStore` | NOT RUN | NOT RUN |
| `Get-DnsClientServerAddress` | NOT RUN | NOT RUN |
| IPv4 `Find-NetRoute` | NOT RUN | NOT RUN |
| IPv6 `Find-NetRoute` or environment limitation | NOT RUN | NOT RUN |
| Current Windows system-proxy fields | NOT RUN | NOT RUN |
| `network_recover.exe --status` | NOT RUN | NOT RUN |
| Baseline evidence directory digest | NOT RUN | NOT RUN |

## 4. RDP, physical path, and OOB proof

| Field | Value | Evidence/result |
| --- | --- | --- |
| RDP local IP | NOT RUN | NOT RUN |
| RDP local port | NOT RUN | NOT RUN |
| RDP remote IP | NOT RUN | NOT RUN |
| RDP remote port | NOT RUN | NOT RUN |
| RDP protocol | NOT RUN | NOT RUN |
| Management address family | NOT RUN | NOT RUN |
| Physical interface name | NOT RUN | NOT RUN |
| Physical ifIndex | NOT RUN | NOT RUN |
| Physical LUID | NOT RUN | NOT RUN |
| Physical gateway | NOT RUN | NOT RUN |
| Physical generation/fingerprint | NOT RUN | NOT RUN |
| OOB console type | NOT RUN | NOT RUN |
| OOB access method | NOT RUN | NOT RUN |
| OOB administrator proof time | NOT RUN | NOT RUN |
| OOB independent of RDP path | NOT RUN | NOT RUN |

RDP itself is never OOB proof.

## 5. Operator-owned management host route

The operator creates and owns this exact `ActiveStore` route. The application
only validates it and must never create, modify, delete, or journal it.

| Field | Value | Evidence/result |
| --- | --- | --- |
| Exact destination prefix (`/32` or `/128`) | NOT RUN | NOT RUN |
| Address family | NOT RUN | NOT RUN |
| Policy store | NOT RUN | NOT RUN |
| Physical ifIndex | NOT RUN | NOT RUN |
| Physical LUID | NOT RUN | NOT RUN |
| Next-hop gateway | NOT RUN | NOT RUN |
| Route metric | NOT RUN | NOT RUN |
| Operator creation command/time | NOT RUN | NOT RUN |
| Unique exact-route count equals 1 | NOT RUN | NOT RUN |
| `Find-NetRoute` wins on expected physical path | NOT RUN | NOT RUN |
| Matching `tun.management_exclusions` entry | NOT RUN | NOT RUN |
| Route absent from application route plan/journal | NOT RUN | NOT RUN |

## 6. Fresh action-time gate and watchdog

| Gate | Fresh value/evidence | Result |
| --- | --- | --- |
| RDP five-tuple recollected | NOT RUN | NOT RUN |
| Physical ifIndex/LUID/gateway recollected | NOT RUN | NOT RUN |
| Unique exact `ActiveStore` route reverified | NOT RUN | NOT RUN |
| Winning best-route result reverified | NOT RUN | NOT RUN |
| Fresh evidence timestamp | NOT RUN | NOT RUN |
| Protected Program Files stage path | NOT RUN | NOT RUN |
| Stage ACL/regular-file/symlink check | NOT RUN | NOT RUN |
| Helper/manifest/Wintun hashes reverified | NOT RUN | NOT RUN |
| `WATCHDOG-CONTEXT.json` SID binding | NOT RUN | NOT RUN |
| Scheduled task identity | NOT RUN | NOT RUN |
| Scheduled task logon/run level | S4U / Highest | NOT RUN |
| Fixed action and `--watchdog` argument | NOT RUN | NOT RUN |
| Five-minute helper / two-second retry policy | NOT RUN | NOT RUN |
| No-journal dry run final JSONL record | NOT RUN | NOT RUN |
| Future trigger still armed | NOT RUN | NOT RUN |
| Runtime journal proved present before trigger | NOT RUN | NOT RUN |
| Watchdog cancellation after verified cleanup | NOT RUN | NOT RUN |

| Authorization | Exact scope | Time/evidence | Result |
| --- | --- | --- | --- |
| Operator-route creation approval | NOT RUN | NOT RUN | NOT RUN |
| Watchdog provision/arm approval | NOT RUN | NOT RUN | NOT RUN |
| Isolated Wintun smoke approval | NOT RUN | NOT RUN | NOT RUN |
| Full DIRECT mutation approval | NOT RUN | NOT RUN | NOT RUN |
| Optional route-removal approval | NOT RUN | NOT RUN | NOT RUN |

## 7. Isolated Wintun smoke

| Check | Evidence | Result |
| --- | --- | --- |
| Unique temporary adapter created | NOT RUN | NOT RUN |
| UDP probe captured and response injected | NOT RUN | NOT RUN |
| TCP SYN captured, SYN-ACK injected, ACK captured | NOT RUN | NOT RUN |
| Default-route fingerprint unchanged | NOT RUN | NOT RUN |
| Temporary `/32` routes absent afterward | NOT RUN | NOT RUN |
| Temporary address absent afterward | NOT RUN | NOT RUN |
| Session ended and adapter absent afterward | NOT RUN | NOT RUN |
| RDP remained connected | NOT RUN | NOT RUN |
| OOB remained reachable | NOT RUN | NOT RUN |

Smoke stdout/stderr, snapshots, and hashes: `NOT RUN`

## 8. Full DIRECT runtime

Configuration, without credentials:

| Field | Value/status |
| --- | --- |
| Mode | NOT RUN |
| Wintun alias | NOT RUN |
| MTU / Windows interface MTU | NOT RUN |
| IPv6 enabled | NOT RUN |
| DNS resolver families | NOT RUN |
| TCP DNS enabled | NOT RUN |
| TCP timeout | NOT RUN |
| UDP idle timeout | NOT RUN |
| Management exclusion(s) | NOT RUN |

### Owned state and route checks

| Check | Evidence | Result |
| --- | --- | --- |
| One exact owned Wintun adapter | NOT RUN | NOT RUN |
| Exact ifIndex/LUID/GUID/alias journal identity | NOT RUN | NOT RUN |
| Durable intent existed before adapter creation | NOT RUN | NOT RUN |
| Wintun IPv4/IPv6 addresses match plan | NOT RUN | NOT RUN |
| Wintun MTU/metric match applied state | NOT RUN | NOT RUN |
| IPv4 split-default routes select Wintun | NOT RUN | NOT RUN |
| IPv6 split-default routes select Wintun | NOT RUN | NOT RUN |
| Longer-prefix shadows/exclusions match plan | NOT RUN | NOT RUN |
| Original physical defaults remain | NOT RUN | NOT RUN |
| Operator route is unchanged and wins for RDP | NOT RUN | NOT RUN |
| Ordinary targets select Wintun | NOT RUN | NOT RUN |
| DNS-server settings unchanged | NOT RUN | NOT RUN |
| System-proxy fields unchanged | NOT RUN | NOT RUN |
| Recovery journal present while running | NOT RUN | NOT RUN |

### Protocol and data-path evidence

For every row record exact command/tool, timestamp, target class, flow/counter
references, physical and Wintun capture hashes, and result.

| Traffic/behavior | Wintun capture | Physical outbound | Return reinjected | Result |
| --- | --- | --- | --- | --- |
| IPv4 HTTPS/TCP | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Plain TCP lifecycle | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| UDP | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| DNS UDP A/AAAA | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| DNS TCP initiated by client/system | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| IPv6 public transport or explicit environment block | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Confirmed system-proxy endpoint, if configured | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Unconfirmed private target follows ordinary policy | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Connection refused | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Timeout | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Cancellation | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Network change and fresh epoch | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Fragment/checksum behavior | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| DIRECT socket does not recur through Wintun | NOT RUN | NOT RUN | NOT RUN | NOT RUN |

If no IPv6 resolver/default route exists, mark the exact row `BLOCKED` or
`DEFERRED`; do not report IPv6 success.

### Safe counters and captures

| Counter | Before | After | Evidence/result |
| --- | --- | --- | --- |
| `tun_rx_packets` | NOT RUN | NOT RUN | NOT RUN |
| `tun_tx_packets` | NOT RUN | NOT RUN | NOT RUN |
| `captured_tcp_sessions` | NOT RUN | NOT RUN | NOT RUN |
| `captured_udp_datagrams` | NOT RUN | NOT RUN | NOT RUN |
| `route_direct` | NOT RUN | NOT RUN | NOT RUN |
| `route_proxy` | NOT RUN | NOT RUN | NOT RUN |
| `direct_tcp_connections` | NOT RUN | NOT RUN | NOT RUN |
| `direct_udp_associations` | NOT RUN | NOT RUN | NOT RUN |
| `unsupported_packets` | NOT RUN | NOT RUN | NOT RUN |
| `dropped_packets` | NOT RUN | NOT RUN | NOT RUN |
| `loop_prevention_drops` | NOT RUN | NOT RUN | NOT RUN |

| Capture | Interfaces/time range | SHA-256 | Evidence/result |
| --- | --- | --- | --- |
| `pktmon` ETL/PCAPNG | NOT RUN | NOT RUN | NOT RUN |
| Wireshark PCAPNG, if used | NOT RUN | NOT RUN | NOT RUN |

## 9. Ordered stop and restoration

| Ordered boundary | Evidence | Result |
| --- | --- | --- |
| New flows/workers stopped; callbacks unregistered | NOT RUN | NOT RUN |
| Owned split/default/shadow routes withdrawn with session alive | NOT RUN | NOT RUN |
| Wintun packet session ended | NOT RUN | NOT RUN |
| Owned addresses removed; exact MTU/metric restored | NOT RUN | NOT RUN |
| Owned adapter removal requested | NOT RUN | NOT RUN |
| Alias/LUID/GUID/ifIndex absence verified | NOT RUN | NOT RUN |
| Journal cleared only after all prior gates | NOT RUN | NOT RUN |
| Failure at a boundary blocked later destructive boundaries | NOT RUN | NOT RUN |
| Operator-owned management route unchanged | NOT RUN | NOT RUN |
| Physical defaults/DNS/proxy match baseline | NOT RUN | NOT RUN |
| RDP remained connected | NOT RUN | NOT RUN |
| OOB remained reachable | NOT RUN | NOT RUN |
| Independent `network_recover.exe --status` says no journal | NOT RUN | NOT RUN |

### Repeated lifecycle

| Cycle | Start/traffic | Ordered stop | Adapter/routes restored | Journal absent | RDP/OOB |
| ---: | --- | --- | --- | --- | --- |
| 1 | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| 2 | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| 3 | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |

## 10. Failure and recovery evidence

| Scenario | Journal before/after | Cleanup/recovery evidence | Result |
| --- | --- | --- | --- |
| Startup failure | NOT RUN | NOT RUN | NOT RUN |
| Forced process termination | NOT RUN | NOT RUN | NOT RUN |
| `runtime-active` watchdog retry | NOT RUN | NOT RUN | NOT RUN |
| Watchdog terminal failure | NOT RUN | NOT RUN | NOT RUN |
| Watchdog timeout retains journal | NOT RUN | NOT RUN | NOT RUN |
| Independent `--apply` exact recovery | NOT RUN | NOT RUN | NOT RUN |
| Conflicting/ambiguous state fails closed | NOT RUN | NOT RUN | NOT RUN |
| No-journal same-user watchdog result | NOT RUN | NOT RUN | NOT RUN |

| Failure record | Value/evidence |
| --- | --- |
| First failing boundary | NOT RUN |
| Exact error/exit code | NOT RUN |
| Watchdog JSONL path/hash | NOT RUN |
| Journal path/hash | NOT RUN |
| Pre/failure/post snapshots | NOT RUN |
| RDP status | NOT RUN |
| OOB status | NOT RUN |
| Manual actions taken | NOT RUN |
| Rollback result | NOT RUN |
| Residual adapter/address/route/settings | NOT RUN |
| Residual risks and owner | NOT RUN |
| Follow-up issue/fix commit | NOT RUN |

Never delete a journal merely to obtain a clean result.

## 11. Operator route disposition

This occurs only after application stop, exact cleanup, journal absence, and
RDP/OOB reachability are proven.

| Field | Value/evidence | Result |
| --- | --- | --- |
| Decision: retain or optional operator removal | NOT RUN | NOT RUN |
| Separate operator command and authorization | NOT RUN | NOT RUN |
| Exact route identity before action | NOT RUN | NOT RUN |
| Post-action best-route result | NOT RUN | NOT RUN |
| RDP status after action | NOT RUN | NOT RUN |
| OOB status after action | NOT RUN | NOT RUN |
| Application performed no route mutation | NOT RUN | NOT RUN |

## 12. Final assessment

| Field | Value/evidence |
| --- | --- |
| Tested scope | NOT RUN |
| Explicitly untested behavior | NOT RUN |
| Deferred Windows/Actions evidence | NOT RUN |
| Blockers | NOT RUN |
| Failures/defects | NOT RUN |
| Residual risks | NOT RUN |
| Final result (`PASS`/`FAIL`/`BLOCKED`/`DEFERRED`/`NOT RUN`) | NOT RUN |

Reviewer name/time/result: `NOT RUN`
