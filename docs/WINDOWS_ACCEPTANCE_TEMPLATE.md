# Windows DIRECT acceptance record

Copy this file for each real-Windows acceptance run. Do not mark an item passed
without attaching or linking the named evidence. Do not place passwords,
credentials, packet payloads, cookies, authorization headers, or complete
sensitive DNS messages in the record.

## Run identity

| Field | Value |
| --- | --- |
| Date/time and timezone | |
| Tester | |
| VM/machine identifier | |
| Windows edition/version/build/architecture | |
| Repository commit | |
| Branch | |
| GitHub Actions run URL/ID | |
| Artifact name/digest | |
| Application SHA-256 | |
| `network_recover.exe` SHA-256 | |
| `wintun.dll` SHA-256 | |
| `wintun.dll` Authenticode status/signer evidence | |
| `WINTUN-LICENSE.txt` SHA-256 | |

Expected Wintun DLL SHA-256:
`e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`.
Expected Wintun Prebuilt Binaries License SHA-256:
`183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2`.

## Safety gates

| Gate | Evidence | Result |
| --- | --- | --- |
| Artifact came from the successful Actions build after compile/test/package | | |
| Administrator status checked without changing state | | |
| Independent VM/serial/out-of-band console demonstrated | | |
| Current RDP peer identified | | |
| Exact RDP `/32` or `/128` management exclusion persisted | | |
| Pre-start adapter/route/DNS/proxy snapshots saved | | |
| Fixed-path recovery binary hash verified | | |
| Recovery records confirmed creates and validates stable adapter identity | | |
| Elevated automatic rollback watchdog armed | | |
| Explicit action-time approval received before isolated smoke | | |
| Explicit action-time approval received before full capture | | |

If any required gate is not passed, full-capture testing must not proceed.

## Read-only baseline

Attach or link complete output:

- [ ] `Get-CimInstance Win32_OperatingSystem`
- [ ] administrator-role check
- [ ] `Get-NetAdapter`
- [ ] `Get-NetIPAddress`
- [ ] `Get-NetRoute`
- [ ] `Get-DnsClientServerAddress`
- [ ] `Find-NetRoute -RemoteIPAddress 1.1.1.1`
- [ ] IPv6 `Find-NetRoute` result or explicit unavailable status
- [ ] established RDP connection tuple
- [ ] Windows system-proxy state
- [ ] `network_recover.exe --status`

Baseline evidence directory and digest:

```text

```

## Actions-built isolated Wintun smoke

| Check | Evidence | Result |
| --- | --- | --- |
| Unique temporary adapter created | | |
| UDP probe observed in receive ring | | |
| Injected UDP response reached originating socket | | |
| TCP SYN observed | | |
| Injected SYN-ACK completed connect and ACK was captured | | |
| Default-route fingerprint unchanged | | |
| Temporary `/32` routes and address removed | | |
| Packet session closed and adapter removed | | |
| Post-smoke cleanup verification found no residual adapter | | |

Attach stdout/stderr and pre/post snapshots:

```text

```

## Full DIRECT runtime

Configuration summary without credentials:

```text
mode: direct
tun interface name:
MTU:
Windows Wintun interface MTU:
IPv6 enabled:
DNS source:
DNS resolver address families:
TCP DNS enabled:
TCP timeout:
UDP idle timeout:
management exclusion(s):
```

If IPv6 DNS is in scope, record the explicit IPv6 resolver. The default custom
resolver list is IPv4-only; without an IPv6 resolver the expected result is an
explicit same-family failure/block, not IPv6 DNS success.

### Route and adapter checks

| Check | Evidence | Result |
| --- | --- | --- |
| One expected Wintun adapter exists | | |
| Wintun IPv4/IPv6 addresses match the owned plan | | |
| Windows Wintun interface MTU matches the configured value and is restored on stop | | |
| IPv4 split-default routes select Wintun | | |
| IPv6 split-default routes select Wintun | | |
| Original physical default routes remain | | |
| RDP peer selects physical interface and remains connected | | |
| Ordinary `Find-NetRoute` targets select Wintun | | |
| Every pre-existing prefix longer than `/1` has an ownership-safe Wintun shadow or explicit approved exclusion | | |
| DNS settings did not change | | |
| Recorded Windows system-proxy fields did not change | | |
| Every non-loopback system-proxy exception is an exact endpoint validated against the pre-capture physical route | | |
| No blanket private-address DIRECT exemption is present | | |
| Recovery journal is present while running | | |

### Traffic checks

For each row record the exact command/tool, target class, timestamp, result,
relevant flow ID, before/after counters, and capture file. Redact sensitive
application data.

| Traffic | Wintun capture | Router DIRECT | Physical outbound | Return injected | Result |
| --- | --- | --- | --- | --- | --- |
| HTTPS/TCP | | | | | |
| Plain TCP test | | | | | |
| UDP test | | | | | |
| DNS UDP | | | | | |
| DNS TCP initiated by client/system | | | | | |
| Confirmed local-network system-proxy endpoint, if configured | | | | | |
| Unconfirmed private target remains subject to ordinary policy | | | | | |
| IPv4 | | | | | |
| IPv6, or explicit captured-and-blocked result | | | | | |
| Connection refused | | | | | |
| Timeout | | | | | |
| Cancellation | | | | | |
| Network change | | | | | |

### Safe counters

Record before and after:

| Counter | Before | After | Expected interpretation |
| --- | ---: | ---: | --- |
| `tun_rx_packets` | | | Captured packets increased |
| `tun_tx_packets` | | | Reconstructed/injected packets increased |
| `captured_tcp_sessions` | | | New accepted TCP SYN flows |
| `captured_udp_datagrams` | | | Captured UDP datagrams |
| `route_direct` | | | DIRECT routing decisions |
| `route_proxy` | | | Must remain zero in direct-mode acceptance |
| `system_proxy_detected` | | | Read-only discovery found a configured proxy candidate |
| `route_direct_system_proxy` | | | Only an exact validated local-network proxy endpoint used the mandatory DIRECT exception |
| `direct_tcp_connections` | | | Successful native TCP connects |
| `direct_udp_associations` | | | Successful native UDP associations |
| `unsupported_packets` | | | Explain every observed increase |
| `dropped_packets` | | | Explain every observed increase |
| `loop_prevention_drops` | | | Expected zero; non-zero is a failure signal |

Counter evidence:

```text

```

### Packet capture

| Capture | Interface(s) | Time range | SHA-256 | Notes |
| --- | --- | --- | --- | --- |
| `pktmon` ETL/PCAPNG | | | | |
| Wireshark PCAPNG, if used | | | | |

Confirm:

- [ ] application-origin packets first appear at Wintun;
- [ ] DIRECT socket traffic appears on the physical adapter;
- [ ] DIRECT source endpoints do not recur through Wintun;
- [ ] return traffic is reconstructed and injected through Wintun; and
- [ ] captures contain no unintended unredacted sensitive payload in the
  shared acceptance bundle.

## Stop and restoration

| Check | Evidence | Result |
| --- | --- | --- |
| Runtime reached `stopped` | | |
| Recovery journal absent | | |
| Owned Wintun adapter absent | | |
| Owned Wintun addresses absent | | |
| Owned split routes absent | | |
| Owned management routes absent | | |
| Physical defaults match baseline | | |
| DNS state matches baseline | | |
| Recorded Windows system-proxy fields match baseline | | |
| Independent `network_recover --status` reports no journal | | |
| Watchdog cancelled only after verification | | |

Post-stop evidence directory and digest:

```text

```

## Repeated lifecycle

| Cycle | Start succeeded | Traffic evidence | Stop succeeded | Adapter baseline restored | Route baseline restored | Journal absent |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | | | | | | |
| 2 | | | | | | |
| 3 | | | | | | |

## Independent recovery exercise

Describe the controlled failure used without risking the RDP path:

```text

```

| Check | Evidence | Result |
| --- | --- | --- |
| Journal existed before recovery | | |
| `network_recover.exe --status` identified confirmed owned changes after the ownership gate | | |
| `network_recover.exe --apply` succeeded | | |
| Journal removed only after successful cleanup | | |
| Routes/addresses returned to baseline | | |
| RDP and out-of-band access remained available | | |

## Final disposition

Choose exactly one:

- [ ] PASS for the tested scope
- [ ] FAIL
- [ ] BLOCKED / NOT RUN

Unsupported, partially supported, or untested behavior:

```text

```

Failures and follow-up issues:

```text

```

Reviewer and review time:

```text

```
