# Windows network recovery

This runbook applies to the Wintun DIRECT runtime and real-machine acceptance.
It is intentionally conservative because a full-capture route error can break
Microsoft Remote Desktop connectivity.

Do not treat access through the current RDP session as an out-of-band recovery
path. A VM hypervisor console, cloud serial console, or other independently
reachable administrative console must be confirmed before full capture.

## What the runtime changes

The current runtime may create:

- one application-owned Wintun adapter;
- `198.18.0.1/15` and `fd00:7373:7273::1/64` on that adapter;
- IPv4 split-default routes `0.0.0.0/1` and `128.0.0.0/1`;
- IPv6 split-default routes `::/1` and `8000::/1`; and
- snapshot-derived child/shadow capture routes for existing longer prefixes;
- explicit Wintun MTU and interface metric values for both IP families; and
- explicit physical-interface host routes for configured management exclusions.

All routes and addresses use Windows `ActiveStore`. The runtime does not:

- replace or delete the physical default route;
- modify Windows DNS-server settings;
- modify Windows Firewall;
- enable or modify the Windows system proxy; or
- install permanent per-destination host routes.

The runtime captures adapter, route, DNS, and read-only system-proxy state for
evidence before mutation. DNS and proxy snapshots are not signals that either
setting was modified. A confirmed local-network system-proxy endpoint remains
inside the Wintun capture plan; no physical host route is installed for it.

Native route/interface/address notifications invalidate the current network
epoch. The runtime blocks new DIRECT work, cancels old flows, performs the same
owned cleanup described here, and only then repeats snapshot, proxy resolution,
route validation, and adapter setup on the new network. It publishes that it
is leaving `running` before rollback begins. After the new change monitor is
active, bounded proxy capture is repeated and cached physical, management, and
confirmed system-proxy bindings are revalidated before `running` is published
again. A fresh route snapshot excludes only rows matching the exact Wintun
ifIndex and LUID, rebuilds the complete external shadow-prefix set after
planned exclusions, and compares it with the installed plan. The same
revalidation fingerprints external IPv4/IPv6 defaults with their route and
interface metrics, so a metric-only default selection change is not missed.
Any difference causes owned cleanup and a fresh startup attempt.

The `/1` route pair per family is supplemented by snapshot-derived child
prefixes for pre-existing longer LAN, host, VPN, or enterprise routes.
Existing `/32` and `/128` host routes cannot be split further, so the planner
requires proof that the Wintun route plus interface metric wins before it
installs a same-prefix shadow. Explicit management hosts are removed from the
shadow set and remain physical.

Windows may derive connected/local routes when the native address API assigns
the two Wintun addresses. They are operating-system consequences of those
addresses, not separately requested route-plan entries, and should disappear
when the addresses/adapter are removed. Include them in pre/running/post route
comparisons instead of misclassifying them as untracked permanent changes.

The runtime applies the configured MTU and metric through `SetIpInterfaceEntry`
and records the previous MTU, metric, and automatic-metric flag. Recovery
accepts either the exact applied state (which it restores) or the exact already
restored state (idempotent success); any other state fails ownership checks.
After each address create, startup polls `GetUnicastIpAddressEntry` every
500 ms for no more than 12 seconds. Only DAD state `Preferred` permits route
installation to continue; `Tentative` keeps waiting and every other state
fails startup and triggers rollback.

## Recovery journal

Before installing a Wintun address or route, the runtime creates:

```text
%APPDATA%\dev.shadowsocks-windows-rs.app\network-recovery-v1.json
```

The fixed filename remains the discovery path for compatibility. New journals
use internal schema version 2, which requires one explicit ownership state per
recorded object. Legacy version-1 journals are accepted only when all state
arrays are absent and are interpreted as the older applied-only format; an
older helper rejects schema version 2 before mutation.

The journal contains:

- the Wintun adapter name plus ifIndex/LUID/GUID/alias identity;
- the read-only pre-start adapter/route/DNS snapshot; and
- the complete expected MTU/metric setting, address, and route fields, each
  marked `Prepared` before mutation and `Applied` after native success.

If a journal already exists, a new runtime start fails with
`recovery-required`. It does not overwrite the journal or proceed to
route/address/interface mutation; cleanup is attempted for every newly
acquired epoch resource before the failure is returned.

Normal runtime cleanup removes recorded application-owned objects from its
trusted in-memory `RouteTransaction` rather than replaying either the journal or
the entire old route table. This trusted path includes physical management host
exclusions created by the live transaction. External recovery treats the
user-writable journal as a request, not as authority for elevated mutation.
Exact conflicts are rejected before mutation.

Journal creation and replacement use a synced temporary file and atomic,
write-through commit. The runtime durably writes `Prepared` before each
recorded route/address/interface-setting mutation. After native success it
marks the in-memory plan `Applied` before durably committing that transition,
so a normal journal-update failure can still roll back from authoritative
in-process state and reports a rollback failure preferentially.

For independent recovery, `Applied` permits only exact owned removal or
restoration. `Prepared` permits only proof that a route/address is still absent
or that an interface setting still equals its exact original state. An
exact-present route/address or applied-looking setting under `Prepared` is
ambiguous after interruption; recovery retains the journal and returns
`recovery-required` instead of deleting it. This is intentionally more
conservative than guessing ownership. The write-ahead sequence removes the old
post-mutation/pre-journal-record gap, but the acceptance watchdog and
out-of-band console remain mandatory because ambiguous recovery and other
machine/process failures are still possible.

Wintun 0.14.1 exposes no independent delete operation for an adapter reopened
after its creating process is gone. Normal cleanup polls every 50 ms for no
more than five seconds and requires that lookups by both alias and LUID report
absence. External recovery performs the same poll only when the journal
contains no external-interface route. If either identity remains, recovery
keeps the journal and returns `recovery-required` rather than reporting full
success.

Normal cleanup never performs a second pass by deserializing the journal. It
deregisters notifications, ends the Wintun session, rolls back through the
trusted in-memory transaction, calls `remove_owned` on the creating adapter
handle, and performs the bounded absence check. It clears the journal only
when rollback ownership remained verified, route rollback succeeded, adapter
removal succeeded, and alias/LUID absence was proved. Any incomplete step keeps
the journal.

## Recovery interfaces

While the desktop application is healthy, the restricted Tauri command
`recover_network` applies the recorded plan only while the runtime is stopped.
Before any mutation, desktop startup, the Tauri recovery command, and the
standalone helper's `--apply` path acquire the same fixed global named recovery
lease without waiting. If another holder is active, the operation returns a
runtime-active error before any journal or network mutation.

Runtime-manager startup teardown is additionally generation-scoped. A timeout
or failed-start cleanup cancels and joins only the generation that initiated
it; if a newer startup is active, a late cleanup from the older generation
cannot cancel, join, retire, or mark the newer runtime failed.

The Tauri recovery command and standalone `--apply` then use only the fixed
application-local Wintun API to open the adapter named by the journal. Before
applying any recorded route/address/interface-setting operation, recovery
requires all of the following:

- the bundled Wintun API loads and the journal alias opens successfully;
- the opened handle's LUID and ifIndex equal the journal values; and
- resolving that ifIndex produces the complete recorded
  ifIndex/LUID/GUID/alias identity.

The verified adapter handle remains alive throughout restoration, preventing a
disappearing adapter and reused ifIndex between verification and mutation. If
the adapter is absent or unopenable, the DLL cannot load, or any identity field
differs, recovery performs zero recorded network mutations, preserves the
journal, and returns `recovery-required`.

Successful adapter provenance authorizes only adapter-scoped recovery. The
elevated helper restores or verifies the verified Wintun adapter's addresses
and interface settings, plus routes whose recorded `route.interface` exactly
equals that verified TUN identity. A route aimed at any other interface—such
as a physical management host exclusion—is never mutated by external recovery.
The helper may restore Wintun-owned objects first, but if any external route is
present it then retains the journal and returns `recovery-required`. Normal
stop still removes a physical exclusion through its trusted in-memory
transaction.

The independent helper is intended for an interrupted or non-starting desktop
application. It accepts no caller-selected path:

```powershell
.\network_recover.exe --status
.\network_recover.exe --apply
```

`--status` is read-only and reports whether a journal exists, the recorded
adapter/interface identity, and the number of planned changes. `--apply`
requires an elevated console, verifies exact ownership, and is idempotent for
already-restored adapter-owned network objects. When the journal contains no
external-interface route, recovery drops the verified opened handle and
performs the same 50 ms, five-second alias/LUID absence check. A residual
crash-created adapter or any recorded external-interface route causes an
explicit non-zero recovery-required result, and the journal remains available
for investigation.

The helper does not restore DNS or firewall state because the runtime never
changes them. It also does not broadly delete adapters by name. After a crash,
inspect adapter state separately; startup deliberately refuses to continue if
the configured Wintun adapter still exists. Do not issue a broad
`Remove-NetAdapter` command without resolving and confirming the exact owned
target.

## Mandatory preflight

Perform these steps in order. The first phase is read-only.

### 1. Use an Actions-built artifact

Use Windows media from a successful GitHub Actions run after compilation,
unit tests, isolated Wintun smoke, DLL-hash verification, and packaging.
Record:

- repository commit;
- branch;
- Actions run URL and run ID;
- artifact name and digest;
- application executable hash;
- `network_recover.exe` hash; and
- bundled `wintun.dll` hash.

The Wintun DLL hash must be:

```text
e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
```

Do not transfer an ad hoc local build to the test VM.

Also record the DLL signature without changing state:

```powershell
Get-AuthenticodeSignature .\wintun.dll |
  Select-Object Status,StatusMessage,SignerCertificate,TimeStamperCertificate
```

The expected hash and a valid signature are separate checks; require both.

### 2. Confirm out-of-band recovery

Record the independent console type and verify that an administrator can use
it without the RDP network path. If this cannot be demonstrated, do not run
full capture.

### 3. Read-only Windows inspection

Run from PowerShell without changing state:

```powershell
Get-CimInstance Win32_OperatingSystem |
  Select-Object Caption,Version,BuildNumber,OSArchitecture

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Get-NetAdapter |
  Select-Object Name,InterfaceDescription,InterfaceIndex,Status,MacAddress,LinkSpeed

Get-NetRoute |
  Sort-Object AddressFamily,DestinationPrefix,RouteMetric |
  Select-Object AddressFamily,DestinationPrefix,NextHop,InterfaceIndex,RouteMetric,PolicyStore

Get-DnsClientServerAddress |
  Select-Object InterfaceIndex,AddressFamily,ServerAddresses

Find-NetRoute -RemoteIPAddress 1.1.1.1
Find-NetRoute -RemoteIPAddress 2606:4700:4700::1111

Get-NetTCPConnection -LocalPort 3389 -State Established |
  Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess

Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' |
  Select-Object ProxyEnable,ProxyServer,AutoConfigURL
```

An unavailable IPv6 route may be recorded as an environment limitation; it
must not be silently treated as IPv6 DIRECT success.

Never inspect, copy, or record the RDP password. The user enters it personally.

### 4. Save evidence snapshots

Create a dedicated acceptance directory and save complete pre-start output for:

- `Get-NetAdapter`;
- `Get-NetIPAddress`;
- `Get-NetRoute`;
- `Get-DnsClientServerAddress`;
- `Get-NetTCPConnection` for the current RDP session;
- system-proxy state; and
- `network_recover.exe --status`.

The acceptance record must name the directory and include hashes of these
files. Avoid embedding credentials or packet payloads.

### 5. Configure the RDP exclusion

Resolve the current RDP peer address from the established connection. Add only
that exact address to `tun.management_exclusions`:

```text
IPv4 peer -> <address>/32
IPv6 peer -> <address>/128
```

Confirm `Find-NetRoute` for that peer selects the physical interface and record
the interface index and gateway. Do not use a broad subnet when a host route
is sufficient.

### 6. Prepare an automatic rollback watchdog

Copy the Actions-built `network_recover.exe` to a stable local path whose hash
was recorded. Create an elevated one-shot watchdog that will run:

```powershell
& "C:\approved\path\network_recover.exe" --apply
```

The watchdog must be scheduled before full-capture startup, must not depend on
the RDP session remaining alive, and must have enough delay to finish the
planned observation. Record the scheduled task name, trigger time, executable
hash, and successful dry status check.

This procedure is not current authorization. Arm it only after the user gives
action-time approval and the independent console, exact RDP exclusion, saved
snapshots, and artifact hashes have all been verified.

Do not cancel the watchdog until normal stop and post-stop restoration have
both been verified.

### 7. Obtain action-time confirmation

Creating the Wintun adapter, loading/using the driver, adding even isolated
test routes, changing default/split-default routes, DNS, or firewall requires
explicit confirmation immediately before the action. A prior general request
does not replace this checkpoint.

If the out-of-band console, RDP exclusion, snapshots, recovery helper, or
watchdog is missing, stop. Do not enable full capture.

## Isolated Wintun smoke on the RDP test machine

Before the full runtime, repeat the Actions-built `wintun_smoke.exe` on the real
Windows machine. This is the appropriate first Wintun test through Microsoft
Remote Desktop, but it is still a privileged mutation and requires the
action-time confirmation above.

The smoke test:

- uses a unique adapter name;
- assigns `192.0.2.1/32`;
- adds only `198.51.100.2/32` and `198.51.100.3/32`;
- captures and responds to one UDP probe;
- captures a TCP SYN, injects SYN-ACK, and verifies the ACK;
- confirms default-route fingerprints are identical; and
- removes its routes, address, session, and adapter.

It does not change a default route or DNS and does not prove the full DIRECT
pipeline. Save stdout/stderr, pre/post snapshots, and cleanup verification.

## Full DIRECT start

Only after preflight and a new explicit confirmation:

1. set `mode` to `direct`;
2. verify the exact RDP host exclusion is persisted;
3. start `pktmon` or Wireshark on both Wintun and physical adapters;
4. start the runtime;
5. immediately verify RDP remains responsive through the physical exclusion;
6. run `network_recover.exe --status` and verify a journal is present;
7. compare adapters, addresses, routes, DNS, and system-proxy state;
8. run `Find-NetRoute` for ordinary IPv4/IPv6 targets and the RDP peer; and
9. perform the TCP, UDP, DNS, HTTPS, IPv4, and IPv6 checks in the acceptance
   template.

If a non-loopback system-proxy endpoint is configured, also record its
pre-capture `GetBestRoute2` result, prove the application connection reaches
Wintun, and prove only the replacement DIRECT socket uses the validated
physical interface. A broad private-address bypass is a failed acceptance
result.

The default custom resolver list is IPv4-only even though the configuration
contains `dns.ipv6 = true`. To test IPv6 DNS, add and record an explicit IPv6
resolver; otherwise record the expected same-family failure/block rather than
claiming IPv6 DNS success.

If any required route is wrong, a loop counter rises, RDP latency becomes
unstable, or packet capture shows DIRECT socket recapture, stop immediately.
If normal stop is unavailable, let the watchdog run or use the out-of-band
console to execute:

```powershell
.\network_recover.exe --apply
```

## Normal stop verification

After `stop_tunnel`:

1. wait for state `stopped`;
2. run `network_recover.exe --status` and expect no journal;
3. confirm the Wintun adapter no longer exists;
4. confirm all four split routes and configured management routes owned by the
   runtime are absent;
5. confirm application-owned Wintun addresses are absent;
6. compare physical default routes and DNS with the pre-start snapshots;
7. verify the recorded Windows system-proxy fields are unchanged; and
8. stop packet capture and save it.

Only then cancel the watchdog.

Repeat start/stop and these checks three times. Adapter counts, routes, and
recovery journals must return to the same baseline after every cycle.

## Failure recovery

### Runtime stopped, journal present

Use an elevated console:

```powershell
.\network_recover.exe --status
.\network_recover.exe --apply
.\network_recover.exe --status
```

Then compare current routes/addresses with the recorded pre-start evidence.

### RDP disconnected

Do not repeatedly reconnect while guessing at route commands. Use the confirmed
out-of-band console or wait for the watchdog. Run the fixed-path recovery
helper, inspect its exit code, and save output. Re-establish RDP only after
ordinary route selection is restored.

### Recovery reports an error

Leave the journal in place. Save:

- helper stdout/stderr and exit code;
- the journal itself;
- current `Get-NetAdapter`, `Get-NetIPAddress`, and `Get-NetRoute`; and
- the Actions artifact/commit identity.

Do not delete the journal or start another runtime. Investigate the exact
recorded objects from the out-of-band console.

## Acceptance evidence

Use [WINDOWS_ACCEPTANCE_TEMPLATE.md](WINDOWS_ACCEPTANCE_TEMPLATE.md). A valid
record includes:

- pre/post network snapshots;
- Actions run and artifact identity;
- Wintun DLL hash;
- isolated-smoke output;
- adapter statistics;
- runtime safe counters;
- `pktmon`/PCAPNG captures;
- commands and exit codes;
- three start/stop cycles;
- normal and independent recovery results; and
- explicit notes for unsupported or unavailable IPv6 behavior.

“A web page opened” is not sufficient evidence.
