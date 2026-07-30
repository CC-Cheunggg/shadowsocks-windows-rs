# Windows network recovery

This runbook applies to the Wintun DIRECT runtime and real-machine acceptance.
It is intentionally conservative because a full-capture route error can break
Microsoft Remote Desktop connectivity.

The mandatory ownership, management-path, lifecycle-ordering, watchdog, and
action-time gates are defined in
[DEVELOPMENT_CONSTRAINTS.md](DEVELOPMENT_CONSTRAINTS.md). Those constraints
take precedence if this runbook or an older architecture description differs.

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
- explicit Wintun MTU and interface metric values for both IP families.

Before the application starts, the operator creates and owns each configured
management `/32` or `/128` as one exact physical-interface host route in
`ActiveStore`. The application validates that route against the independently
discovered physical ifIndex, LUID, gateway, address family, and winning
best-route result. It never creates, modifies, deletes, or journals that
operator route.

All routes and addresses use Windows `ActiveStore`. The runtime does not:

- replace or delete the physical default route;
- modify Windows DNS-server settings;
- modify Windows Firewall;
- enable or modify the Windows system proxy; or
- install, repair, or remove a physical management host route.

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

Before calling `WintunCreateAdapter`, the runtime creates:

```text
%APPDATA%\dev.shadowsocks-windows-rs.app\network-recovery-v1.json
```

The fixed filename remains the discovery path for compatibility. New journals
use internal schema version 3. The durable sequence is:

```text
no journal
  -> adapter_creation_intent(alias + pre-generated GUID + snapshot)
  -> adapter_identity(ifIndex + LUID + GUID + alias, empty owned plan)
  -> one Prepared append or one Prepared-to-Applied transition per update
```

Version-2 and legacy records remain constrained compatibility inputs. They do
not grant ownership of an external-interface route, and any such claim is
rejected before mutation.

The journal contains:

- first, the fixed alias plus pre-generated adapter GUID intent, then the
  promoted ifIndex/LUID/GUID/alias identity;
- the read-only pre-start adapter/route/DNS snapshot; and
- the complete expected MTU/metric setting, address, and route fields, each
  marked `Prepared` before mutation and `Applied` after native success.

If a journal already exists, a new runtime start fails with
`recovery-required`. It does not overwrite the journal or proceed to
route/address/interface mutation; cleanup is attempted for every newly
acquired epoch resource before the failure is returned.

Normal runtime cleanup removes recorded application-owned objects from its
trusted in-memory `RouteTransaction` rather than replaying either the journal or
the entire old route table. Physical management host routes are absent from
both that transaction and the journal. External recovery treats the
user-writable journal as a request, not as authority for elevated mutation;
exact conflicts and every external-interface route claim are rejected before
mutation.

Journal creation and replacement use a synced temporary file and atomic,
write-through commit. The runtime durably writes `Prepared` before each
recorded route/address/interface-setting mutation. After native success it
marks the in-memory plan `Applied` before durably committing that transition,
so a normal journal-update failure can still roll back from authoritative
in-process state and reports a rollback failure preferentially.

For independent recovery, both `Prepared` and `Applied` use exact
reconciliation because a process can stop after native success but before the
`Applied` transition is durable. Exact absence or an exact original interface
setting is an idempotent no-op. A unique exact applied route/address is removed,
and an exact applied interface setting is restored. A duplicate, partial, or
conflicting state is never guessed at: recovery retains the journal and returns
`recovery-required`. The acceptance watchdog and out-of-band console remain
mandatory because fail-closed recovery can intentionally leave evidence and
owned state for investigation.

Wintun 0.14.1 exposes no independent delete operation for an adapter reopened
after its creating process is gone. Normal cleanup polls every 50 ms for no
more than five seconds and proves absence against alias, LUID, GUID, and
ifIndex. Intent-only and full-journal recovery likewise use all available
selectors and fail closed on reuse, conflict, or ambiguity. External-interface
route claims are rejected before any recovery mutation.

Normal cleanup never performs a second pass by deserializing the journal. Its
destructive boundaries are ordered:

1. stop new flows/workers and unregister callbacks;
2. withdraw every owned split-default and shadow capture route while the
   Wintun session remains alive;
3. end the Wintun packet session;
4. remove owned Wintun addresses and restore exact MTU/metric settings;
5. remove the creating process's owned adapter;
6. verify absence by alias, LUID, GUID, and ifIndex; and
7. clear the journal.

Failure or unproved completion at one boundary prevents the later destructive
boundaries. The fallback path retains downstream handles for process-lifetime
recovery rather than crossing an unsafe boundary, and any incomplete cleanup
keeps the journal.

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
Current, previous, and legacy journal forms containing any external-interface
route are rejected on load before mutation. Normal stop likewise has no
physical management route in its owned transaction.

The independent helper is intended for an interrupted or non-starting desktop
application. It accepts no caller-selected path:

```powershell
.\network_recover.exe --status
.\network_recover.exe --apply
.\network_recover.exe --watchdog
```

`--status` is read-only and reports whether a journal exists, the recorded
adapter/interface identity, and the number of planned changes. `--apply`
requires an elevated console, verifies exact ownership, and is idempotent for
already-restored adapter-owned network objects. Recovery drops the verified
opened handle and performs the same bounded four-selector absence proof. A
residual crash-created adapter, identity conflict, or recorded
external-interface route causes an explicit non-zero recovery-required result,
and the journal remains available for investigation.

`--watchdog` uses a fixed five-minute deadline and a fixed two-second retry
interval; neither value nor any journal, DLL, manifest, or audit path is
caller-configurable. The same deadline clock starts immediately after the
watchdog action is recognized and therefore includes user-context, audit, and
asset preflight. It is a fail-closed attempt/commit boundary: at or after the
deadline the helper starts no new recovery attempt and never authorizes
journal clearing. A synchronous Windows recovery call already in flight is
not unsafely terminated; when it returns after the deadline, the helper records
timeout, exits non-zero, and retains the journal. Before its first recovery
attempt it:

1. reads the process token SID, rejects LocalSystem, LocalService, and
   NetworkService, and requires `%APPDATA%` to match the current token's
   `FOLDERID_RoamingAppData`;
2. derives the journal and audit paths below the same fixed application config
   directory used by the desktop application;
3. requires a provisioning-time `WATCHDOG-CONTEXT.json` beside the helper and
   requires its strict schema to contain the same SHA-256 token-SID
   fingerprint, so a different ordinary user's valid `%APPDATA%` cannot be
   mistaken for the desktop user's empty config;
4. requires `network_recover.exe`, `wintun.dll`, and `SHA256SUMS` beside the
   running helper, rejects symlinks and directory traversal, strictly parses
   every manifest filename, and requires exactly one case-insensitive mapping
   with the exact spelling for each of `network_recover.exe` and `wintun.dll`;
5. re-hashes both files, verifies both manifest hashes, and also requires the
   compiled approved Wintun hash; and
6. creates and synchronously writes a unique audit log before recovery can
   mutate any network object.

Other manifest rows are accepted only when they are unique, safe, single-file
basenames; the watchdog never resolves or loads them. Absolute paths, drive or
alternate-stream syntax, either slash, dot traversal, Windows device names,
duplicate case-insensitive names, malformed hashes, and unsafe name
punctuation are rejected.

Every attempt re-verifies the same staged assets and calls only the constrained
recovery implementation described above. `runtime-active` is the only retry
state. Recovery-required, identity ambiguity, journal decode failure, asset or
audit failure, and every other recovery error are terminal. A verified
recovery retains both the lease and journal until its successful final audit
decision has been synchronized. That write-ahead record is
`journal_clear_authorized` / `recovery_verified` /
`success_after_journal_clear`; it does not claim that the journal is already
gone. The helper then re-reads the clock after that synchronized write; if the
deadline has been reached, it records timeout and retains the journal. Only a
still-in-bounds result may clear the journal and verify its absence before
exit 0. A clear failure appends terminal
`journal_clear` evidence and exits non-zero. This ordering ensures that an
audit write failure happens while the journal is still retained. Timeout is
non-zero and never clears the journal. A verified no-journal result is
successful only after the current user/config, provisioned SID binding, final
audit synchronization, and a fresh still-in-bounds clock read all pass.

The unique JSONL audit files are retained at:

```text
%APPDATA%\dev.shadowsocks-windows-rs.app\network-recovery-watchdog-audit\watchdog-<run-id>.jsonl
```

Each record has the audit schema/version, watchdog run ID, UTC Unix
milliseconds, attempt number, elapsed and deadline milliseconds, a bounded
state enum, retry decision, final status/exit class when applicable, the
helper/Wintun hashes after verification, and a SHA-256 fingerprint of the
current token SID. It never contains a path, username, address, configuration,
credential, or raw operating-system error text. Every record is flushed and
synchronized; logs, including timeout logs, are not automatically deleted.

The helper does not restore DNS or firewall state because the runtime never
changes them. It also does not broadly delete adapters by name. After a crash,
inspect adapter state separately; startup deliberately refuses to continue if
the configured Wintun adapter still exists. Do not issue a broad
`Remove-NetAdapter` command without resolving and confirming the exact owned
target.

## Mandatory preflight

Perform these phases in this exact order. Do not reuse an old artifact, hash,
route observation, RDP tuple, or authorization as evidence for a new run.

### 1. Obtain a newly built artifact

Obtain the artifact from the new successful Windows Actions run selected for
this acceptance attempt. Do not transfer an ad hoc local build or an artifact
from an earlier run to the test machine. Record the commit, ref, Actions run
URL/ID/attempt, artifact name/ID/digest, and downloaded ZIP SHA-256.

### 2. Verify artifact identity and delivery gates

Before copying any executable to the target, verify and record:

- the ZIP SHA-256 and the artifact service digest;
- every row and file hash in `SHA256SUMS`;
- every field in `BUILD-INFO`, including the setup filename and hash;
- separate hashes for `shadowsocks-windows-rs.exe`,
  `network_recover.exe`, and `wintun_smoke.exe`;
- exactly one `*-setup.exe`, the raw desktop EXE, both helpers, `wintun.dll`,
  `LICENSE.txt`, `THIRD_PARTY_NOTICES.md`, and `WINTUN-LICENSE.txt`;
- the Windows Actions evidence that the three Rust EXEs passed static MSVC CRT
  inspection and PE subsystem values 2/3/3;
- the Wintun DLL pinned hash and valid Authenticode signature; and
- the NSIS build/config evidence (`downloadBootstrapper`, silent mode) without
  treating it as proof of installation behavior.

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

The raw EXE, NSIS setup, and staging directory are separate deliverables. Do
not claim that the NSIS setup contains either helper unless a later Windows
installation-layout check proves it. Do not claim that Actions proves a silent
installer UI, installed resource location, or real application startup.

### 3. Capture a read-only baseline and snapshots

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

### 4. Prove an independent out-of-band path

Record the independent console type and demonstrate that an administrator can
reach and use it without the RDP network path. The current RDP session is not
out-of-band. If this proof is unavailable, do not create the management route
or run any Wintun mutation.

### 5. Create and configure the operator-owned management route

Resolve the current RDP peer from the established TCP connection. The operator,
not the application, creates exactly one matching physical `/32` or `/128`
route in `ActiveStore`. Substitute the recorded values; angle-bracket tokens
are deliberately non-runnable placeholders:

```powershell
$ManagementPeer = [Net.IPAddress]::Parse("<RDP_REMOTE_IP>")
$ManagementPrefix = if (
  $ManagementPeer.AddressFamily -eq
    [Net.Sockets.AddressFamily]::InterNetwork
) {
  "$ManagementPeer/32"
} else {
  "$ManagementPeer/128"
}
$RouteAddressFamily = if (
  $ManagementPeer.AddressFamily -eq
    [Net.Sockets.AddressFamily]::InterNetwork
) {
  "IPv4"
} else {
  "IPv6"
}
$PhysicalIfIndex = [int]"<PHYSICAL_INTERFACE_INDEX>"
$PhysicalGateway = [Net.IPAddress]::Parse("<PHYSICAL_GATEWAY>")
$ManagementRouteMetric = [uint32]"<MANAGEMENT_ROUTE_METRIC>"

New-NetRoute `
  -PolicyStore ActiveStore `
  -DestinationPrefix $ManagementPrefix `
  -InterfaceIndex $PhysicalIfIndex `
  -NextHop $PhysicalGateway `
  -RouteMetric $ManagementRouteMetric
```

Verify the operator action separately:

```powershell
$exactRoute = @(
  Get-NetRoute `
    -PolicyStore ActiveStore `
    -DestinationPrefix $ManagementPrefix `
    -AddressFamily $RouteAddressFamily
)
if ($exactRoute.Count -ne 1) {
  throw "Expected exactly one ActiveStore management host route."
}
$exactRoute |
  Select-Object AddressFamily,DestinationPrefix,InterfaceIndex,NextHop,
    RouteMetric,PolicyStore
$bestRoute = Find-NetRoute -RemoteIPAddress $ManagementPeer
$bestRoute
if (
  $exactRoute[0].InterfaceIndex -ne $PhysicalIfIndex -or
  ([string]$exactRoute[0].NextHop) -ne ([string]$PhysicalGateway) -or
  $bestRoute.InterfaceIndex -ne $PhysicalIfIndex
) {
  throw "The exact operator route does not win on the expected interface."
}
```

Record the physical interface LUID from the same native identity evidence used
by the application. Add only `$ManagementPrefix` to
`tun.management_exclusions`. Do not use a broader subnet. The application will
validate the exact route; it will not install, repair, journal, or remove it.

### 6. Revalidate action-time state and prepare the watchdog

Immediately before the mutation authorization in phase 7, recollect the RDP
five-tuple and freshly verify the management address family, exact
`ActiveStore` route count, physical ifIndex/LUID/gateway, and winning
`Find-NetRoute` result. Save this evidence with a new timestamp. A prior
baseline, screenshot, or earlier successful verification is not sufficient.

Use this one procedure only from the same interactive Windows user that runs
the desktop application. The commands below are an acceptance-time procedure,
not authorization for DIRECT mutation. Set the placeholder artifact directory
to the already verified extracted Actions artifact:

```powershell
$artifactDirectory = "<VERIFIED_ARTIFACT_DIRECTORY>"
$stage = "C:\Program Files\Shadowsocks Windows RS\recovery"
$taskName = "ShadowsocksDirectRecoveryWatchdog"
$approvedWintunHash =
  "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User.Value
if ($sid -in @("S-1-5-18", "S-1-5-19", "S-1-5-20")) {
  throw "The watchdog must not run as a Windows service identity."
}
$sidBytes = [byte[]]::new($identity.User.BinaryLength)
$identity.User.GetBinaryForm($sidBytes, 0)
$sidHasher = [Security.Cryptography.SHA256]::Create()
try {
  $sidFingerprint = (
    [BitConverter]::ToString($sidHasher.ComputeHash($sidBytes))
  ).Replace("-", "").ToLowerInvariant()
}
finally {
  $sidHasher.Dispose()
}
$knownAppData = [Environment]::GetFolderPath(
  [Environment+SpecialFolder]::ApplicationData
)
if (-not $env:APPDATA -or $knownAppData -ine $env:APPDATA) {
  throw "APPDATA does not match the current user profile."
}

New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item -LiteralPath "$artifactDirectory\network_recover.exe" `
  -Destination "$stage\network_recover.exe"
Copy-Item -LiteralPath "$artifactDirectory\wintun.dll" `
  -Destination "$stage\wintun.dll"
Copy-Item -LiteralPath "$artifactDirectory\SHA256SUMS" `
  -Destination "$stage\SHA256SUMS"
$contextBinding = [ordered]@{
  schema = "dev.shadowsocks-windows-rs.watchdog-context"
  version = 1
  user_sid_sha256 = $sidFingerprint
} | ConvertTo-Json -Compress
[IO.File]::WriteAllText(
  (Join-Path $stage "WATCHDOG-CONTEXT.json"),
  "$contextBinding`n",
  [Text.Encoding]::ASCII
)

$requiredStageFiles = @(
  "$stage\network_recover.exe",
  "$stage\wintun.dll",
  "$stage\SHA256SUMS",
  "$stage\WATCHDOG-CONTEXT.json"
)
foreach ($requiredStageFile in $requiredStageFiles) {
  $item = Get-Item -LiteralPath $requiredStageFile -Force
  if (
    -not ($item -is [IO.FileInfo]) -or
    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
  ) {
    throw "The protected watchdog stage contains a non-regular/reparse file."
  }
}
Get-Acl -LiteralPath $stage |
  Format-List Owner,AccessToString

$actualWintunHash = (
  Get-FileHash -Algorithm SHA256 -LiteralPath "$stage\wintun.dll"
).Hash.ToLowerInvariant()
if ($actualWintunHash -ne $approvedWintunHash) {
  throw "The staged Wintun DLL hash is not approved."
}
$sourceHelperHash = (
  Get-FileHash -Algorithm SHA256 `
    -LiteralPath "$artifactDirectory\network_recover.exe"
).Hash
$stagedHelperHash = (
  Get-FileHash -Algorithm SHA256 `
    -LiteralPath "$stage\network_recover.exe"
).Hash
if ($sourceHelperHash -ne $stagedHelperHash) {
  throw "The staged recovery helper differs from the verified artifact."
}

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
  throw "The fixed watchdog task name already exists; inspect it and stop."
}
$rollbackAt = (Get-Date).AddMinutes(15)
$action = New-ScheduledTaskAction `
  -Execute "$stage\network_recover.exe" `
  -Argument "--watchdog" `
  -WorkingDirectory $stage
$trigger = New-ScheduledTaskTrigger -Once -At $rollbackAt
$principal = New-ScheduledTaskPrincipal `
  -UserId $sid `
  -LogonType S4U `
  -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
  -StartWhenAvailable `
  -ExecutionTimeLimit (New-TimeSpan -Minutes 7) `
  -MultipleInstances IgnoreNew
Register-ScheduledTask `
  -TaskName $taskName `
  -Action $action `
  -Trigger $trigger `
  -Principal $principal `
  -Settings $settings | Out-Null

$task = Get-ScheduledTask -TaskName $taskName
try {
  $scheduledSid = (
    [Security.Principal.SecurityIdentifier]$task.Principal.UserId
  ).Value
}
catch {
  $scheduledSid = (
    [Security.Principal.NTAccount]$task.Principal.UserId
  ).Translate([Security.Principal.SecurityIdentifier]).Value
}
if (
  $scheduledSid -ne $sid -or
  $task.Principal.LogonType -ne "S4U" -or
  $task.Actions.Count -ne 1 -or
  $task.Actions[0].Execute -ine "$stage\network_recover.exe" -or
  $task.Actions[0].Arguments -ne "--watchdog"
) {
  throw "The scheduled watchdog identity or fixed action is wrong."
}

& "$stage\network_recover.exe" --status
if ($LASTEXITCODE -ne 0) {
  throw "The read-only recovery status check failed."
}
$beforeRun = Get-ScheduledTaskInfo -TaskName $taskName
Start-ScheduledTask -TaskName $taskName
$dryRunDeadline = [DateTime]::UtcNow.AddSeconds(30)
do {
  Start-Sleep -Seconds 1
  $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
  $taskState = (Get-ScheduledTask -TaskName $taskName).State
} while (
  (
    $taskInfo.LastRunTime -le $beforeRun.LastRunTime -or
    $taskState -eq "Running"
  ) -and
  [DateTime]::UtcNow -lt $dryRunDeadline
)
if (
  $taskInfo.LastRunTime -le $beforeRun.LastRunTime -or
  $taskState -eq "Running" -or
  $taskInfo.LastTaskResult -ne 0
) {
  throw "The scheduled same-user no-journal dry run failed."
}
$auditDirectory = Join-Path $knownAppData `
  "dev.shadowsocks-windows-rs.app\network-recovery-watchdog-audit"
$dryAudit = Get-ChildItem -LiteralPath $auditDirectory `
  -File -Filter "watchdog-*.jsonl" |
  Sort-Object LastWriteTimeUtc -Descending |
  Select-Object -First 1
$dryFinal = Get-Content -LiteralPath $dryAudit.FullName |
  Select-Object -Last 1 |
  ConvertFrom-Json
if (
  $dryFinal.final_status -ne "no_journal" -or
  $dryFinal.exit_class -ne "success" -or
  $dryFinal.user_sid_fingerprint -ne $sidFingerprint
) {
  throw "The scheduled dry-run audit did not prove same-user no-journal success."
}

[pscustomobject]@{
  TaskName = $taskName
  TriggerUtc = $rollbackAt.ToUniversalTime().ToString("o")
  UserSidSha256 = $sidFingerprint
  HelperSha256 = $stagedHelperHash.ToLowerInvariant()
  WintunSha256 = $actualWintunHash
}
```

Save the ACL output and confirm that an unprivileged user cannot replace files
in the stage. If that cannot be proved, do not arm the watchdog; hash checks do
not close a later writable-stage replacement race.

The S4U task is bound to the same user SID but does not depend on the RDP
connection remaining attached. Its manual dry run is permitted only while
`--status` reports no journal; it must finish with the audited `no_journal`
success before any DIRECT mutation. Verify that the future trigger still
exists after the dry run. The fixed example trigger is 15 minutes after
registration and Task Scheduler limits the helper process to seven minutes; if
that does not cover the explicitly approved observation, stop and prepare a
new recorded change plan rather than silently changing the task.

After phase-7 action-time authorization, start full capture early enough to run
`--status` and prove that the same user's journal exists before the recorded
trigger. If the journal is not present before the trigger, stop the acceptance
attempt; a watchdog that already returned `no_journal` is not armed. Save the
task definition, trigger time, hashes, dry-run exit result, and dry-run audit
log with the acceptance evidence.

This procedure is not current DIRECT authorization. Provisioning and arming the
scheduled task are themselves operator actions that require their own recorded
approval, and they occur only after the independent console, exact operator
route, fresh state, snapshots, and artifact hashes have been verified.

Do not cancel the watchdog until normal stop and post-stop restoration have
both been verified.

### 7. Obtain action-time confirmation

Creating the Wintun adapter, loading/using the driver, adding even isolated
test routes, changing default/split-default routes, DNS, or firewall requires
explicit confirmation immediately before the action. A prior general request
does not replace this checkpoint.

If the out-of-band console, RDP exclusion, snapshots, recovery helper, or
watchdog is missing, stop. Do not enable full capture.

## Phase 8 — Authorized mutation, ordered cleanup, and recovery

### Isolated Wintun smoke on the RDP test machine

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

### Full DIRECT start

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

### Normal stop verification

After `stop_tunnel`:

1. wait for state `stopped`;
2. run `network_recover.exe --status` and expect no journal;
3. confirm the Wintun adapter no longer exists;
4. confirm all owned split-default/shadow routes are absent and the
   operator-owned management route is unchanged;
5. confirm application-owned Wintun addresses are absent;
6. confirm exact Wintun MTU/metric restoration and four-selector adapter
   absence;
7. compare physical default routes and DNS with the pre-start snapshots;
8. verify the recorded Windows system-proxy fields are unchanged;
9. verify RDP and the independent console remain reachable; and
10. stop packet capture and save it.

Only then cancel the watchdog.

Repeat start/stop and these checks three times. Adapter counts, routes, and
recovery journals must return to the same baseline after every cycle.

### Failure recovery

#### Runtime stopped, journal present

Use an elevated console:

```powershell
.\network_recover.exe --status
.\network_recover.exe --apply
.\network_recover.exe --status
```

Then compare current routes/addresses with the recorded pre-start evidence.

#### RDP disconnected

Do not repeatedly reconnect while guessing at route commands. Use the confirmed
out-of-band console or wait for the watchdog. Run the fixed-path recovery
helper, inspect its exit code, and save output. Re-establish RDP only after
ordinary route selection is restored.

#### Recovery reports an error

Leave the journal in place. Save:

- helper stdout/stderr and exit code;
- the journal itself;
- current `Get-NetAdapter`, `Get-NetIPAddress`, and `Get-NetRoute`; and
- the Actions artifact/commit identity.

Do not delete the journal or start another runtime. Investigate the exact
recorded objects from the out-of-band console.

## Phase 9 — Operator disposition of the management route

After the application is stopped, cleanup is verified, the journal is absent,
and both RDP and the independent console are reachable, the operator decides
whether to retain the exact host route. Retention is valid. Optional deletion
is a separate operator action, never application cleanup or unattended
watchdog behavior:

```powershell
$ManagementPeer = [Net.IPAddress]::Parse("<RDP_REMOTE_IP>")
$ManagementPrefix = if (
  $ManagementPeer.AddressFamily -eq
    [Net.Sockets.AddressFamily]::InterNetwork
) {
  "$ManagementPeer/32"
} else {
  "$ManagementPeer/128"
}
$RouteAddressFamily = if (
  $ManagementPeer.AddressFamily -eq
    [Net.Sockets.AddressFamily]::InterNetwork
) {
  "IPv4"
} else {
  "IPv6"
}
$PhysicalIfIndex = [int]"<PHYSICAL_INTERFACE_INDEX>"
$PhysicalGateway = [Net.IPAddress]::Parse("<PHYSICAL_GATEWAY>")
$exactRoute = @(
  Get-NetRoute `
    -PolicyStore ActiveStore `
    -DestinationPrefix $ManagementPrefix `
    -AddressFamily $RouteAddressFamily |
    Where-Object {
      $_.InterfaceIndex -eq $PhysicalIfIndex -and
      ([string]$_.NextHop) -eq ([string]$PhysicalGateway)
    }
)
if ($exactRoute.Count -ne 1) {
  throw "Refusing optional removal without one exact operator-owned route."
}
$exactRoute | Remove-NetRoute -Confirm
```

Record `RETAINED`, `REMOVED BY OPERATOR`, or `BLOCKED`, along with the command,
timestamp, route identity, post-action best-route result, RDP status, and
out-of-band status. The application must never be credited with either
retaining or deleting this route.

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
