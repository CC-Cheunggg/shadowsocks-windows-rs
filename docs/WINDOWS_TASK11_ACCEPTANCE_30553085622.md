# Windows DIRECT Task 11 acceptance record — run 30553085622

This is the run-specific record derived from
[WINDOWS_ACCEPTANCE_TEMPLATE.md](WINDOWS_ACCEPTANCE_TEMPLATE.md). It covers
only Task 11's read-only refresh and raw-EXE WebView2 bootstrap check. Tasks
12–14 and all Windows network mutation remained `NOT RUN`.

## 1. Record identity

| Field | Value | Evidence/result |
| --- | --- | --- |
| Test time | 2026-07-31, Asia/Shanghai (UTC+08:00) | PASS |
| Repository commit | `85c87a7e216f8d2de346e77240a2cd53166bba46` | PASS |
| Branch/ref | `codex/direct-wintun-slice` | PASS |
| Windows target | `177.5.74.14`; `CLOUD-TI1RM2-2D` | PASS |
| OS | Windows Server 2022 Datacenter Evaluation, build 20348, x64 | PASS |
| Current user | `CLOUD-TI1RM2-2D\Administrator` | PASS |
| Token SID | `S-1-5-21-2232602958-3163185423-148646785-500` | PASS |
| Administrator/session | Elevated; interactive RDP session `2` | PASS |
| Final disposition | `BLOCKED` | Runtime bootstrap failed; main application did not start |

## 2. Artifact provenance and Windows verification

| Field | Value | Evidence/result |
| --- | --- | --- |
| Actions run/attempt | `30553085622` / `1`; job `90906464758` | PASS |
| Artifact | ID `8763958284`; `sswr-windows-x86_64-msvc-30553085622-1` | PASS |
| GitHub digest | `sha256:b49998bbe08a0c496ddacfae8d12ab5f1d7cba1866a9fc594f3e3158a04aec43` | PASS |
| Original local ZIP | `/private/tmp/sswr-task10-30553085622-50reVT/sswr-windows-x86_64-msvc-30553085622-1.zip` | Retained read-only; no repack |
| Windows delivery | Authenticated connector temporary download URL used as the RDP transfer mechanism; exact bytes reverified before extraction | PASS |
| Windows ZIP size/hash | `4531660` bytes; `b49998bbe08a0c496ddacfae8d12ab5f1d7cba1866a9fc594f3e3158a04aec43` | PASS |
| Remote root | `C:\Users\Administrator\Desktop\sswr-acceptance\task11-30553085622-85c87a7-20260731-0002` | Retained |
| Inventory | ZIP has exactly ten files; manifest has nine payload entries | PASS |
| `BUILD-INFO` | Hash `c07a4b2c341d1d204385cb92007968a01e214517061b8f06aaa99d24a7dd3b98`; commit/run/target/profile/setup/bootstrap fields matched | PASS |
| `SHA256SUMS` | Hash `bea53470a86a182c4cc62853b374c68db84357f229e9e89eed5bf58f57e3bd82`; all nine entries matched | PASS |
| Main EXE | `78072ada3073b97ac3c1080f0244d871f1ef93ba94efd7577a5bfc632ebcb11a` | PASS |
| Main EXE subsystem | PE subsystem `2` (Windows GUI) | PASS |
| Recovery helper | `7d3095ff5accac9015ff9a4c4d5a6aa3437539b0e062a2279de24647617f525d` | PASS; NOT RUN |
| Smoke helper | `95330f2007e06e87d15048f984291d38e070ab05c107a028009ae9dcbd3d4aa4` | PASS; NOT RUN |
| Sole NSIS setup | `Shadowsocks_0.1.0_x64-setup.exe`; `34e4281266beed4eae2d06faa6756f58bf28f734fbbce65202d826afd579cbc4` | PASS; NOT RUN |
| `wintun.dll` | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` | PASS |
| Wintun signature | Valid; subject WireGuard LLC; issuer DigiCert EV Code Signing CA SHA2 | PASS |

The RDP file clipboard could not transfer the retained local file. Windows
therefore received the already-qualified artifact bytes through the
authenticated GitHub connector's temporary download URL. This did not select a
different run or artifact, and the resulting size and SHA-256 matched the
retained ZIP exactly before extraction. Nothing was rebuilt, repacked,
replaced, or unblocked.

## 3. Interactive RDP and pre-launch baseline

The raw GUI launch occurred only inside the already established interactive
RDP desktop, as the same elevated user in session `2`. It was not launched
from SSH, Session 0, SYSTEM, a service, another user, or a scheduled task. RDP
remained a management connection and was not treated as OOB.

The final read-only snapshot retained these live TCP tuples:

- `177.5.74.14:3389 <- 14.19.62.144:9532` (TCP, PID `5536`)
- `177.5.74.14:3389 <- 138.226.239.7:12020` (TCP, PID `5536`)

Both peers selected local address `177.5.74.14`, Ethernet ifIndex `6`, and the
IPv4 default route through `177.5.74.254`. The physical interface evidence was
ifIndex `6`, LUID decimal `1689399683186688`
(`0x0006008004000000`), route metric `101`, and interface metric `15`.

The fresh pre-launch gate found:

- no running `shadowsocks-windows-rs` process;
- no project Wintun adapter/session, address, or capture/split/shadow route;
- no recovery journal;
- no project watchdog or stage task;
- no auto-connect configuration field;
- no setup/helper/smoke process.

Result: `PASS — safe to perform the raw-EXE startup observation`.

## 4. WebView2 initial state

The official client GUID and `pv` semantics were checked in all four registry
views: HKLM/HKCU, 32-bit/64-bit. None contained an installed non-zero Runtime
version.

Initial state: `MISSING`. Final state: `MISSING`.

The application entered the missing-Runtime bootstrap branch; the complete
successful missing-Runtime path was not executed or verified. This was not the
installed-Runtime fast path.

## 5. Raw-EXE launch and bootstrap result

The valid test launch used only `shadowsocks-windows-rs.exe`, with no arguments,
from the extracted directory in the same interactive RDP PowerShell. The main
process was PID `7944`, parent PID `9052`, session `2`, and its image path was
the exact verified extracted EXE.

Observed product result:

- no CMD console window;
- no separate installer wizard;
- no unexpected UAC prompt;
- no application child process in the 500 ms process timeline;
- no application-spawned cmd, PowerShell, pwsh, or curl;
- transient application TCP from `177.5.74.14` to
  `199.232.214.172:443` and `104.83.198.44:443`;
- no usable evidence capture of the required native progress window;
- failure dialog captured at `2026-07-31 00:33:56+08:00`;
- native error title: `Shadowsocks 初始化失败`;
- native error body:
  `运行环境安装失败。请重试；如仍失败，请联系管理员。`;
- no main Tauri window;
- Runtime still absent after exit.

The error dialog was closed normally. There was no retry, manual Runtime
installation, check bypass, or second raw-EXE launch. The setup and both
helpers remained `NOT RUN`.

Operator-observation note: before the valid launch, a forward-slash Windows
path was entered in Explorer's address bar. Explorer interpreted it as a URL
and opened ordinary Edge at a failing `c/Users/...` address. That action did
not start the application. The timeline separates the Edge processes from PID
`7944`; Edge was closed normally and is not classified as bootstrap behavior.

Bootstrap/app result: `BLOCKED`.

## 6. Post-exit comparison

The same isolated read-only collector ran again under `evidence-post`.
Adapters, IP configuration, addresses, interfaces/metrics, DNS, routes, and
default routes matched their pre-launch files exactly. There was:

- no new Wintun adapter/session;
- no route, address, DNS, default-route, gateway, or metric change;
- no recovery journal;
- no watchdog or stage task;
- no residual SSWR, setup, bootstrapper, or helper process;
- no `%TEMP%\sswrs-webview2-*.exe`;
- no detected WebView2 Runtime;
- no RDP loss.

The raw pre/post RDP files and live netstat screenshots are retained. The
generated final-analysis field `TASK11_FINAL_RDP_EXACT=True` is not accepted as
an exact comparison result: its deeply serialized CIM JSON could not be parsed
back by `ConvertFrom-Json`. The narrower, independently visible facts are
recorded instead: RDP remained established, both final tuples are retained,
and both peers still selected Ethernet ifIndex `6` through
`177.5.74.254`.

Network-safety result: `PASS`. Bootstrap/application-start result: `BLOCKED`.

## 7. Evidence index and integrity

Remote evidence:

- `C:\Users\Administrator\Desktop\sswr-acceptance\task11-30553085622-85c87a7-20260731-0002\evidence`
- `evidence\99-final-evidence-sha256.txt` SHA-256:
  `1fc9ef60322193a97e850ac6b7c6b5cc07d4855d30a2b104133df825d76e0573`
- `C:\Users\Administrator\Desktop\sswr-acceptance\task11-30553085622-85c87a7-20260731-0002\evidence-post`
- `evidence-post\99-final-evidence-sha256.txt` SHA-256:
  `9d33f3512455f2bbf647f82951d37a4f4d2b16ea5ed5d08a333447cd707b5b92`

Local screenshot evidence:

- `/private/tmp/sswr-task11-30553085622-20260731-0002`
- `/private/tmp/sswr-task11-30553085622-20260731-0002/SCREENSHOT-SHA256SUMS.txt`
- screenshot-manifest SHA-256:
  `8ab3bcd24381e49ec8f1b1e1bf1ee9eab334fbbf3caf867a36bc4f96ceced4e8`
- failure-dialog screenshot SHA-256:
  `580fbcce5940496e7d976a940af6b491a2974d8da8f48f89d5ec8bcdedba3cea`

The remote artifact and evidence directories remain in place for inspection.
No credential, token, or secret was recorded in this document.

## 8. Deferred/not-run gates

| Gate | Result |
| --- | --- |
| WebView2 Runtime automatic installation and non-zero final `pv` | BLOCKED |
| Required progress-window lifecycle | BLOCKED — not fully captured |
| Main Tauri window and About/version UI | BLOCKED — window never appeared |
| Normal close of main app window | BLOCKED — no main window; failure dialog was closed normally |
| OOB proof and management host-route action plan | NOT RUN — Task 12 |
| Wintun smoke | NOT RUN — Task 13 |
| Full DIRECT data path | NOT RUN — Task 14 |
| Any Windows network mutation | NOT RUN |

## 9. Task 11-R1 local bootstrap failure analysis

Task 11-R1 was performed only against the retained source and Task 11
evidence. There was no new Windows connection, EXE launch, Runtime
installation, registry write, helper/setup execution, DIRECT/Wintun activity,
or network mutation.

### 9.1 Exact state-machine call chain

The raw GUI entry point calls `prepare_before_tauri()` before Tauri is
constructed. The Windows implementation then executes this ordered chain:

1. query the official WebView2 client `pv` in HKLM/HKCU, 32-bit/64-bit views;
2. create/acquire the named bootstrap mutex, then repeat the four-view query;
3. create the native progress window;
4. open the fixed WinHTTP session, connect, open/send the HTTPS request,
   receive the response, process bounded manual redirects and require final
   HTTP 200;
5. create the exclusive temporary EXE, read the bounded body, write and sync
   it, then retain the restricted duplicate file handle;
6. run `WinVerifyTrust`, inspect the primary publisher certificate, and require
   organization exactly `Microsoft Corporation`;
7. create/configure the kill-on-close Job Object, call `CreateProcessW`
   suspended with `/silent /install`, assign it to the job, resume it, wait,
   collect the installer exit code, and wait for the job to drain;
8. poll the four-view Runtime registration until present or the fixed
   installation deadline;
9. release the temporary-file handle and delete the temporary EXE, close the
   progress window, release the mutex, and only then allow Tauri construction.

On any error, `bootstrap_and_report()` closes the progress UI best-effort,
shows the native failure dialog, returns failure to `main`, and `main` exits
with code `1` without constructing the Tauri window.

### 9.2 Proven and unresolved boundaries for run 30553085622

| Boundary | What the retained evidence proves | What it does not prove |
| --- | --- | --- |
| Runtime registry detection | Both application-level pre-install checks returned “not installed”; the independent collector also found no non-zero `pv` in all four views before and after launch | The historical detector discarded individual `RegOpenKeyExW`/`RegGetValueW` errors, so per-probe in-process success and Win32 codes were not retained |
| Mutex / progress window | Mutex acquisition and `ProgressUi::open()` returned success, because execution reached the installer-family error | The screenshot set does not visually prove the progress-window lifecycle; progress-close and mutex-release errors were discarded when a primary operation had already failed |
| WinHTTP session/connect/request | The downloader returned an artifact, so its session/options, connect, request-open, send, receive, and deadline gates returned success | Exact endpoint-to-stage attribution and per-call timings were not recorded |
| HTTP redirect/status | Every redirect actually followed passed the fixed policy and the final response passed the required HTTP 200 check | Redirect count, individual status codes, and header values were not recorded |
| Download read | The bounded body-read loop completed | Byte count and read-call timing were not recorded |
| Temporary create/write | Exclusive creation, bounded writes, `sync_all`, and restricted-handle duplication completed | The temporary path is intentionally not evidence and must remain undisclosed |
| Authenticode / signer | `WinVerifyTrust` completed successfully, signer inspection succeeded, the signer organization matched exactly, and trust-state close succeeded | Certificate details beyond the required organization were intentionally not recorded |
| Job / `CreateProcessW` / process control | `SilentInstaller::install()` was entered | The old single `InstallerLaunch` category collapsed Job Object creation/configuration, `CreateProcessW`, assignment, resume, wait, exit-code query, job-drain, and termination failures |
| Installer exit code | The result was either a collapsed installer-control error or a non-zero installer exit | The numeric exit code was discarded |
| Runtime redetection | Runtime was still absent in the independent post-exit collector | The old dialog alone shared the same text with `RuntimeStillMissing`; however, the same-host timeline from process observation at `00:31:14` to the dialog at `00:33:56` is only 162 seconds, so the fixed 10-minute installer/redetection deadlines are inconsistent with this run unless those timestamps are invalid |
| Temporary cleanup | Explicit artifact cleanup returned success; otherwise the old state machine would have replaced the primary error with the generic `Cleanup` family. No residual bootstrapper was found | Drop-time fallback detail was not separately recorded |

The exact old dialog body could only have been produced by
`InstallerLaunch`, `InstallerTimeout`, `InstallerFailed`, or
`RuntimeStillMissing`. It excludes the download, temporary-file, signature,
registry/mutex/progress-open, and explicit-cleanup error families at the
state-machine result level. With the retained 162-second same-host timeline,
the two fixed 10-minute outcomes are not credible for this run. The earliest
unresolved native boundary is therefore Job Object creation, the first native
operation inside `SilentInstaller::install()`. The evidence cannot distinguish
that boundary from later installer-control calls or a short-lived installer
that returned non-zero. A 500 ms process sample that found no child is not
proof that `CreateProcessW` never succeeded.

### 9.3 Root-cause conclusion and bounded hypotheses

The historical root cause is **not proven**. The source does prove an
observability defect: Win32, WinHTTP, WinTrust, HTTP-status, installer-exit,
wait-status, and exact-stage information was collapsed into broad enum values;
registry probe errors were ignored; and a cleanup error could overwrite the
primary failure.

The evidence-ranked hypotheses are:

1. `CreateProcessW` failed, with sharing violation `32` the leading
   code-derived hypothesis. The temporary file was opened read/write with only
   read sharing; `DuplicateHandle(..., GENERIC_READ, ...)` creates another
   handle to the same kernel object rather than a new read-only open
   ([DuplicateHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)).
   Because the duplicate existed before the original handle was dropped, the
   last-handle cleanup for that file object did not occur
   ([IRP_MJ_CLEANUP](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-cleanup)).
   This proves the retained handle is not an independent read-only reopen, but
   the public `CreateProcessW` contract does not specify its internal image-open
   share flags. Therefore error `32` remains a hypothesis, not the historical
   result or a proven launch defect.
2. Another collapsed `InstallerLaunch` substage failed: Job Object
   create/configure, process assignment/resume, wait/exit query, job drain, or
   bounded termination.
3. A child was shorter-lived than the 500 ms observation interval and returned
   a non-zero installer exit code.

No handle-lifetime, reopen, file-sharing, download, signature, or trust-policy
change is justified before an exact new stage and system code are captured.
Closing the verified handle before execution could introduce a
verify-to-execute race; adding write sharing would weaken the existing
protection.

### 9.4 Local minimal diagnostic patch

The uncommitted local patch keeps the existing Chinese operator guidance and
adds bounded native-dialog lines containing only:

- a stable stage ID and stable error category;
- a typed numeric code when the relevant API contract provides one:
  Win32, WinHTTP, HTTP status, WinTrust, HRESULT, wait status, or installer
  exit;
- the first cleanup/control failure as `secondary` without replacing the
  original `diagnostic`.

It adds literal stages for the registry checks, mutex/progress open,
message-loop and close lifecycle, WinHTTP session/connect/request, HTTP
status/redirect, download read,
temporary-file create/write/flush/lock/cleanup, Authenticode verify/signer/
close, and every Job Object/process/exit/drain/termination boundary. Registry
probe failures no longer masquerade as a missing Runtime when no view proves
installation. Expected size-probe control flow and APIs without a documented
extended-error contract do not emit stale `GetLastError` values.
`GetMessageW == -1` is no longer treated as a normal progress-loop exit; it is
reported as `progress.message_loop` with the immediate Win32 code. A failed
window-close post that is recovered by the thread-message fallback remains a
successful close.

The diagnostic contains no path, URL, host, signer value, certificate body,
response body, query credential, token, memory content, or unrelated personal
information. It does not create a diagnostic file.

The fixed Microsoft URL, HTTPS/redirect constraints, timeouts, header/body
limits, exclusive temporary creation, Authenticode trust and exact signer
requirement, Job Object/process waiting, and cleanup policy are unchanged.
The restricted duplicate handle is intentionally unchanged pending evidence.

Local validation:

- focused bootstrap library tests: `26 passed; 0 failed`;
- complete library tests: `203 passed; 0 failed`;
- Windows-native code compile check:
  `cargo check --target x86_64-pc-windows-gnu --lib --bin shadowsocks-windows-rs`
  passed;
- `cargo fmt --check` passed;
- `git diff --check` passed.

### 9.5 Required next evidence, not executed

No current artifact contains this diagnostic patch. Root-cause resolution
therefore requires one newly qualified artifact and exactly one authorized
raw-EXE missing-Runtime retry. That retry must preserve:

- the complete native dialog, including `diagnostic` and optional `secondary`;
- process start/dialog/exit times on the same clock;
- event-based child-process create/exit evidence, not only interval sampling;
- read-only pre/post results for all four Runtime registry views;
- read-only confirmation of bootstrapper-process and temporary-file cleanup.

If the result is `stage=installer.create_process; ...; code=win32:32`, a
separate narrowly scoped handle-lifetime fix can then be designed and
Windows-validated without weakening the verify-to-execute boundary. No new
artifact was built, no Actions run was triggered, and no retry was performed
in Task 11-R1.

## 10. Final verdict

`任务 11 未通过，禁止开始任务 12`.

Task 11-R1 stopped after the local evidence analysis and diagnostic patch.
Task 12 was not started.
