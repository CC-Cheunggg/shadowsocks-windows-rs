# Windows DIRECT acceptance task ledger

This file is the resumable, sequential task ledger for the Windows real-machine
DIRECT data-path acceptance. Work on exactly one numbered task at a time.
Do not start the next task until the current task's completion gate is recorded
here.

The normative safety requirements remain in
[DEVELOPMENT_CONSTRAINTS.md](DEVELOPMENT_CONSTRAINTS.md). If this ledger and
that document differ, the development constraints win.

## Current checkpoint

- Checkpoint: 2026-07-30, Asia/Shanghai, immediately after Task 8's
  documentation and full local-validation gate passed.
- Branch: `codex/direct-wintun-slice`.
- Last pushed commit: `ece125b3e4cfe1974c3947a89d9c626ab8b55fbf`.
- No new commit or push was made after that commit.
- No new GitHub Actions run was started.
- No Windows adapter, address, route, DNS, firewall, or proxy mutation was
  performed.
- The existing read-only Windows baseline remains the latest remote evidence.
- `preview-overview.png` is still the user's unrelated staged deletion. It must
  not be restored, modified, or included in our commits.
- The current worktree contains combined, uncommitted WIP from several tasks.
  Treat every WIP change as unaccepted until its own task is reviewed and its
  completion gate passes.
- Tasks 6 and 7 are implementation-complete at their local gates. Their MSVC,
  NSIS, artifact, and native Windows evidence remains explicitly deferred to
  Tasks 9–11.
- Task 8 is complete. Task 9 has not started; resume only after an explicit
  instruction naming Task 9.

## Task 1 — Management route ownership and startup gate

Status: `COMPLETE — local code gate passed 2026-07-26`

Scope:

- Treat each management `/32` or `/128` as an operator-owned, pre-existing
  physical route.
- Require a unique exact ActiveStore host route with the expected ifIndex,
  LUID, gateway, and winning best-route selection.
- Verify before adapter creation, before the first network mutation, and again
  immediately before the first capture route.
- Ensure the physical route never enters `route_specs`, `RecoveryPlan`, a
  native Create/Delete call, or application cleanup.

Completion gate:

- Focused code review completed. The route layer rejects a management host
  prefix that reappears as a shadow route, and startup compares every
  management binding with the independently discovered pre-Wintun physical
  interface generation and gateway.
- Regression tests cover missing, ambiguous, wrong-ifIndex, stale-LUID,
  mismatched-gateway, non-winning, IPv4 `/32`, IPv6 `/128`, and variable valid
  route metrics. Failed fresh verification invokes zero native mutation.
- Regression tests prove management exclusions stay out of `route_specs` and
  `RecoveryPlan`, external-interface routes are rejected by journal validation,
  and a physical route cannot reach the guarded Create/Delete operation.
- Validation passed:
  - `cargo check --all-targets`
  - `cargo check --lib --target x86_64-pc-windows-gnu`
  - `cargo test --lib mandatory_` (5 passed)
  - `cargo test --lib management_` (3 passed)
  - `cargo test --lib external_route_` (5 passed)
  - `cargo test --lib mutation_and_capture_phases_use_independent_fresh_precondition_gates`
    (1 passed)
  - `cargo test --lib recovery_journal_rejects_every_external_interface_route`
    (1 passed)
  - `cargo fmt --check`
  - `git diff --check`
- The optional local MSVC cross-check stopped in the Tauri resource build
  because this macOS host has no `llvm-rc`; the Windows GNU target compiled the
  actual `cfg(windows)` library. No Actions run or Windows-machine operation was
  performed.

## Task 2 — Ordered stop and failure cleanup

Status: `COMPLETE — local code gate passed 2026-07-26`

Scope:

1. stop new flows and callbacks;
2. withdraw Wintun split-default and shadow routes;
3. end the Wintun session;
4. restore owned addresses/interface settings and remove the adapter; and
5. clear recovery state only after exact verification.

The automatic Rust field-drop fallback must preserve the same ordering.

Completion gate:

- Normal stop, startup failure, cancellation, network-change rollback,
  partial-route-removal, early-return/panic fallback, `EpochResources` Drop,
  and `RouteTransaction` Drop paths were reviewed.
- Every explicit path uses callbacks -> capture routes -> Wintun session ->
  owned addresses/exact interface restoration -> owned adapter plus absence
  verification -> recovery lease. The recovery journal is cleared only after
  the ordered cleanup succeeds and the adapter is proven absent.
- A failed or unproved capture-route withdrawal cannot actively or implicitly
  end the Wintun session. The fallback retains the session, adapter, and lease
  handles for process-lifetime recovery instead of crossing that boundary.
  A failed interface restoration similarly prevents adapter removal.
- Route withdrawal attempts every owned route in reverse order. Exact
  already-absent objects are successful no-ops, so a partial first pass can be
  retried idempotently without touching physical-interface routes.
- `RouteTransaction::Drop` may attempt only capture-route withdrawal; it never
  restores interface state because it does not own the session lifetime.
  `EpochResources` owns and tests the complete automatic fallback order.
- Recovery journals remain present after route, interface-restoration, adapter
  removal, or adapter-absence-verification failure. They clear only after
  exact ordered cleanup and absence verification both succeed.
- The Task 8 full-code audit closed an additional install-failure gap:
  `RouteTransaction` now hands any partially installed, in-memory recovery
  state to the epoch owner instead of restoring addresses/settings while the
  session is still alive. Both the full runtime and isolated smoke withdraw
  routes first, end the session second, and only then restore interface state;
  an unproved route withdrawal retains the downstream resources and journal.
- Validation passed:
  - focused engine cleanup tests (5 passed)
  - automatic fallback Drop tests (3 passed)
  - partial route retry and `RouteTransaction` Drop tests (2 passed)
  - `cargo test --manifest-path src-tauri/Cargo.toml --lib` (162 passed)
  - Task 1 regressions: `mandatory_` (5 passed), `management_` (3 passed),
    `external_route_` (5 passed), and
    `recovery_journal_rejects_every_external_interface_route` (1 passed)
  - `cargo fmt --manifest-path src-tauri/Cargo.toml --check`
  - `git diff --check`
- Remaining risk: native Windows failure injection and real-machine timing
  behavior were not exercised in this task. Those remain gated to the later
  Windows artifact and explicitly authorized real-machine acceptance tasks.
  No Actions run or Windows-machine operation was performed.

## Task 3 — Recovery journal and durable adapter intent

Status: `COMPLETE — local code gate passed 2026-07-26`

Scope:

- Write durable adapter-creation intent before `WintunCreateAdapter`.
- Use a pre-generated GUID and atomically promote intent to the complete
  ifIndex/LUID/GUID/alias identity.
- Reject external-interface routes in every new journal.
- Treat a legacy/user-writable external-route claim as `recovery-required`
  with zero mutation.
- If the exact adapter is absent and every object is adapter-owned, permit
  idempotent journal clearing only after complete absence proof.
- If an adapter exists, require exact ifIndex/LUID/GUID/alias provenance.
- Reconcile Prepared native mutations only through exact
  absent/exact-applied/conflict states.

Completion gate:

- The current journal has an explicit schema, version, and phase. Its durable
  state machine is `no journal -> adapter_creation_intent ->
  adapter_identity`; each later owned object advances through one atomic
  `Prepared -> Applied` transition. Batched claims, Applied-first claims,
  phase/field disagreement, and state-array disagreement are rejected.
- A synchronized temporary file and atomic create record the fixed alias,
  pre-generated GUID, and bounded non-secret recovery context before
  `WintunCreateAdapter`. The same GUID object is passed to Wintun. The complete
  ifIndex/LUID/GUID/alias identity is verified against both the created handle
  and IP Helper, then atomically replaces the intent before session start or
  any address, interface-setting, or route mutation.
- Create failure, cancellation, identity lookup failure, identity mismatch,
  and identity-promotion failure retain the intent unless all intended and
  observed adapter selectors are proven absent. The same-process cleanup proof
  includes any observed identity, LUID, and ifIndex, so an unexpected actual
  alias/GUID cannot make the intent disappear prematurely.
- Intent-only recovery takes one interface snapshot and requires both the
  intended alias and intended GUID to be absent twice before clearing. Any
  presence, reuse, conflict, or discovery failure returns
  `recovery-required` with no mutation. It never performs broad name cleanup
  or claims that an independently undeletable Wintun adapter was recovered.
- Full-journal absence and presence checks use one bounded interface snapshot
  to classify all four keys: alias, LUID, GUID, and ifIndex. Absence is accepted
  only when no current interface matches any key; presence is accepted only
  when one interface exactly matches all keys. Recovery then opens the same
  adapter through the bundled Wintun API, rechecks handle LUID/ifIndex and the
  complete current identity, and keeps that handle alive throughout exact
  adapter-owned restoration.
- External-interface routes are rejected by route-plan generation,
  `RecoveryPlan` validation, journal identity preparation/update, journal
  load, and recovery before any mutation. Legacy v1/v2 physical-route claims
  retain their evidence and return `recovery-required`; a user-writable journal
  never authorizes physical-route deletion.
- Prepared and Applied records both use exact reconciliation. Exact absence or
  already-restored interface state is an idempotent no-op; exact applied state
  is removed/restored; any conflicting row or field is left untouched and
  keeps the journal. Current-version journal updates are limited to one new
  Prepared object or one Prepared-to-Applied transition.
- Fault-injection coverage includes pre-intent failure, crash/failure after
  intent, create failure, create-before-promotion presence, actual identity
  mismatch, atomic identity-upgrade failure (including post-commit sync
  uncertainty), identity-before-first-native-call gating, Prepared-before-call,
  native-success-before-Applied, asynchronous adapter disappearance, all four
  identity reuse/conflict cases, legacy external routes, repeated recovery,
  incomplete/oversized/illegal journals, inconsistent states, and clear
  failures that preserve loadable evidence.
- Validation passed:
  - `cargo test --manifest-path src-tauri/Cargo.toml --lib
    runtime::recovery::tests::` (21 passed)
  - `cargo test --manifest-path src-tauri/Cargo.toml --lib
    runtime::engine::tests::` (13 passed)
  - focused write-ahead, Prepared/Applied, and adapter-GUID tests (3 passed)
  - `cargo test --manifest-path src-tauri/Cargo.toml --lib` (172 passed)
  - `cargo check --manifest-path src-tauri/Cargo.toml --lib --target
    x86_64-pc-windows-gnu`
  - `cargo check --manifest-path src-tauri/Cargo.toml --bin network_recover
    --target x86_64-pc-windows-gnu`
  - Task 1 regressions: `mandatory_` (5 passed), `management_` (3 passed),
    `external_route_` (5 passed), and
    `recovery_journal_rejects_every_external_interface_route` (1 passed)
  - Task 2 regressions: focused engine ordering tests (within the 13 engine
    tests), partial route retry (1 passed), and `RouteTransaction` Drop
    ordering (1 passed)
  - `cargo fmt --manifest-path src-tauri/Cargo.toml --check`
  - `git diff --check`
- Remaining risk: the Windows GNU target compiled all `cfg(windows)` recovery
  code, but native Windows fault injection, filesystem power-loss behavior,
  and real adapter disappearance/reuse timing were not exercised locally.
  Those remain gated to a later verified Windows artifact and explicitly
  authorized real-machine acceptance. No watchdog test, Actions run, commit,
  push, or Windows-machine operation was performed.

## Task 4 — Bounded recovery watchdog

Status: `COMPLETE — local code gate passed 2026-07-26`

Scope:

- Run under the same Windows user/config context, never SYSTEM's APPDATA.
- Verify the fixed-directory helper, `wintun.dll`, and `SHA256SUMS`.
- Retry `runtime-active` until a bounded deadline.
- Record every attempt and the final state.
- On timeout, return non-zero and preserve the journal/evidence.

Completion gate:

- `network_recover.exe --watchdog` has one fixed policy: its five-minute
  fail-closed attempt/commit deadline starts before user-context, audit, and
  asset preflight; it starts no attempt and clears no journal at or after that
  boundary. Sleeps are at most two seconds and a derived maximum-attempt cap
  applies even to a non-advancing injected clock. No caller can supply a
  timing, journal, DLL, manifest, or audit path.
- Before any recovery attempt, the helper rejects LocalSystem, LocalService,
  and NetworkService, compares `%APPDATA%` with the token's
  `FOLDERID_RoamingAppData`, fingerprints the binary token SID, creates and
  syncs the fixed audit log, and verifies a provisioned
  `WATCHDOG-CONTEXT.json` containing the intended desktop user's same SID
  fingerprint. A different ordinary user therefore fails before journal
  lookup or recovery instead of reporting a false no-journal success.
- The fixed helper directory must contain canonical regular-file
  `network_recover.exe`, `wintun.dll`, and `SHA256SUMS` entries. Manifest
  parsing rejects malformed hashes, unsafe/absolute/traversing/device names,
  case-insensitive duplicates, missing required rows, and symlink mappings.
  The helper and DLL are re-hashed before every attempt; the DLL must also
  match the compiled approved hash
  `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`.
- `runtime-active` is the only retry state. Verified recovery retains the
  existing global recovery lease and journal, syncs a write-ahead
  `journal_clear_authorized` decision, then takes a fresh clock reading before
  calling the existing verified journal clear. The no-journal path likewise
  rechecks the deadline after its synchronized final audit. A final audit that
  reaches or crosses the boundary therefore cannot clear the journal or return
  success. No-journal exits 0 only in the bound user context and inside the
  deadline. Timeout, recovery-required, identity conflict, decode/asset/audit
  failure, and journal-clear failure exit non-zero without speculative cleanup.
- Every attempt and final state is appended to the unique fixed JSONL log with
  schema/version, run ID, attempt, UTC Unix milliseconds, elapsed/deadline,
  bounded state/retry/final/exit enums, SID fingerprint, and verified hashes.
  Records contain no path, username, address, configuration, credential, or
  raw OS error and are flushed plus synchronized. Audit failure stops further
  attempts; timeout logs and journals are retained.
- `--status` remains read-only and `--apply` keeps its existing one-shot
  recovery contract; neither is routed through the watchdog retry loop.
- Validation passed:
  - `cargo test --manifest-path src-tauri/Cargo.toml --bin network_recover`
    (22 passed)
  - focused recovery interface tests (23 passed)
  - `cargo test --manifest-path src-tauri/Cargo.toml --lib` (174 passed)
  - Task 1 regressions: `mandatory_` (5 passed), `management_` (3 passed),
    `external_route_` (5 passed), and
    `recovery_journal_rejects_every_external_interface_route` (1 passed)
  - Task 2 regressions: shared explicit cleanup ordering (1 passed), fallback
    Drop ordering (3 passed), and partial route retry (1 passed)
  - Task 3 regressions: recovery suite (23 passed), durable identity and
    adapter-create gates (2 passed), and Prepared/Applied reconciliation
    (1 passed)
  - `cargo check --manifest-path src-tauri/Cargo.toml --bin network_recover
    --target x86_64-pc-windows-gnu`
  - `cargo fmt --manifest-path src-tauri/Cargo.toml --check`
  - `git diff --check`
- `WINDOWS_RECOVERY.md` now gives one exact, acceptance-time-only
  Program-Files staging and same-SID S4U scheduling procedure, including
  context binding, hash checks, fixed `--watchdog` action, bounded execution,
  and an audited no-journal dry run.
- Remaining risk: this macOS host compiled the Windows GNU code but did not
  exercise Windows token/known-folder APIs, Program Files ACLs, Task Scheduler
  S4U behavior, native recovery, filesystem power-loss behavior, or the narrow
  hash-verification-to-DLL-load race if the protected stage is made writable.
  A synchronous Windows recovery call admitted before the deadline is not
  force-terminated and may return just after it; the post-attempt deadline
  check then records timeout and preserves the journal instead of clearing it.
  These remain gated to a later verified artifact and explicitly authorized
  Windows acceptance. No scheduled task, Actions run, Windows-machine
  operation, commit, or push was performed.

## Task 5 — GUI subsystem

Status: `IMPLEMENTATION COMPLETE — local code gate passed 2026-07-26; Windows evidence deferred`

Scope:

- Release `shadowsocks-windows-rs.exe` uses PE subsystem 2.
- `network_recover.exe` and `wintun_smoke.exe` remain subsystem 3.

Completion record:

- Implementation files:
  - `src-tauri/src/main.rs` applies `windows_subsystem = "windows"` only when
    both `target_os = "windows"` and `not(debug_assertions)` are true. The
    application entry point and startup call are otherwise unchanged.
  - `scripts/verify-windows-pe-subsystems.ps1` reads three explicit literal
    paths and directly validates the DOS signature, `e_lfanew`, PE signature,
    complete COFF header, declared optional-header boundary, PE32/PE32+ magic,
    and the two-byte Subsystem field before enforcing values 2, 3, and 3.
  - `.github/workflows/windows.yml` invokes that script with the three exact
    release EXE paths after the release build, NSIS bundle, and static-CRT gate,
    and before artifact staging.
- Neither helper source contains a GUI-subsystem attribute or linker override.
  `.cargo/config.toml` still enables `+crt-static` for the MSVC target, and the
  existing workflow static-CRT gate still checks all three EXEs.
- Local validation passed:
  - `cargo fmt --manifest-path src-tauri/Cargo.toml --check`
  - `cargo check --manifest-path src-tauri/Cargo.toml --locked`
  - `npm run build`
  - `npm run verify:windows-bundle-config` (recorded only as the current WIP
    result; no later WebView2/NSIS design was accepted or changed here)
  - JSON parsing for `package.json`, `package-lock.json`,
    `src-tauri/tauri.conf.json`, and `src-tauri/tauri.windows.conf.json`
  - YAML parsing for `.github/workflows/windows.yml`
  - `git diff --check`
- The installed MinGW target and linker produced all three x86_64 Windows GNU
  release PE files. An independent direct-header read found PE32+ magic and
  Subsystem 2 for the main EXE and 3 for each helper. This is supplementary
  local evidence, not the required MSVC workflow execution evidence.
- An additional GNU debug-link attempt did not produce a main EXE because the
  MinGW linker rejected an existing debug `cdylib` export ordinal. The
  release/debug cfg behavior was therefore code-reviewed, but no debug PE
  execution claim is made.
- This macOS host has no `pwsh`, `powershell`, `dotnet`, `llvm-rc`, or MSVC
  linker. PowerShell syntax and boundary behavior received static review, but
  the PowerShell verifier itself and MSVC PE files were not executed locally.
- `implementation complete`
- `Windows PE execution evidence deferred to Task 9`
- `real no-CMD-window evidence deferred to Task 11`
- No GitHub Actions run or Windows-machine operation was performed.

## Task 6 — Bare-EXE WebView2 bootstrap

Status: `IMPLEMENTATION COMPLETE — local code gate passed 2026-07-30; Windows evidence deferred to Task 11`

Scope:

- Keep the raw EXE usable when Evergreen WebView2 is missing.
- Display a non-interactive Windows-native progress window containing at least
  `正在初始化运行环境，请稍候…`.
- Download only the official Microsoft Evergreen bootstrapper using native
  Windows networking; no PowerShell, cmd, or generated shell command.
- Verify a valid Microsoft Authenticode signer/chain before execution.
- Run the bootstrapper with silent install arguments, wait for success,
  automatically close the progress window, and continue application startup.
- On failure, do not start the WebView; show a native actionable error dialog.
- Do not embed a fixed WebView runtime.

Completion gate:

- Detection, download restrictions, signature rejection, installer exit codes,
  progress-window lifecycle, and failure UI are tested.
- On the WebView2-missing Windows target, first launch completes without a
  separate WebView2 wizard or manual confirmation.

Completion record:

- `src-tauri/src/main.rs` now calls the Windows-only bootstrap gate before
  `shadowsocks_windows_rs_lib::run()`, so no Tauri builder or WebView window is
  created until the gate succeeds. The Task 5 release GUI-subsystem attribute
  is preserved. Non-Windows startup remains the existing direct `run()` call.
- `src-tauri/src/webview2_bootstrap/mod.rs` contains a platform-neutral,
  injected state machine for runtime detection, clock/deadlines, cross-process
  locking, progress/error UI, download/artifact cleanup, signature
  verification, and installer execution. The installed-runtime fast path does
  not acquire the mutex, open UI, download, or create a process.
- The native detector queries the official WebView2 client GUID under HKLM and
  HKCU through both 32-bit and 64-bit registry views. It accepts only a
  present, non-empty `pv` value other than `0.0.0.0`, and checks all probes
  before failing on a registry access error.
- The downloader uses WinHTTP and the one compiled-in Microsoft URL
  `https://go.microsoft.com/fwlink/p/?LinkId=2124703`. Automatic redirects are
  disabled. Every manually followed redirect must remain HTTPS on an explicit
  Microsoft download-domain allowlist; user info, fragments, non-443 ports,
  IP literals, and lookalike suffixes are rejected. Redirects are capped at
  four, response and Location headers are bounded, the body is capped at
  16 MiB, per-operation timeouts are finite, and each blocking request timeout
  is clamped to the remaining three-minute download deadline.
- A GUID-named installer is created with create-new semantics in the Windows
  temporary directory. After the download is flushed, a read-only handle that
  denies write/delete sharing stays open across verification and execution.
  All controlled exits explicitly delete the file; deletion is retried after
  the installer Job Object is confirmed empty, and any cleanup failure remains
  fatal instead of continuing to Tauri.
- WinVerifyTrust uses the generic Authenticode policy with no trust UI,
  whole-chain revocation checking, and exact success status. The verified
  primary publisher certificate is then inspected and its Organization must
  equal `Microsoft Corporation`; unsigned, invalid-chain, test-certificate,
  lookalike, and non-Microsoft results are rejected before process creation.
- The verified path is passed directly to `CreateProcessW` with fixed
  `/silent /install` arguments, `CREATE_NO_WINDOW`, and `CREATE_SUSPENDED`.
  The process is assigned to a kill-on-close Job Object before it is resumed.
  The complete installer process tree has a ten-minute bound; timeout and
  failure paths terminate and boundedly drain the Job. Only exit code 0 is
  accepted, after which the official registry detection is repeated before
  Tauri startup.
- A per-session named mutex serializes concurrent EXE launches and every waiter
  rechecks the Runtime after acquiring it. Missing-Runtime work opens a
  buttonless native window containing `正在初始化运行环境，请稍候…`, ignores
  close requests, and uses bounded UI-thread startup/closure handshakes.
  Success or failure closes it automatically. Failures show only a short
  native actionable error and return non-zero without creating the WebView.
- Local validation passed:
  - focused Task 6 unit tests (23 passed), covering the installed fast path,
    complete missing-Runtime flow, redirect/size/deadline policy, signature
    rejection, installer failures, post-install detection, cleanup, UI
    lifecycle, and real two-thread single-install serialization;
  - `cargo test --manifest-path src-tauri/Cargo.toml --locked --lib`
    (197 passed: the prior 174-test baseline plus 23 Task 6 tests);
  - `cargo test --manifest-path src-tauri/Cargo.toml --locked --bin
    network_recover` (22 passed);
  - host and `x86_64-pc-windows-gnu` `cargo check --locked --all-targets`;
  - `cargo fmt --manifest-path src-tauri/Cargo.toml --check`;
  - `npm run build`;
  - `git diff --check`; and
  - a raw `x86_64-pc-windows-gnu` release main-EXE link plus `objdump`
    inspection, which found PE subsystem 2 and the expected Registry, WinHTTP,
    WinVerifyTrust, CreateProcessW, Job Object, and native-window imports.
- Static scans found no PowerShell, pwsh, cmd.exe, curl, ShellExecute,
  `std::process::Command`, or generated shell path in production Rust. No
  command-line, environment, configuration, or user-provided download URL or
  installer path is accepted. Task 6 changed no NSIS/offline-installer setting.
- This macOS host did not execute Windows registry, WinHTTP/proxy,
  Authenticode, Job Object, native UI, or real WebView2 installation behavior,
  and did not build with MSVC. An MSVC `cargo check --all-targets` attempt
  stopped in the existing Tauri resource build before crate checking because
  this host has no `llvm-rc`. The WebView2-missing bare-EXE first-launch,
  no-console/no-wizard, silent-install, cleanup, and subsequent Tauri startup
  evidence remains explicitly assigned to Task 11. No Windows-machine
  operation, GitHub Actions run, commit, or push was performed.

## Task 7 — Optional NSIS package and Windows artifact

Status: `IMPLEMENTATION COMPLETE — local gate passed; Windows Actions evidence deferred to Task 9`

Scope:

- Keep NSIS as an optional convenience installer.
- Use `downloadBootstrapper` with silent WebView2 installation; do not embed
  an offline installer or fixed Runtime.
- Stage the artifact with the NSIS setup, raw desktop EXE,
  `network_recover.exe`, `wintun_smoke.exe`, `wintun.dll`, licenses,
  `BUILD-INFO`, and `SHA256SUMS`; do not infer that NSIS installs the helpers.
- Preserve static MSVC CRT verification and Wintun hash/signature checks.

Completion gate:

- Local JSON/config/frontend checks pass.
- Windows Actions builds and validates the setup and raw EXEs.
- Artifact manifest and hashes cover every required file.

Implementation record:

- `src-tauri/tauri.windows.conf.json` now uses Tauri's
  `downloadBootstrapper` WebView2 install mode with `silent: true`. The
  superseded `offlineInstaller` verifier was removed. No fixed Runtime path,
  offline Runtime payload, or caller-controlled download URL was added.
- The Task 6 bare-EXE startup gate remains independent of NSIS and unchanged:
  the raw executable still performs its native WebView2 detection, bounded
  Microsoft download, Authenticode verification, silent install, and
  pre-WebView startup state machine.
- `.github/workflows/windows.yml` now explicitly performs a locked
  `--release --bins` build for `x86_64-pc-windows-msvc` with
  `custom-protocol`, then creates the optional NSIS bundle. Before staging it
  checks all three Rust EXEs for static MSVC CRT, enforces PE subsystem values
  2/3/3, and rechecks the pinned Wintun DLL/license hashes and approved
  Authenticode signer. The isolated Wintun smoke and cleanup gates remain
  before artifact creation.
- `scripts/stage-windows-artifact.mjs` accepts only explicit source
  directories, requires exactly one `*-setup.exe`, and stages only the setup,
  raw desktop EXE, two helper EXEs, `wintun.dll`, project license,
  third-party notices, Wintun binary license, `BUILD-INFO`, and
  `SHA256SUMS`. A missing input, non-empty stage, directory entry, extra file,
  zero/multiple setup match, unsafe filename, or inventory mismatch fails.
- `BUILD-INFO` records the commit, ref/ref name, run ID/attempt, target,
  release profile, rustc, Node/npm, project and Tauri CLI versions, NSIS
  setup name/hash, `downloadBootstrapper`/silent mode, static CRT and PE
  subsystem expectations, and `bare_exe_webview2_bootstrap=enabled`. The local
  simulator uses explicit `LOCAL-SIMULATION` evidence placeholders.
- `SHA256SUMS` uses stable filename order, ASCII/LF `sha256sum` syntax, relative
  root filenames, and hashes every delivery file except itself exactly once.
  The staging script rereads and hashes the staged files, compares the exact
  artifact and manifest inventories, and rejects missing, extra, duplicate,
  misspelled, or mismatched entries. The workflow then repeats manifest/hash
  verification and Wintun Authenticode verification on the staged copy before
  the single `upload-artifact` step, whose missing-file policy is `error`.
- `scripts/verify-windows-bundle-config.mjs` now rejects
  `offlineInstaller`, `fixedRuntime`, local WebView2 installer/runtime paths,
  and obsolete offline workflow logic. It requires the NSIS target,
  `downloadBootstrapper`, silent mode, explicit raw-EXE staging,
  release/MSVC commands, the exact required inventory, complete hash coverage,
  and fail-closed artifact upload.
- Local validation passed:
  - `npm run build`;
  - `npm run verify:windows-bundle-config`;
  - `npm run test:windows-artifact` (4 tests);
  - JSON parsing for `package.json`, `package-lock.json`,
    `src-tauri/tauri.conf.json`, and `src-tauri/tauri.windows.conf.json`;
  - merged Tauri configuration validation against the installed
    `@tauri-apps/cli/config.schema.json`;
  - YAML parsing for `.github/workflows/windows.yml`;
  - `cargo fmt --manifest-path src-tauri/Cargo.toml --check`;
  - `cargo check --manifest-path src-tauri/Cargo.toml --locked`;
  - Task 6 focused `webview2_bootstrap::` regression suite (23 passed); and
  - static workflow/config scans plus `git diff --check`.
- This macOS host has not run NSIS, PowerShell, MSVC, the Tauri Windows
  bundler, or `upload-artifact`. **Windows NSIS 构建及 artifact 实证待任务 9
  的 Windows Actions 完成。** The Windows part of this task's completion gate
  is deliberately not recorded as passed. No Actions run, Windows-machine
  operation, commit, or push was performed.

## Task 8 — Documentation and complete local validation

Status: `COMPLETE — documentation and local validation gate passed`

Scope:

- Remove every statement claiming the program creates or deletes a physical
  management route.
- Document durable intent, ordered cleanup, watchdog, bare-EXE WebView2
  bootstrap, and operator-owned route lifecycle.
- Update the acceptance template.

Completion gate:

- `cargo fmt --check`
- `cargo check` and `cargo test`
- `npm run build`
- Windows bundle/config validation
- JSON/YAML validation
- `git diff --check`

Completion record:

- README, protocol design, Wintun/DIRECT architecture, normative development
  constraints, recovery runbook, acceptance template, and this ledger now use
  one ownership model: the operator creates and owns the exact physical
  `ActiveStore` management `/32` or `/128`; the application only validates it
  and never creates, updates, deletes, or journals it.
- The runbook now gives the exact nine-phase operator sequence: new artifact,
  artifact/hash/build verification, read-only baseline, independent OOB proof,
  operator route create/configure/verify, action-time tuple/route revalidation
  and watchdog preparation, fresh authorization, isolated/full mutation plus
  ordered cleanup/recovery, and operator retain/optional-delete disposition.
- The acceptance template defaults every evidence/result field to `NOT RUN`
  and records run/artifact identity, three EXE hashes and PE/static-CRT gates,
  setup/Wintun/license evidence, current user/SID/admin state, RDP five-tuple,
  physical ifIndex/LUID/gateway/family, exact route and OOB proof, action-time
  authorization, protocol/capture/counter results, cleanup/recovery, failures,
  rollback, residual risks, and route disposition.
- Task 5–7 documentation distinguishes local injected/static evidence from
  MSVC/Actions and native Windows evidence; distinguishes the raw EXE's custom
  WebView2 gate from NSIS `downloadBootstrapper`; and records the exact staged
  artifact inventory without claiming that NSIS installs the two helpers.
- The full-code audit found and fixed two small pre-existing safety regressions:
  the watchdog now takes fresh clock readings after synchronized final audit
  writes before journal clearing/no-journal success, and partial route
  installation is handed to ordered epoch/smoke cleanup so failed route
  withdrawal cannot be followed by live-session interface restoration.
- Local validation passed:
  - `cargo fmt --manifest-path src-tauri/Cargo.toml --check`
  - host `cargo check --manifest-path src-tauri/Cargo.toml --locked
    --all-targets`
  - Windows GNU `cargo check --manifest-path src-tauri/Cargo.toml --locked
    --target x86_64-pc-windows-gnu --all-targets`
  - `cargo test --manifest-path src-tauri/Cargo.toml --locked --all-targets`
    (library 200 passed; `network_recover` 24 passed; main/smoke have no host
    tests)
  - focused route/ownership/cleanup suite (30 passed)
  - focused WebView2 bootstrap suite (23 passed)
  - `npm run build`
  - `npm run verify:windows-bundle-config`
  - `npm run test:windows-artifact` (4 passed)
  - JSON parsing for four configuration/package files, merged Tauri schema
    validation, and workflow YAML parsing
  - all relative Markdown links (9 files)
  - `git diff --check`
- Only existing `dead_code` warnings remain in local Rust checks. This macOS
  host did not run PowerShell, MSVC, NSIS, Authenticode, native WebView2,
  Windows installer/layout, no-CMD-window, artifact upload, or real Wintun
  behavior. Those claims remain deferred to Tasks 9–11 and the later
  explicitly authorized real-machine tasks.
- No Actions run, Windows connection or mutation, artifact download, commit,
  push, or Task 9 work was performed. The unrelated staged deletion of
  `preview-overview.png` remains untouched.

## Task 9 — Bounded commit, push, and Windows Actions

Status: `PENDING`

Scope:

- Review all intended diffs and the staged diff separately.
- Stage only explicit in-scope paths.
- Keep the unrelated staged deletion of `preview-overview.png` out of our
  commit.
- Commit, push `codex/direct-wintun-slice`, and wait for the Windows workflow.

Completion gate:

- Commit contains only approved task files.
- Push succeeds.
- Windows Actions completes successfully.

## Task 10 — New artifact verification

Status: `PENDING`

Scope:

- Record run URL/ID, artifact ID/name/digest, and ZIP SHA-256.
- Verify `SHA256SUMS`, the three Rust EXEs' static CRT state, PE subsystems,
  setup presence, raw-EXE bootstrap evidence, Wintun hash, and Authenticode.

Completion gate:

- Only a fully verified new artifact is eligible for the Windows machine.

## Task 11 — Windows read-only refresh and WebView bootstrap check

Status: `PENDING`

Scope:

- Transfer only the verified artifact.
- Re-collect the established RDP tuple and current network baseline.
- Launch the raw EXE to validate the native initialization window, silent
  WebView2 bootstrap, GUI subsystem, and application startup.
- Do not create Wintun state or any route in this task.

Completion gate:

- Read-only evidence is saved and hash-checked.
- WebView2/app startup passes without a separate installer wizard.

## Task 12 — Out-of-band proof and action-time change plan

Status: `PENDING — requires user participation`

Scope:

- Demonstrate an independently reachable cloud/VM/serial console.
- Freshly identify the RDP peer.
- List the exact operator-owned host route, watchdog, smoke changes, full
  DIRECT changes, rollback, and final operator decision to retain or optionally
  remove the route.
- Obtain explicit authorization at the moment before mutation.

Completion gate:

- Every safety gate in `DEVELOPMENT_CONSTRAINTS.md` has evidence.
- The user gives action-time authorization for the exact listed changes.

## Task 13 — Isolated real-machine Wintun smoke

Status: `PENDING — no mutation before Task 12 passes`

Completion gate:

- UDP and TCP ring smoke pass.
- Default-route fingerprint is unchanged.
- Temporary adapter/address/TEST-NET routes are absent afterward.

## Task 14 — Full DIRECT real-machine acceptance

Status: `PENDING — no mutation before a fresh authorization`

Scope:

- IPv4 HTTPS/TCP, UDP, DNS A/AAAA, TCP lifecycle, fragmentation/checksum,
  timeout/cancellation, network change, physical outbound, Wintun reinjection,
  three start/stop cycles, startup failure, forced termination, and recovery.
- Record IPv6 public transport as environment-unsupported if the target still
  has no IPv6 default route.

Completion gate:

- Pre/post baselines match except for explicitly documented operator actions.
- Operator-owned management route is never changed by the program.
- Required packet captures, counters, hashes, and recovery evidence exist.

## Task 15 — Final acceptance report

Status: `PENDING`

Use this structure:

- test machine and network environment;
- action-time authorization and out-of-band proof;
- artifact source, hashes, and signatures;
- pre-change baseline;
- per-protocol results;
- packet-capture and counter evidence;
- three lifecycle results;
- fault and recovery tests;
- post-change restoration comparison;
- untested or environment-unsupported items;
- defects and fix commits; and
- final disposition: pass, partial pass, or fail.
