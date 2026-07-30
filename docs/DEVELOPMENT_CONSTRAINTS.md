# Development constraints

This file is normative for changes to the Windows Wintun/DIRECT data path.
`MUST`, `MUST NOT`, `REQUIRED`, and `STOP` are release and acceptance gates,
not recommendations. If another design note or runbook conflicts with this
file, this file wins until the conflict is corrected.

## Preserve the active management path

Full capture installs IPv4 and IPv6 split-default routes that are more
specific than an ordinary default route. The management connection can
therefore be captured before the data path is ready, or while it is failing,
unless its remote peer is already pinned to the physical interface.

The following constraints apply to every RDP, SSH, or other management
connection used during development and acceptance:

1. Access through the interface and default route being tested is in-band. It
   MUST NOT be described or accepted as out-of-band recovery.
2. Immediately before any network mutation, the established management
   connection's local address, local port, remote address, remote port, and
   address family MUST be collected again. A previously observed peer address
   MUST NOT be assumed to remain current.
3. The remote peer MUST have an exact IPv4 `/32` or IPv6 `/128` route in the
   Windows `ActiveStore` before the application adds an address, interface
   setting, shadow route, or split-default route.
4. That host route MUST select the confirmed physical interface generation
   (ifIndex and LUID) and expected gateway. A correct host route may use any
   valid metric because its prefix length, not a hard-coded metric, keeps it
   ahead of the Wintun `/1` routes.
5. The host route is operator-owned recovery infrastructure. The application
   MAY read and require it, but MUST NOT create it, update it, record it as an
   application-owned object, or delete it during normal stop, startup
   rollback, failure recovery, crash recovery, or network-change handling.
   It remains operator-managed after application exit; whether and when to
   remove it is outside the application's responsibility.
6. If the exact host route is absent, ambiguous, stale, points at the Wintun
   interface, or no longer wins route selection, startup MUST fail closed
   before the first network mutation.

Do not hard-code an address observed during one acceptance session. Store the
session-specific peer and route evidence with the acceptance record, not in
product defaults or source code.

## Action-time mutation gate

An isolated smoke test or full-capture start MUST NOT change an adapter,
address, interface setting, route, or DNS setting until all of these are true:

- an independently reachable VM, hypervisor, cloud serial, or equivalent
  out-of-band console has been demonstrated;
- the process has Administrator rights;
- the current management peer and its pre-existing exact physical host route
  have been freshly verified;
- the recovery helper, its application-local `wintun.dll`, their hashes, and a
  bounded retrying watchdog are already staged and verified;
- the complete pre-mutation baseline has been saved and hash-checked; and
- the operator has given explicit authorization for the listed changes at the
  time those changes will occur.

Repository access, ownership of a test machine, a broad instruction to
"operate the machine", or an earlier authorization does not satisfy the final
action-time authorization requirement. If any item is missing, STOP in the
read-only phase.

## Required lifecycle ordering

Startup MUST:

1. acquire exclusive recovery ownership and create any required durable intent;
2. freshly verify every operator-owned management host route;
3. prepare and verify the Wintun adapter and recovery identity;
4. install only application-owned Wintun addresses, settings, and routes; and
5. add split-default capture routes only after the management route
   preconditions still pass.

Normal stop, startup failure, and network-change rollback MUST:

1. stop accepting new flows and unregister change callbacks;
2. remove application-owned split-default and shadow capture routes while the
   Wintun session can still drain traffic;
3. end the Wintun session;
4. remove application-owned addresses and restore exact owned interface
   settings;
5. remove the application-owned adapter;
6. prove the owned routes, addresses, adapter generation, and interface-setting
   changes are absent or exactly restored; and
7. clear recovery state only after every preceding phase succeeds.

No cleanup path may delete or rewrite the physical default route or any
operator-owned management host route.
Failure in any phase MUST prevent later destructive phases from crossing that
safety boundary; the recovery journal remains for investigation/retry.

## Crash recovery and watchdog ownership

Recovery may mutate only objects whose complete identity and ownership can be
proved. Adapter-owned routes and addresses require the exact adapter
ifIndex/LUID/GUID/alias generation. Ambiguity, identity reuse, unexpected
state, or a user-writable journal claiming an external-interface route MUST
produce `recovery-required` without broad cleanup.

The watchdog MUST:

- run under the same Windows user/configuration context as the application;
- use a fixed directory containing the hash-verified recovery executable and
  `wintun.dll`;
- treat `runtime-active` as a retry condition until a bounded deadline, not as
  successful recovery;
- record every attempt and its final state; and
- remain armed until normal stop and post-stop baseline comparison both pass.

## Regression and release gates

Changes to routing or recovery MUST include tests proving:

- management exclusions never enter an application-owned `RecoveryPlan`;
- a missing or mismatched pre-existing host route causes zero network mutation;
- no physical-interface route reaches a create or delete API;
- capture routes are withdrawn before the Wintun session ends;
- journal/native-call failure points restore only exact application-owned
  objects;
- repeated recovery is idempotent when an adapter disappears asynchronously;
- watchdog retries `runtime-active` and preserves evidence on timeout; and
- unrelated physical routes remain byte-for-byte/effectively unchanged.

Windows CI smoke tests MUST remain isolated to TEST-NET addresses and routes.
They do not replace real-machine action-time gates. A new acceptance artifact
may be used only after its complete test, hash, dependency, and signature
checks pass.
