# Full Bluetooth implementation review

## Outcome

No findings.

This means that the review loops described below ended without another
demonstrated, actionable source defect in the reviewed worktree.  It does not
mean that source review and an offline test suite constitute Bluetooth SIG
qualification, prove every controller interaction, or prove the absence of
all bugs.

## Scope and reference identity

The review used the procedure in `BLUETOOTH_FULL_REVIEW_PROMPT.md` and covered
the Bluetooth implementation under `usr.sbin/bluetooth`, `lib/libble`,
`lib/libmesh`, the Bluetooth portions of `lib/libbluetooth`,
`sys/netgraph/bluetooth`, and the Bluetooth ATF programs under
`tests/usr.sbin/bluetooth/blued` and `tests/sys/netgraph`.  The review traced
daemon and CLI lifecycle, IPC, HCI, advertising/scanning, connection/privacy,
L2CAP/LE CoC/ECBFC, ATT/GATT/EATT, SMP and persistence, ISO, and Mesh bearer,
network, transport, configuration, model, relay, proxy, LPN/Friend, and
persistence paths.

The implementation worktree was based on FreeBSD commit
`d14e7d716b14f9579b6224ed65752502b03c77d0`.  It was already heavily modified
(334 status entries when the review prompt was captured), so no clean-tree
assumption was made and unrelated user changes were preserved.

Normative local Core context was
`bluetooth-specs/Core_Specification_6_3.txt` (SHA-256
`65a7dc1ff4f1967dcb2016f757244d09f1c330f489cb740fbe2854200e54a785`) and the
matching PDF.  The local A2DP 1.3.2, AVDTP 1.3, AVRCP 1.6.3, CAP 1.0.1, and
GATT Supplement PDFs were used where applicable.  `/tmp/bluez` at commit
`629b788e11b5ba7a8b1554c5ed1b8a02f2f9f310` was comparative implementation
evidence, not a normative source.  In particular, BlueZ's authenticated Mesh
control dispatch and Friend credential/transmit paths were compared with the
local Mesh daemon before deciding that the local production daemon must not
advertise Friend support.

## Review loops and remediations

The adversarial review was repeated across core daemon/library, kernel
HCI/L2CAP/ISO, Mesh, and test-suite surfaces.  Each candidate was re-read in
current control flow, reduced to a root cause, fixed, built, and regression
tested before the next pass.  The material defects removed during those loops
included:

- detached `blued` setup-worker lifetime and shutdown races, control-client
  locking, and incorrect powered-adapter preconditions for global MTU/GATT
  operations;
- `libble` IPC waits whose timeout could be restarted by async events or
  `EINTR`, plus descriptor-receive interruption handling;
- stale L2CAP/EATT and ISO test expectations that did not exercise the current
  production contracts;
- incomplete ISO CIS handle/role propagation, duplicate-CIS acceptance,
  receive fragmentation/timeout cleanup, and transmit-credit leakage or
  mis-accounting across completion, disconnect, and timeout paths;
- an incoming CIS duplicate check and HCI forwarding telemetry that did not
  reflect actual delivery;
- Mesh persistence atomicity/versioning, queue retention, independent relay
  and network retransmission parameters, retransmission scheduling, and a
  daemon tick too coarse for the protocol's retransmission intervals;
- false Friend capability exposure.  The Friend helper FSM is not connected to
  the authenticated production bearer, so composition and Configuration
  Server state now report `Not Supported`, persistence cannot re-enable it,
  `friend 1` configuration is rejected, the control surface says
  `unsupported`, and the implementation-limit documentation agrees.

The last green full-suite run was followed by a separate configuration,
control-output, and documentation consistency pass.  That pass found and
removed the final silent Friend-configuration mismatch, after which both the
focused and complete suites were rerun.

## Verification

The principal final commands and results were:

| Verification | Result |
|---|---|
| `env MAKEOBJDIRPREFIX=/tmp/bluetooth-final-obj ... make all` in `lib/libble`, `lib/libmesh`, `usr.sbin/bluetooth/meshd`, and the relevant Bluetooth kernel module directories | Clean builds under the tree's strict C warning policy; final `meshd` and `ng_btsocket` rebuilds succeeded |
| Focused `kyua test meshd_test iso_socket_test` | 56/56 passed before the final operator-surface consistency correction |
| Focused `kyua test meshd_test` after that correction | 37/37 passed; result `...20260718-222419-061975` |
| Final `kyua test` in the isolated Bluetooth test object directory | 3,148/3,165 passed, 0 failed, 0 broken, 17 skipped; result `...20260718-222425-288635` |
| `git diff --check` | No whitespace errors in tracked diffs |

The 17 skipped cases are the `hci_hw_test` cases requiring root privileges and
real controller access.  They cover controller reset, address/features/buffer
queries, scan and advertising cycles, periodic/extended advertising, privacy,
filter/resolving lists, data-length defaults, PHY, and connection-parameter
behavior.

## Subsystem coverage matrix

| Surface | Review evidence | Final verification |
|---|---|---|
| `blued`, control IPC, CLIs | lifecycle, worker ownership, request correlation, credentials, fd/event handling, shutdown and persistence paths | strict builds and daemon/IPC/fault tests in the 3,165-case suite |
| HCI and privacy | command/event layouts, handles, roles, controller state, malformed events, flow accounting | HCI offline, privacy-kernel, role, periodic/DF, event and logging tests |
| L2CAP, ATT/GATT/EATT | signaling states, deferred acceptance, ECBFC, bearer selection, MTU, malformed PDUs and async interleaving | L2CAP signaling/data plus ATT/GATT client/server/deep/fault suites |
| SMP and key persistence | legacy/SC/OOB/CTKD flows, policy, timeouts, rate limiting, crypto failures, atomic encrypted bond storage | pairing, scenario, negative, timeout, secret, key-edge and fault suites |
| ISO kernel/socket paths | CIS/BIS lifecycle, handle propagation, fragmentation, completion credits, disconnect/timeout cleanup | strict kernel-module build and 19/19 `iso_socket_test` cases, plus HCI role/privacy tests |
| Mesh libraries and daemons | provisioning, crypto/network/transport/RPL, IV/KR, relay/proxy, models/configuration, manager/persistence, LPN/Friend exposure | strict `libmesh`/`meshd` builds and Mesh model, daemon, persistence, security and fault suites |
| Test suite itself | fixtures, expected wire values, production-source inclusion, failure-path assertions, timing and skip contracts | complete rebuild and two final complete executions with zero failures |

## Rejected or superseded claims

- Older `/tmp` failures and coverage notes were treated as leads only.  Claims
  involving pre-fix L2CAP deferred acceptance, EATT fixtures, ISO signatures or
  handles, Mesh persistence version 5, relay retransmission coupling, and
  setup-worker ownership are superseded by current code and passing targeted
  regressions.
- BlueZ behavior was not copied merely because it differed.  Its Mesh Friend
  path was relevant because it exposed concrete production integrations absent
  locally; the chosen fix was truthful capability reporting, not an incomplete
  imitation of that architecture.
- Direct unit tests of `meshd_friend_enable()` demonstrate the isolated helper
  FSM only.  They are not evidence of production Friend interoperability, and
  the daemon no longer presents them as such.
- A green offline suite was not treated as conformance certification.  It is
  evidence for the paths and fixtures it executed only.

## Residual risks and limits

No physical Bluetooth controller or peer device was exercised in the final
run, and the root-only hardware cases remained skipped.  No Bluetooth SIG PTS
campaign, RF coexistence testing, long-duration stress/soak run, or formal
qualification was performed.  The local standards collection does not contain
the Mesh Profile/Model normative PDFs, so Mesh conclusions used existing local
implementation contracts, tests, and BlueZ comparison and must still be
validated in an official Mesh PTS/qualification campaign.  Controller-specific
timing, firmware quirks, real-air packet loss, and concurrency schedules not
reached by the tests remain residual risk.
