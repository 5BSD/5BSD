# Deep adversarial review: complete FreeBSD Bluetooth stack

Act as a senior Bluetooth Core, Mesh, kernel networking, security, concurrency,
and systems-C reviewer. Perform a fresh, read-only, evidence-driven review of
the current `/usr/src` worktree. The worktree contains uncommitted user work:
do not edit, reset, clean, format, or otherwise disturb implementation files.

## Authority and comparative context

- Treat `/usr/src/bluetooth-specs/Core_Specification_6_3.txt` and its PDF as
  normative for Core behavior. Use the local profile PDFs where applicable.
- Use `/tmp/bluez` as mature comparative implementation evidence, never as a
  normative standard. Distinguish intentional FreeBSD architectural choices
  from actual correctness defects.
- Mine relevant `/tmp` build, sanitizer, coverage, and per-test review results,
  but revalidate every adopted conclusion against the current worktree.

## Complete implementation scope

Review end-to-end behavior across, at minimum:

- `usr.sbin/bluetooth/blued`, `bluedctl`, `meshd`, `meshctl`, and `hccontrol`;
- `lib/libble`, `lib/libmesh`, and Bluetooth-facing `lib/libbluetooth` code;
- `sys/netgraph/bluetooth`, including HCI, L2CAP, ISO, sockets, and virtual HCI;
- every relevant program under `tests/usr.sbin/bluetooth/blued` and
  `tests/sys/netgraph`, plus build/packaging/rc/manpage integration;
- corresponding BlueZ daemon, shared ATT/GATT/L2CAP/HCI/crypto, mesh, emulator,
  and unit-test code under `/tmp/bluez`.

Trace whole operations rather than files in isolation: adapter discovery and
selection; legacy/extended/periodic advertising and scanning; connection and
privacy lifecycles; HCI command/event correlation; L2CAP signaling, LE CoC and
ECBFC; ATT/GATT/EATT; SMP legacy and Secure Connections; persistence and IPC;
ISO primitives; daemon/CLI lifecycle; Mesh provisioning, network/transport,
replay protection, IV/key refresh, friendship/LPN, proxy, relay, directed
forwarding, access/configuration/model behavior, persistence, and multi-node
isolation.

## Required audit dimensions

1. **Standards conformance.** Verify wire layouts, octet order, bit domains,
   address types, identifiers, state machines, timers, error/status codes,
   cryptographic inputs, replay/sequence rules, bounds, and required cleanup.
   Cite precise volume/part/section/table evidence for every standards claim.
2. **Correct C.** Audit undefined behavior, signedness and integer overflow,
   alignment/aliasing, lifetime/ownership, leaks/double-free/use-after-free,
   secret zeroization, unchecked sizes, partial I/O, EINTR/EAGAIN/EOF/SIGPIPE,
   locks, atomics, callbacks, cancellation, shutdown races, stale handles, and
   resource exhaustion. Enforce FreeBSD C/style and build contracts only where
   they affect correctness or maintainability materially.
3. **Security.** Audit peer-controlled input before every field access; pairing,
   authorization, downgrade and repeated-attempt defenses; key storage and
   rollback; IPC credentials/capabilities/fd passing; cross-adapter, cross-peer,
   cross-client, and cross-mesh-node isolation.
4. **Architecture and interoperability.** Compare relevant behavior with BlueZ
   to expose omissions or suspicious divergence, but report only demonstrated
   defects in this implementation.
5. **Tests.** Inspect the entire suite for false positives, tests that do not
   exercise production code, incorrect expected values, missing failure-path
   assertions, flaky timing, sanitizer incompatibility, build omissions, and
   coverage claims unsupported by execution. A missing test is a finding only
   when tied to a concrete production defect or materially false assurance.
6. **Verification.** Run the narrowest safe builds, tests, static analysis, and
   sanitizer/coverage diagnostics available. Never infer success from artifacts
   alone; record exact commands, exit status, and environmental limitations.

## Review method

- Treat comments, handoff notes, test names, and prior results as claims, not
  proof. Follow actual current control/data flow and error cleanup.
- Search for duplicates before reporting. Reduce related symptoms to the
  narrowest root cause. Do not report already-fixed code or style-only nits.
- Validate line numbers immediately before finalizing. Findings must point to
  the smallest defective range in the current worktree.
- Do not silently broaden exclusions: all implemented Bluetooth functionality,
  including Mesh and ISO primitives, is in scope.

## Output contract

Produce `BLUETOOTH_FULL_REVIEW.md` containing:

1. Scope, worktree/reference identity, and verification commands/results.
2. Findings sorted by priority. Each finding must be exactly:
   `[P0|P1|P2|P3] Imperative title — /absolute/path/file:start-end`
   followed by one compact paragraph proving trigger, faulty behavior, impact,
   and code/spec/BlueZ evidence. P0 is catastrophic; P1 is security boundary,
   corruption, or common workflow failure; P2 is a concrete interoperability,
   lifecycle, or resource defect; P3 is narrow but real correctness loss.
3. A subsystem coverage matrix listing reviewed surfaces and verification.
4. Rejected/superseded prior claims, so stale `/tmp` artifacts are not mistaken
   for current defects.
5. Residual risks and test/environment limitations.

If no concrete defect remains, say `No findings.` Do not claim complete
conformance merely because tests pass; state exactly what evidence establishes.
