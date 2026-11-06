# VM case descendant cleanup qualification (2026-11-06)

## Observed failure and correction

The complete-package VM retry timed out at its 900-second whole-case deadline.
Its pkg subprocess had created a separate session for its own command timeout.
The harness killed only the test's process group; the separate session survived
and held the target, input and devfs mounts busy. The run remains FAIL, despite
clean guest shutdown. It is not reinstall or complete installation acceptance.

The maintained runtime_init fixture now supervises each body and cleanup under a
dedicated procctl(PROC_REAP_ACQUIRE) reaper. The supervisor sends SIGKILL through
PROC_REAP_KILL with REAPER_KILL_SUBTREE for that specific test child, enumerates
and reaps surviving descendants, and requires an empty subtree before cleanup.
A bounded 30-second drain failure fails the case. New sessions and nested process
groups cannot evade the OS descendant tree. This is fixture supervision, not a
production process or kernel policy change. PID 1 remains available for the later
Capsule handoff. Existing service latency assertions remain unchanged.

An initial attempt applied subtree filtering directly from PID 1. A real VM
regression rejected it: init's descendants share its special subtree identity.
The corrected acquired-reaper supervisor uses ordinary per-child subtree identities.
That failed attempt is retained; no kernel behavior or test expectation was changed.

The helper and probe now have native static Bazel binary targets alongside their
existing Make declarations. They use ordinary declared C inputs and ATF dependency.
The normal format-5 frontend builds and captures them; no C CLI or production
Make default changes are needed. Tests never install a host kernel or run as host
PID 1.

## Real positive and negative VM tests

runner_probe:session_leak forks a worker which calls setsid, waits for readiness,
and records its PID. Its body exits normally. Cleanup requires that the worker
no longer exists. runner_probe:session_timeout does the same, then deliberately
waits beyond its two-second deadline. Cleanup must succeed, but the timed-out
body and complete VM must still fail. These are fixture regression controls,
not product acceptance tests.

All paths below are relative to /usr/obj/usr/src:

- bazel-world-pkg-runtime-reaper-native-r1-20261106 builds complete package inputs,
  driver, first harness/probe and passes all eleven selected native test targets.
- bazel-runtime-reaper-native-r2-20261106 captures the corrected native helper and
  probe. It has tests=[]; it is compilation evidence, not executed-case evidence.
- bazel-runtime-reaper-normal-vm-r1-20261106 is the rejected direct-init-subtree
  attempt. Its escaped worker survived and cleanup correctly failed.
- bazel-runtime-reaper-normal-vm-r2-20261106/result.json is PASS. The escaped worker
  is gone before cleanup; all four unchanged baseline cases also pass.
- bazel-runtime-reaper-timeout-vm-r1-20261106/result.json is deliberately FAIL.
  The exact two-second timeout is recorded, the escaped worker is gone and cleanup
  passes. There is no product case pass or VM pass marker for this negative test.
- bazel-runtime-reaper-review-r1-20261106/review.json independently requires those
  exact positive/negative outcomes, single cleanup markers, unchanged baseline
  passes, no panic/WITNESS failure, clean QEMU exit and verified serial hashes.
  SHA256 9fbc64e3de31593830f5501a288063f24efb262f77f17d4f4884b6595cd34f72

These two disk-backed TCG VMs each use 2GB RAM/four vCPUs and a 3GB host RSS ceiling.
They prove the specific escaped-session regression. They do not qualify every
possible kernel wait state, full ATF isolation semantics or production services.

## Interrupted package evidence and new retry

bazel-world-pkg-install-vm-r2-20261106/result.json is FAIL. Its offline extracted
interrupted-checker-report.json records successful repository import, initial
445-package install (502.259 seconds), exact inventory, 32,512 verified payload
paths, 1,369 directory checks, zero discrepancies, pkg checksum checking and local
account creation. Reinstallation was interrupted before a result. Extraction
metadata records the read-only fsdb block observations; the source output image
and interrupted report remain diagnostic evidence, not a passing generation.

The checker now prints phase boundaries, records timeout output before failure,
and takes command_timeout_seconds explicitly from the fixture plan. The prepared
r4 fixture uses 900 seconds per command. The new install-vm-r3 invocation records
an explicit 1,800-second whole-case budget (the original declared ATF deadline
remains recorded), with a 2,100-second outer VM deadline. This allows the measured
complete initial install plus a second install and verification; it changes no
payload, state-preservation, failure or cleanup assertion. It is not performance
acceptance. The retry remains pending. Normal startup, new-version upgrades and
all full-system/platform/bootstrap/cache/sandbox/reproducibility/performance gates
remain open. BIP remains excluded.

Final provenance audit update: install-vm-r3 passes all installation/reinstallation
checks, but its plan staged the new helper under an unused alias, leaving the
legacy helper selected. It does not establish full-suite reaper qualification.
The independent new-helper probe VMs above remain valid. Exact fixture keys now
reject that plan, and the corrected install-vm-r4 repeat is pending. See
WORLD-PACKAGE-INSTALL-VM-QUALIFICATION.md for passing payload/state evidence and
the actual selected-helper hashes. No passing record is relabeled as a new-helper run.
