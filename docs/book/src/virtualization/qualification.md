# Qualification and Testing

WASPNest treats qualification as a first-class deliverable. Completion is
not asserted in prose: every requirement, guest activation, and device is a
row in a machine-readable TSV ledger, validators enforce ledger integrity,
and a fail-closed release gate refuses to pass while any required row is
pending. `docs/waspnest-completion-matrix.md` is the entry point;
`docs/waspnest-qualification-handoff.md` is the operational handoff.

## Evidence vocabulary

The suite distinguishes evidence classes and forbids collapsing them
(`docs/waspnest-test-readiness-plan.md`):

- **model-verified** — rootless host-model, wire, and negative tests pass;
- **live-qualified** — a real guest drove the feature's distinguishing
  behavior and the host trace proves that path ran (enumeration or
  feature-bit negotiation is never activation evidence);
- **release-qualified** — live evidence across every claimed guest and
  platform, plus checkpoint/soak gates;
- **driver-gap** — an explicit record that a guest lacks the driver.

## The WASPNest test suite

`tests/waspnest/` installs `/usr/tests/waspnest/waspnest-test`, driven by
`waspnest-suite.tsv` (ordered release gates: package-selftest, post-reboot,
audit, host-model, vmm-kernel, linux-live, fivebsd-live, nonvirtio-live,
checkpoint, nested-vmx, soak):

```sh
/usr/tests/waspnest/waspnest-test list        # gate inventory
/usr/tests/waspnest/waspnest-test status      # dispositions from all ledgers
/usr/tests/waspnest/waspnest-test audit       # validators + lab selftest, no VM
/usr/tests/waspnest/waspnest-test plan        # print the exact campaign
/usr/tests/waspnest/waspnest-test run         # full supervised campaign (root)
/usr/tests/waspnest/waspnest-test release-ready
```

`release-ready` demands zero failed/blocked cases, per-case status files,
content-bound input identities in `run.config`, and zero `pending` or
`environment-dependent` rows across the VirtIO activation, nested, and
non-VirtIO ledgers. Non-VirtIO coverage (13 devices: AHCI, NVMe, e82545,
HDA, xHCI, framebuffer, UARTs, TPM CRB, pvpanic, hostbridge, passthrough,
fw_cfg) is tracked in `waspnest-nonvirtio-coverage.tsv` with mechanically
enforced case naming (`validate-nonvirtio-coverage.sh`).

Full campaigns are launched through
`tests/sys/kern/vsock_e2e/run-waspnest-qualification.sh`, which validates
the configuration in plan mode before touching the host, then drives the
`virtio-lab.lua`/`virtio-lab.yaml` case matrix. Profiles range from
`qualification` to `full-qualification`, `nested`, `checkpoint`, `soak`,
and `nonvirtio`; Alpine ISO and 5BSD image inputs are SHA-256-pinned, and
results land under a `WORKDIR` with `summary`, `events.tsv`, and per-case
status. Interrupted runs resume with `RESUME=yes`; cancellation is
explicitly "not qualification evidence".

## Disk I/O qualification

`docs/waspnest-disk-io-qualification.md` records four separated findings
from block-path qualification: a mounted-root resize hazard mitigated by
making resize notification opt-in (`resize=true`); short `pwritev(2)`
writes now retried on a private iovec cursor; a pause-fence that rejects
guest flushes while a backend is paused; and one unresolved item — a ZFS
sustained-write livelock in the guest, reproducible with a 1.5 GB
`dd`+`sync`. That last item has a mandatory root-only debugging gate
(guest kernel dumps with retained symbols, at least three runs each for
single-queue and multiqueue, DTrace `vtblk:::request-submit/complete`
balance accounting) and no speculative workaround is enabled.

## Reference corpus

Reviews compare against digest-pinned normative and interoperability
sources listed in
`tests/sys/kern/vsock_device_harness/virtio-reference-corpus.tsv`: the
OASIS VirtIO 1.4 spec, Intel SDM volumes 3 and 4, and pinned Linux and
QEMU archives (oracles only; no code is copied). Privileged runs may cite
a reference directory only if
`validate-virtio-reference-corpus.sh ... --waspnest <dir>` verifies every
artifact's digest; `docs/waspnest-reference-corpus-status.md` records that
the current exploratory cache does not qualify and must be re-staged.

## Review process

All virtualization code goes through a sustained adversarial review whose
prompt is `tests/sys/kern/vsock_e2e/DEEP_REVIEW_PROMPT.md`: a 29-pass
cycle (state/ownership, error propagation, concrete concurrency schedules,
protocol boundaries, resource exhaustion, observability, test validity,
independent kernel re-reviews, and more). Every claimed defect needs a
regression test that fails before the fix; after fixes, the cycle restarts
at the pass following the last defect, and review terminates only when a
complete cycle finds nothing actionable and the sanitizer,
privileged-provider, live-matrix, and soak gates all pass.
`docs/waspnest-review-status.md` is the append-only log — roughly 270
dated snapshot sections from 2026-07-27 through 2026-08-11, each recording
the defect, fix, and regression test, with the explicit rule that a commit
is not review evidence.

## Status

As of the 2026-08-13 ledger snapshot: the rootless baseline is green
(device harness under ASan/UBSan, 349 nested-VMX model cases, `-Werror`
builds of bhyve, `vmm.ko`, and all 15 in-tree 5BSD VirtIO guest modules),
but no live-guest, checkpoint, non-VirtIO, nested-L2, or soak
qualification has yet passed, the ZFS sustained-write livelock is open,
and release qualification is therefore blocked by design until every
ledger row is exercised or explicitly excluded.
