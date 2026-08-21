# WASPNest test package

`5BSD-waspnest-tests` is the aggregate qualification package for bhyve, VMM,
VirtIO, non-VirtIO device models, checkpoint/restore, and nested VMX.  The
fine-grained sources of truth remain the installed VirtIO and nested-VMX TSV
ledgers.  `waspnest-nonvirtio-coverage.tsv` separately prevents PCI and
platform devices from disappearing behind a successful VirtIO guest boot;
`waspnest-suite.tsv` defines the ordered release gates.

The entry point is `/usr/tests/waspnest/waspnest-test`:

* `list` prints the release-gate inventory.
* `status` summarizes Linux, 5BSD, and nested live dispositions directly from
  the authoritative ledgers.
* `post-reboot` verifies that the installed world, kernel, Oracle boot model,
  branding, VMM module, and test payload agree.
* `audit` runs source/ledger/manifest and orchestration self-checks without
  creating a VM or changing networking.
* `host` runs audit, sanitizer/model coverage, AF_VSOCK coverage, and the VMM
  Kyua corpus.  It first applies the installed-host gate, requires root, and
  never converts a privileged skip into a pass.
* `plan` prints the exact full live campaign without mutating the host.
* `release-ready` fails while any required VirtIO, nested, or non-VirtIO live
  or save/restore row is still pending or environment-dependent.
* `run` executes `full-qualification` automatically on an initialized Intel
  VMX host: Alpine, 5BSD, checkpoint, audio, bounded soak, and nested-VMX
  gates.  Other hosts default to the portable `qualification` profile;
  `PROFILE` may select an explicit supported profile.  Required image and
  networking inputs are validated by the existing
  `run-waspnest-qualification.sh` front end.  After the campaign completes,
  `run` applies the same `release-ready` gate, so a partial matrix cannot
  return an overall release pass.

Nested VPID qualification has two loader-time policies and therefore needs
two boots.  `full-qualification` exercises the positive VPID policy; run the
`nested-default` profile after rebooting with the default-off policy.  The
release gate checks both live ledgers and will not accept one boot as evidence
for the other.

Root execution is accepted from the installed `/usr/tests` payload.  Running
root-only gates from a development checkout requires the explicit
`WASPNEST_ALLOW_UNTRUSTED_SOURCE=yes` acknowledgement; ordinary `audit`,
`status`, and `plan` runs should remain unprivileged.  The runner fixes its
helper `PATH`, uses a private creation mask, and supervises the campaign so
HUP, INT, or TERM cannot become a pass or leave the manager unsupervised.

Every new descriptor returned by a VM, device, or checkpoint path is tested
at its actual boundary.  Enumeration or negotiated feature bits alone are
not activation evidence: the guest must exercise the distinguishing behavior
and the host must record the corresponding path.

Live coverage for a guest is required only where that guest has a supported
driver.  Unsupported features are acceptable only as explicit ledger
`driver-gap`, `not-applicable`, or unadvertised rows with negative coverage;
an unexplained skip is not a release result.

Nested VMX validators and readiness rows apply on amd64 Intel VMX and in the
nested/full profiles.  Other architectures retain the ledger in the package
but report the hardware gate as unsupported instead of attempting to compile
or run Intel-only probes.

The `nonvirtio` profile contains 50 named cases: live and checkpoint-policy
cases for Alpine and 5BSD for AHCI, NVMe, e82545, HDA, xHCI, framebuffer,
PCI/LPC UART, TPM CRB, hostbridge, passthrough, and qemu-fwcfg, plus Linux
pvpanic (5BSD has a recorded driver gap).  Restorable devices run an operation
continuously through both a nonterminal checkpoint and suspend/restore.  The
qemu-fwcfg cases split a port read across restore to prove selector/cursor
continuity.  TPM and passthrough have no portable snapshot implementation and
must reject the save without stopping or corrupting the live VM.

TPM and passthrough are environment-dependent qualification inputs.  A live
run of `PROFILE=nonvirtio` or `PROFILE=full-qualification` requires
`NONVIRTIO_TPM_PATH`, `NONVIRTIO_PASSTHRU`,
`NONVIRTIO_PASSTHRU_LINUX_ASSERT`, and
`NONVIRTIO_PASSTHRU_FIVEBSD_ASSERT`.  The two assertion values are reviewed
guest commands that must prove activation of the selected physical device;
enumeration alone is intentionally insufficient.  The ledger remains
`pending` until the cases produce accepted durable run evidence.
