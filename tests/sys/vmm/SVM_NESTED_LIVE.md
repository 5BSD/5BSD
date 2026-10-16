# AMD nested-SVM guest qualification

Run `run-svm-nested-atf.sh` on separate default-off and enabled policy boots
as described in `docs/bhyve-virtio-state-nested-architecture.md`. On the enabled AMD boot, run
`run-svm-nested-live.sh` with a reviewed root-owned L1 driver and immutable
Linux/KVM L1, Linux L2, and 5BSD L2 images. The host needs AMD SVM with
DecodeAssists and `hw.vmm.svm.nested=1` before loading `vmm`.

Set `WORKDIR` to a fresh, private, root-owned directory of mode 0700. Set
`NESTED_L1_RUNNER`, `NESTED_L1_IMAGE`, `NESTED_LINUX_L2_IMAGE`, and
`NESTED_FIVEBSD_L2_IMAGE` to root-owned files below protected directories.
`KERNEL` and `BHYVE` optionally select matching trusted images; their
defaults are `/boot/kernel/kernel` and `/usr/sbin/bhyve`.
The wrapper rejects a running kernel whose build ID differs from `KERNEL`.

The L1 driver receives a clean environment with the four image paths, `WORKDIR`,
`NESTED_EVIDENCE_FILE`, `NESTED_LIVE_LEDGER`,
`NESTED_LIVE_ARTIFACT_DIR`, `NESTED_SVM_BHYVE`, `NESTED_LIVE_RUN_ID`, and
`NESTED_LIVE_TIMEOUT`. It must boot the pinned L1 and both L2 guests and
execute **every** scenario in `svm-nested-live-qualification.tsv`. For each
feature group it writes one Linux L2 artifact, one 5BSD L2 artifact, and one
host trace artifact, plus an evidence manifest at `NESTED_EVIDENCE_FILE`.
The driver must destroy every VM before returning success.

The manifest has the exact tab-separated header
`feature_id linux_l2_evidence fivebsd_l2_evidence host_evidence` (tabs between
fields). Each artifact token is `nested-svm-live:<safe-name>`, naming
`<safe-name>.evidence` in `NESTED_LIVE_ARTIFACT_DIR`. Tokens must be unique.
An artifact contains tab-separated records in this order:

```text
format	nested-svm-live-evidence-v3
feature_id	EXPOSURE-POLICY
role	linux-l2
result	PASS
run_id	<the exact NESTED_LIVE_RUN_ID>
started_utc	2026-10-16T12:00:00Z
finished_utc	2026-10-16T12:00:01Z
assertion	SVM-LIVE-001
proof	SVM-LIVE-001	guest-test	serial-log-identifier	1
```

Use `role=fivebsd-l2` for the second guest and `role=host` with proof type
`host-trace` for the host artifact. The final proof field is a positive
observation count. The feature and requirement ID must match the ledger row.
Both guest roles and the host role must independently assert and prove every
requirement ID in their row. Attach detailed logs and trace files in the
reviewed driver corpus and make the proof identifiers resolve to those files.
The host wrapper validates structure, ownership, run identity, timestamps,
complete coverage, and stable input hashes, then seals and publishes one
`svm-nested-live-result` directory. A passing structure check alone is not a
review of the semantic claims in the logs.

The repository does not ship guest images or a hardware-specific L1 driver.
Their absence leaves hardware qualification pending; it does not turn an
unexecuted group into a pass.
