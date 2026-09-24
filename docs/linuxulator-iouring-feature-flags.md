# io_uring feature-flag audit

Reference: Linux 7.1.5 in the disposable reference VM and the upstream
[io_uring_setup manual](https://man7.org/linux/man-pages/man2/io_uring_setup.2.html).
These feature bits describe behavior implemented by the shared squeue engine,
so both native squeue and the Linuxulator advertise them from
`SQ_SUPPORTED_FEATURE_FLAGS`. No Linux-only execution path is needed.

| Feature | Contract and named positive/negative tests |
| --- | --- |
| `IORING_FEAT_SQPOLL_NONFIXED` | `sqpoll_nonfixed_shared`: ordinary fd pipe read under SQPOLL; closed fd returns `-EBADF`. Tests both frontends, ZFS and tmpfs. Linux 7.1.5 oracle passed. |
| `IORING_FEAT_CQE_SKIP` | `cqe_skip`: successful linked NOP suppresses its CQE; a failing read with `IOSQE_CQE_SKIP_SUCCESS` still posts `-EBADF`. Linux 7.1.5 oracle passed. |
| `IORING_FEAT_LINKED_FILE` | `linked_file_feature`: a linked direct `OPENAT` installs a fixed-file slot before the dependent `WRITE`; a failed open cancels its dependent with `-ECANCELED`. Linux 7.1.5 oracle passed. |
| `IORING_FEAT_REG_REG_RING` | `feature_reg_ring_shared`: a register call through a registered ring fd succeeds; out-of-range and empty slots fail, and an unregistered slot becomes stale. Tests both frontends. Linux 7.1.5 oracle passed. |

The focused candidate VM logs are
`/tmp/linuxulator-gate-20260919/sqpoll-nonfixed-focus.console.log`,
`/tmp/linuxulator-gate-20260919/feature-bits-reg-focus.console.log`, and
`/tmp/linuxulator-gate-20260919/linked-feature-focus.console.log`.
The combined Linux 7.1.5 reference run passed all four feature contracts in
`/tmp/linuxulator-gate-20260919/linux715/oracle-feature-flags-final.console.log`.
The full amd64 ZFS-root gate passed in
`/tmp/linuxulator-gate-20260919/linked-feature-full-gate/results.json`:
395 Linux io_uring cases, 942 shared-option executions, 39 NO_MMAP,
33 dedicated SQPOLL and 24 MEM_REGION executions, with zero nonzero subtests
or kernel diagnostics, healthy ZFS, zero final ring/request/issuer counts and
clean QEMU shutdown. Exact source, kernel, module and test hashes are pinned in
`/tmp/linuxulator-gate-20260919/linked-feature-full-gate/manifest.json`.
An earlier complete VM run reported FAIL only because the host runner listed
`feature_reg_ring_shared` in a supplemental buffer-only inventory. The runner
inventory is corrected, and the later full gate above is the acceptance run.

`IORING_FEAT_NATIVE_WORKERS` remains clear: the current squeue worker pool is
a set of kernel threads, whereas Linux's feature means process-like native
workers. `IORING_FEAT_RW_ATTR` remains clear because native squeue has no storage
protection-information transport. The Linux frontend now rejects nonzero masks
explicitly and its full eight-opcode negative contract is recorded in
[the RW-attribute audit](linuxulator-iouring-rw-attr.md). Feature advertisement is independent of the remaining `ATTACH_WQ|SQPOLL`
stress combinations, IOPOLL, NAPI, hardware ZCRX and BPF contracts. Copied
Linux v7.1 NODEV ZCRX is qualified separately.


The later integrated 432-case amd64 ZFS-root gate includes both RW-attribute
cases and passed with the complete 1,092-run shared-option matrix, zero
recognized diagnostics or final tracked resources, healthy ZFS and clean
poweroff. Evidence is in
`/tmp/linuxulator-quota-20260921/full4-run/manifest.json`.
