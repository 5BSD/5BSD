# Linux remap_file_pages implementation and gate

Status: the amd64 Linuxulator handler and shared VM-map object-offset
replacement primitive passed the disposable amd64 ZFS-root QEMU gate.
The handler's five Linux arguments, page rounding, offset-overflow checks, Linux error policy and
prefault option belong to Linuxulator. Validating and replacing an existing
mapping under one VM map lock, while retaining its object after the creating
file descriptor is closed, belongs to shared VM code. No new native syscall
number is needed.

Linux 6.18 emulates the deprecated syscall by replacing the requested portion
of a shared mapping with a fixed mapping of the same backing file at the
requested page offset. It requires `prot == 0`, rounds `start` and `size`
down to page boundaries, rejects empty/overflowing ranges and private or
unmapped regions, ignores all input flags except `MAP_NONBLOCK`, and keeps
the original mapping's protections. The [Linux source](https://codebrowser.dev/linux/linux/mm/mmap.c.html#1082)
is the reference. The Linux 6.18.35 amd64 oracle for the freestanding
`tests/sys/kern/linux_remap_file_pages.c` probe passed at
`/tmp/linuxulator-gate-20260919/remap-oracle.console.log`.

The mandatory disposable amd64 ZFS-root gate runs the probe three times on
ZFS and three times on tmpfs. Each run creates a four-page shared file
mapping, closes the creating descriptor, aliases distinct file pages, checks
write coherence and the untouched original file page, remaps with unaligned
start/size and unknown flags, then checks nonzero `prot`, zero size, unmapped
address, a range past the mapping end, page-offset overflow and
private mapping rejection with unchanged mapping contents. It also exercises
`MAP_NONBLOCK`. A second group remaps across adjacent VM areas of the
same file, checks the mapping inherited by `fork`, remaps after a read-only
protection change, and rejects a range crossing into anonymous memory. The
full existing Linuxulator, native squeue, io_uring and AIO
matrix, zero diagnostics, healthy ZFS and clean shutdown remain required.
The exact revised binary (SHA-256
`9e7a5d4b5df97541e347cf38f76a93723130c2f28426e59b4fdc33e2891c9ac0`)
passed all six runs in
`/tmp/linuxulator-gate-20260919/remap-edge-gate/results.json`. The full
regression gate also passed: 42 rseq, 343 io_uring, 786 squeue option, 57
Linux AIO, 6 native AIO, 36 base and 144 pathname cases; no recognized
diagnostics, healthy ZFS and clean shutdown. The shared helper preserves vnode write-mapping and executable-mapping
accounting while replacing entries. The candidate kernel and modules were tested only in the disposable QEMU VM; none was installed or loaded on
the host.

Additional qualification remains for adjacent VMAs of the same/different
objects, memory-mapped seals, locked/pinned ranges, fork inheritance, and
concurrent map replacement. Those require Linux-reference positives and
negatives before claiming complete syscall compatibility.
