# Kernel source retirement (2026-10-15)

This change removes inherited code that 5BSD does not intend to ship. It is a
source and package change; it does not install a kernel or upgrade the running
machine. The support boundary is ZFS as the primary filesystem, basic UFS2/FFS,
PF, the 64-bit native and Linux ABIs, and hardware from roughly 2011 onward.

## Removed

| Area | Source and build surface retired | User-visible result |
| --- | --- | --- |
| UDF | `sys/fs/udf`, both modules, `mount_udf`, `libprocstat`'s UDF handler, installed headers, rescue and tracing entries | UDF volumes no longer mount through the base kernel. ISO9660 and userspace optical-disc readers remain. |
| GEOM | cache, concat, mountver, stripe, union and zero classes; their modules, class command libraries, headers, tests and periodic jobs | Existing providers of these classes need migration before upgrading. ZFS vdev layouts replace GEOM concat and stripe for new 5BSD storage. |
| Netgraph | Cisco, Frame Relay, LMI, RFC1490 and Predictor-1 nodes; modules, headers and manual pages | Graphs that name these nodes no longer load. |
| 32-bit execution | FreeBSD32 and Linux32 kernel ABI sources, syscall generators, native i386 kernel implementation, FreeBSD32/Linux32 DTrace modules and arm64's enabled FreeBSD32 option; obsolete ABI entries in `truss` and `libsysdecode`, `ldd32` and unsupported dynamic linker back ends | 32-bit FreeBSD and Linux executables do not run. |
| Legacy buses | floppy controller, parallel port, CardBus/ExCA bridge, AGP, 3Dfx Voodoo and four i386-only driver trees (Geode I²C/crypto, Promise SuperTrak, SBNI); their modules, utilities, headers and manual pages | These devices are outside the hardware support horizon. USB mass storage, PCIe, SD readers and generic PPS timing remain. |
| ARM32-only platform code | QEMU, Qualcomm, Rockchip and TI source trees under `sys/arm`, and their orphaned module recipes | The supported arm64 drivers remain in `sys/arm64`, `sys/dev`, and shared `sys/arm` paths. |
| PowerPC kernel remnants | The remaining `sys/powerpc` header tree, unused NCSW/DPAA and MacIO drivers, and drivers whose only remaining header dependencies were PowerPC specific | Native PowerPC targets remain unsupported; retained compiler back ends can still process foreign object files. |

The ARM64 DPAA2 network driver remains; it is separate from the retired
PowerPC DPAA/NCSW code.

The corresponding old installed files are listed in `ObsoleteFiles.inc` for
`delete-old`. Package builds omit the retired modules and commands. No deletion
of files from the live system was performed here.
The i386 and powerpc manual trees were also removed; they described kernel
targets that 5BSD no longer builds. ARM manuals remain where the drivers are
shared with arm64.
The amd64 BIOS bootstrap still builds 32-bit boot code and uses selected i386
headers. This is firmware-facing boot code, not 32-bit process execution; the
BIOS boot path was explicitly retained.
`libkvm` now reads crashes for the three supported native architectures only;
the ARM32, i386 and PowerPC readers were retired.
Startup no longer builds 32-bit loader hints or accepts 32-bit linker paths;
`ldd` diagnoses 32-bit ELF files as unsupported.
The old 32-bit ABI test tree is removed, and `src.conf(5)` records that LIB32
is unavailable.

## Kept after dependency review

Core GEOM, partition handling and GPT labels remain because ZFS, UFS/FFS and
the EFI boot mount use them. GELI, mirror and RAID remain because the installer
still offers encrypted root/swap, mirrored swap and RAID cleanup. Gate remains
for HAST and ggate. UZIP remains for compressed memory-disk startup, and NOP
and multipath remain because the ZFS and GEOM test suites exercise them.
Linux LVM2 is a current disk format: its GEOM reader and module remain.
The upstream [RHEL 10 LVM documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/configuring_and_managing_logical_volumes/configuring_and_managing_logical_volumes)
documents ongoing LVM2 use.
FreeBSD 9 and newer compatibility options remain within the requested 10 to
15 year window; an unreachable FreeBSD 8 feature declaration was removed.
The AAC, AACRAID, IPMI, MFI and MRSAS Linux management adapters also remain;
they now use Linux64 syscall declarations and depend on `linux64.ko`.

Netgraph core, sockets, Bluetooth nodes, PPP/PPPoE, L2TP, MPPC and VJ
compression remain. Base PPP/PPPoE utilities use some of these, Bluetooth
provides radio and virtual-controller paths through Netgraph, and the mpd5
port references MPPC. NFS, SCTP and IPsec remain as requested. PF and
Dummynet remain; no firewall stack was changed in this pass.

## Ports review

The custom ports checkout at `/usr/obj/5BSD-ports` was searched for direct
references to the removed kernel interfaces. Its `devel/freebsd-sysroot`
packing lists describe an upstream FreeBSD sysroot, not 5BSD's installed
headers, so editing those lists would break that port. `multimedia/libudfread`
and `sysutils/kpmcore` contain independent userland UDF support; both remain.
The `net/mpd5` port refers to the retained MPPC node. The legacy VirtualBox
port requires FreeBSD32 and lib32, so it is marked broken with that reason;
its obsolete advice to re-enable the ABI was removed. The `pnm2ppa` install
example now uses the retained USB printer device `/dev/ulpt0` instead of the
retired parallel port `/dev/lpt0`. The unrelated dirty fail2ban port files
were not modified. The ports checkout's `UPDATING` file records both changes.
The 118 Linux RPM ports with `WANT_LINUX32` also contain 32-bit files in their
package manifests. Their 64-bit package splits need validation before removing the
i686 RPMs; simply clearing the flag would make the manifests inaccurate.
The amd64 manifests also contain valid x86_64 GCC files under `usr/lib`, so
path-based removal would delete 64-bit toolchain content. Those RPM ports
remain unchanged pending package-level validation.
Remaining 3Dfx mentions in ports describe emulators, shaders, historical
port moves or bundled documentation; they do not require the retired kernel
driver. No port directly names a removed kernel module.

## Validation

Kernel configuration generated successfully for amd64 GENERIC-NODEBUG, arm64
GENERIC and riscv GENERIC after source pruning. The 5 target/ABI, 4 software
selection and 3 console regression tests passed. The amd64 GENERIC-NODEBUG
kernel and module build passed before the final source pruning, and the final
kernel rebuild passed after the world build. The retained ZFS, UFS, PF, Linux
LVM2, VJ, Bluetooth and Linux64 management modules were present in its output.

Isolated builds passed for `libkvm`, `libsysdecode` against the new sysroot,
`ldconfig`, `ldd`, `stdbuf`, `truss`, and `kdump`. A synthetic ELF32 file was rejected by
the new `ldd`; `ldconfig -32` was rejected. The `libkvm` test rejected an
unsupported PowerPC kernel with the newly built library. The ports VirtualBox
`BROKEN` value and diff checks passed. Nineteenth-round tracing verified 8
offline profiles and 10 kernel objects; twentieth-round checks verified 9
linked components with tracing enabled and disabled, and its runtime/profile
tests passed.

Full build validation passed, one retirement build at a time with
`-j8`: arm64 world and kernel, riscv64 world and kernel, then amd64 world and
kernel. The arm64 world resumed with `NO_CLEAN` from an interrupted `-j16`
run. Its first `-j8` attempt reached stage 4.4 and exposed an unaligned ELF
fixture cast in `libcapimage` tests. The next attempt exposed the same pattern
in a `switchboard` test. Both fixtures now use aligned struct members; a
source search found no other ELF header casts of this form. Two later attempts
reached stage 4.4 and stopped on bhyve migration helpers that were unused in
one build mode or hidden from their source-including tests; those helpers now
compile in both contexts. Arm64 `buildworld` passed at 06:50 UTC on October 16;
its successful log is `/tmp/5bsd-retirement-buildworld-arm64-resume5.log`.
Arm64 `buildkernel` passed at 07:04 UTC on October 16; its log is
`/tmp/5bsd-retirement-buildkernel-arm64.log`. The resulting module build
includes `zfs.ko`, `pf.ko`, `geom_linux_lvm.ko`, and `ng_vjc.ko`. Riscv64
`buildworld` reached stage 4.2 but found that the host-built target-aware
DTrace linker generated a RISC-V provider object with no floating-point ABI
flags. The staged `drti.o` uses RVC and the double-float ABI, so `lld`
rejected the link. The linker now emits the target's `rv64imafdc`/`lp64d`
flags for ELF64 provider objects; the incremental riscv64 world retry ran
at `-j8` before the remaining kernel and amd64 builds. The riscv64 world
retry passed at 10:13 UTC on October 16; its log is
`/tmp/5bsd-retirement-buildworld-riscv64-resume.log`. The generated provider
object and staged `drti.o` both have ELF flags `0x5` (RVC, double-float ABI).
The first riscv64 kernel pass then found that the crypto SDT provider
declarations were inside an x86/arm64-only header guard, although the probes
are called on riscv64. The guard now covers only the machine PCB header; the
provider declarations are available on all supported architectures. Riscv64
`buildkernel` passed on retry at 10:18 UTC on October 16; its log is
`/tmp/5bsd-retirement-buildkernel-riscv64-resume.log`. The module build
includes `zfs.ko`, `pf.ko`, `geom_linux_lvm.ko`, and `ng_vjc.ko`.
The final amd64 `buildworld` and GENERIC-NODEBUG `buildkernel` passed at 10:20
UTC on October 16. Their logs are `/tmp/5bsd-retirement-buildworld-amd64.log`
and `/tmp/5bsd-retirement-buildkernel-amd64.log`. The retained ZFS, PF, Linux
LVM2 and VJ module artifacts are present in the amd64 object tree.
The sequence and results are recorded in
`/tmp/5bsd-retirement-validation-status.log`. The first amd64 `buildworld`
run was interrupted during LLVM cross-tool compilation because another build
was using the same `/usr/obj/usr/src` object tree; that run cannot be used as
an integration result. Its log is `/tmp/5bsd-retirement-buildworld.log`.
No packages are being published, installed or booted. A standalone `libsysdecode` build
against the running host's older headers failed because those headers still declare removed
ioctls; the same build against the new world sysroot passed. The standalone
runtime linker build needs the new world's `libc_nossp_pic.a`; the completed
`buildworld` validated that link.

The host's boot pool, EFI GPT label and filesystems were inspected before the
change. No running provider uses a retired GEOM class, but other installations
may. Migration of such providers is an upgrade prerequisite.
