# Kernel retirement follow-up (2026-10-16)

This source change narrows 5BSD's kernel and module surface on amd64,
arm64 and riscv64. It does not install or boot a new kernel. The retained
support boundary is ZFS, basic UFS2/FFS, PF, Linux64 and the networking and
storage paths listed in the [previous retirement](kernel-retirement-2026-10-15.md).

## Removed and ranked

| Priority | Component | Evidence and replacement | Effect |
| --- | --- | --- | --- |
| High | `stf(4)` 6to4 tunnel, including `ifconfig` commands, rc service, test and module | Native IPv6 is the preferred network path. [RFC 7526](https://datatracker.ietf.org/doc/rfc7526/) deprecated **6to4 relay anycast** in 2015 and requires host 6to4 to be disabled by default. It explicitly does **not** deprecate unicast 6to4; this is a 5BSD support decision. `gif(4)`, `gre(4)`, IPsec and other tunnel facilities remain. | Existing `stf`/`stf0` configurations must migrate before upgrade. |
| High | Netgraph `echo`, `ether_echo`, `hole`, `etf`, `source`, and the unused `sample` skeleton | These are standalone test, traffic generation or narrow EtherType utility nodes. They had no 5BSD runtime consumers after the unsupported `ng_ipacct` ipfw example was removed. `ng_bpf`, `ng_ether`, `ng_tee`, `ng_patch`, `ng_ip_input`, bridge and the PPP/Bluetooth graph nodes remain for supported graphs. | Graphs naming these node types no longer load. |
| High | Dormant `bsdlabel` and `fdisk` command sources | `gpart` is the supported partition manager for GPT, BSD labels, and MBR. The normal amd64/arm64/riscv64 subdirectory lists did not build either command; stale pseudo-userland and unsupported-architecture entries still named them. | No current supported system command is removed. Existing `delete-old` entries for historical binaries and manuals remain. |
| High | Dormant `comcontrol` serial utility and its old `serial` rc script | Both were already excluded from the normal base build and startup; the source recipes and stale manual references remained. | No current supported system command or service is removed. Their historical `delete-old` entries remain. |
| High | Dormant SMB1 `smbfs`/`netsmb` client, `libsmb`, utilities, examples, headers, and package stub | The build already excluded the client and its modules. [Microsoft deprecated SMB1 in 2014](https://learn.microsoft.com/en-us/windows-server/storage/file-server/Troubleshoot/smbv1-not-installed-by-default-in-windows); [Samba `smbclient` negotiates SMB3 by default](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html) for file transfer. It does not provide a drop-in `mount_smbfs` mount. | The disabled code is gone; previously installed SMB1 files are marked for `delete-old`. The `mountsmb2` port is marked broken because it requires `mount_smbfs`. |
| High | Dormant FireWire Ethernet/IP drivers `fwe` and `fwip` | Both network modules had already been excluded. The FireWire bus, SBP storage, camera and audio paths remain. | No supported network interface is removed from the active builds; the obsolete network headers/modules are marked for `delete-old`. |
| Medium | Attansic/Atheros L1 `age(4)` Ethernet driver | Its own manual identifies the L1 family and is dated 2008. The driver was compiled into amd64 GENERIC despite no matching adapter on the build host. Modern PCIe NIC families remain in GENERIC; adapters requiring `age` need newer hardware or another OS. This does **not** imply a different driver can operate the same L1 adapter. | L1 Ethernet adapters lose native 5BSD support. |
| Low | Dormant `tools/tools/sysbuild` helper | Its README instructs users to install FreeBSD 10 from SVN onto `ad0` slices with `bsdlabel`; nothing in the maintained build targets calls it. The maintained `/usr/src` build and package targets replace that workflow. | Removes an unmaintained historical helper; no installed command changes. |

The age ranking is conservative: [OpenBSD still lists `age(4)`](https://man.openbsd.org/age), so support in another maintained OS argues for preserving it longer than the 6to4 or test-only nodes. The removal follows 5BSD's roughly 2011-onward hardware horizon, not an assertion that no one uses the chip. The `IFT_STF` and `IFT_IEEE1394` interface type numbers remain reserved in the public header so removing the drivers does not renumber interface types; their dead protocol branches are removed.

Source files, module recipes, kernel configuration entries, installed headers,
manuals, rc settings, and the `if_stf` test were removed together. The SMB1
cleanup also removes its package metadata, userland library and commands,
installer header lists, and pseudo-userland references. The removed
installed paths are listed in `ObsoleteFiles.inc` for `delete-old`; nothing was
deleted from the running system. `sys/crypto/md4c.c` stays because the
userland `libmd` bootstrap and public MD4 API compile it independently of
SMB1. The `net-mgmt/ng_ipacct` port's ipfw divert
example was removed because it required `ng_echo` and ipfw, which 5BSD does
not ship. The port's supported `ng_ether` examples remain. `sysutils/mountsmb2`
is marked broken because its script invokes the retired `mount_smbfs`; this
does not affect Samba's userspace SMB clients or their libraries. The
`devel/freebsd-sysroot` manifests represent an upstream FreeBSD sysroot and
retain upstream headers by design.

The in-tree MSDOSFS regression scripts now use `gpart` MBR FAT partitions,
and the old tmpfs disk-image test uses `gpart` and UFS2. These are source-only
test updates; the root-only disk tests have not been run on this host.

## Next candidates after dependency review

| Candidate | Modern path | Current blocker or reason to defer |
| --- | --- | --- |
| Legacy ATA/PATA chipset modules | AHCI, NVMe and CAM for supported disks | Linux still maintains [PATA and SATA through libATA](https://docs.kernel.org/driver-api/libata.html); 5BSD's legacy `ata` code is outside GENERIC but has many module and boot-menu references. A complete dependency and boot audit is needed before source removal. |
| `ng_bridge` | `if_bridge` plus `epair`/virtual Ethernet; [OpenBSD also uses a bridge interface](https://man.openbsd.org/bridge) | `net/freevrrpd` explicitly requires `ng_bridge`, and 5BSD has dedicated netgraph bridge tests. A port migration is required first. |
| Hardware RAID controller families | Direct disk access and ZFS vdevs | Storage controllers expose boot disks and management interfaces; ZFS cannot replace a controller driver when disks are not exposed individually. Per-controller device and installer audits are required. |
| Other early PCIe NIC families | `igc`, `ix`, `vtnet`, and current physical NIC drivers | OpenBSD still supports several of the apparently old devices (`ale`, `et`, `jme`, `nfe`). Their last deployed hardware dates and host inventory need checking before dropping them. |
| `cdcontrol` CD audio command | `camcontrol eject` covers disc ejection; file-based audio tools cover music playback | `bsdconfig` calls `cdcontrol eject`; the `audio/ripperx` and `devel/glib20` ports also call it. Its CD audio and drive-volume controls have no direct `camcontrol` replacement, and [OpenBSD still ships the related `cdio` utility](https://man.openbsd.org/cdio). This is a low-priority candidate that needs an explicit feature decision. |

Core GEOM and GPT, Linux LVM2, UFS2/FFS, ZFS, PF, Bluetooth, PPP/PPPoE,
L2TP, MPPC/VJ, NFS, SCTP, and IPsec remain. `ng_pptpgre` remains pending a
port-level audit; its apparent age alone is not proof that its consumers are
gone. UHCI/OHCI/EHCI also remain because older EHCI controllers may require
USB 1.1 companion controllers for low- and full-speed devices, even though
modern xHCI controllers handle all speeds.

`camcontrol` remains. The ZFS installer calls it for disk inquiry and
identification; optical-drive ports use `camcontrol devlist`, and CAM is the
shared transport for supported SATA/SAS storage. `nvmecontrol` serves NVMe
devices rather than replacing those CAM functions. `camdd` also stays: it
exposes asynchronous CAM pass-through transfers that plain `dd` does not.
The BSD disklabel and MBR
format readers also remain in GEOM so old partitions can be read and UFS2
volumes remain accessible; retiring the unused command source does not remove
the on-disk format.

## Validation

The unrelated PF world and kernel build finished before this validation began.
In `/usr/src`, serial `make -j8 buildworld` and `make -j8 buildkernel
KERNCONF=GENERIC-NODEBUG` passed for each of amd64 (`TARGET_ARCH=amd64`),
arm64 (`TARGET_ARCH=aarch64`), and riscv (`TARGET_ARCH=riscv64`), in that
order. The six logs are `/tmp/5bsd-retire-20261016-{amd64,arm64,riscv}-
{buildworld,buildkernel}.log`. The first amd64 world attempt caught the
shared `sys/crypto/md4c.c` dependency; after restoring that file, all six
steps passed. This was development validation with the default malloc mode;
no packages were published and nothing was installed or rebooted.

`config` generated `GENERIC-NODEBUG` for all three architectures. Build list,
source/ports reference, `sh -n`, and staged-diff checks passed. Changed manual
pages passed `mandoc -Tlint` with only existing style notices. The
MSDOSFS/tmpfs device tests require root to create and mount `md` devices;
root access is unavailable in this shell, so those tests were syntax checked
but not executed.
