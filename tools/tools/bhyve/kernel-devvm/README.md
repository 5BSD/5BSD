# Isolated bhyve kernel-development VM

This kit keeps experimental kernels and destructive kernel tests off the
physical workstation.  The VM defaults to 8 vCPUs, 16 GiB RAM, a sparse
96 GiB disk, a dedicated 20 GiB guest panic-dump disk in the same isolated ZFS
dataset, and a serial console.  Networking uses
bhyve's slirp backend; outbound traffic is allowed, while guest SSH is exposed
only at `127.0.0.1:2242` on the host.  No tap, bridge, host forwarding, or
firewall changes are required.  bhyve monitor mode keeps the process and SSH
forwarding alive across guest panic reboots.

## 1. Make physical-host panic recovery unattended

The current workstation has 32 GiB RAM but only a 2 GiB raw swap/dump
partition.  The setup script therefore enables Zstandard-compressed minidumps,
turns off interactive debugger entry on panic, keeps the panic trace, reboots
after 15 seconds, and enables `savecore` plus `crashinfo`:

```sh
su root -c 'sh /usr/src/tools/tools/bhyve/kernel-devvm/host-crashdump-setup.sh'
```

This is the best configuration possible with the current partition layout,
but a compressed minidump has no fixed upper bound.  For guaranteed capture,
add a dedicated raw dump device at least 36 GiB in size or configure a
`netdumpd` server, then set `DUMPDEV` to that device and rerun the script.
A ZFS dataset, regular file, sparse file, or ZFS zvol is not a reliable panic
target: panic dumping requires a provider with a safe `GEOM::kerneldump` path.

Do not deliberately panic the physical host to test this.  Validate panic,
dump, reboot, `savecore`, and debugger analysis inside the development VM.

## 2. Install and configure the VM manager

The slirp helper loads `libslirp.so.0` at runtime:

```sh
su root -c 'pkg install -y libslirp'
su root -c 'install -o root -g wheel -m 0644 \
  /usr/src/tools/tools/bhyve/kernel-devvm/kernel-devvm.conf.sample \
  /etc/kernel-devvm.conf'
su root -c 'install -o root -g wheel -m 0555 \
  /usr/src/tools/tools/bhyve/kernel-devvm/kernel-devvm \
  /usr/local/sbin/kernel-devvm'
su root -c 'install -o root -g wheel -m 0555 \
  /usr/src/tools/tools/bhyve/kernel-devvm/host-crashdump-setup.sh \
  /usr/local/sbin/kernel-crashdump-setup'
```

Review `/etc/kernel-devvm.conf` before creating anything.  Creation refuses to
overwrite an existing image.  The source image is treated as read-only.

```sh
su root -c '/usr/local/sbin/kernel-devvm create'
su root -c '/usr/local/sbin/kernel-devvm provision'
su root -c '/usr/local/sbin/kernel-devvm start'
```

`provision` mounts only the cloned image, requires exactly one UFS root
partition, installs the host's public key for key-only root SSH, enables DHCP,
arms FreeBSD's first-boot growfs service, and installs the crash setup helper
as `/root/kernel-crashdump-setup.sh`.  The original
`/home/koryheard/vm/bsd-guest.img` is never mounted or modified.

Watch the first boot if desired:

```sh
su root -c '/usr/local/sbin/kernel-devvm console'
```

Exit `cu` with `~.`.  Once SSH is ready, agents running as the host account can
enter without host root privileges:

```sh
/usr/local/sbin/kernel-devvm status
/usr/local/sbin/kernel-devvm ssh
/usr/local/sbin/kernel-devvm ssh uname -a
```

The private key never enters the guest; only its public key is injected.  A
dedicated known-hosts file prevents VM rebuilds from altering the user's normal
SSH trust database.

## 3. Snapshot and kernel-test workflow

Sync or clone the source tree into the guest, build there, install the test
kernel there, and reboot only the guest.  Before a risky test:

```sh
su root -c '/usr/local/sbin/kernel-devvm stop'
su root -c '/usr/local/sbin/kernel-devvm snapshot before-mac-capability'
su root -c '/usr/local/sbin/kernel-devvm start'
```

Never snapshot the writable disk while bhyve is running.  Rollback is
intentionally not automated because it destroys newer guest state; perform it
only after reviewing `kernel-devvm snapshots` and the exact ZFS target.

Inside the guest, configure the same crash policy with a dump device sized for
the guest's 16 GiB RAM.  The manager attaches its dedicated 20 GiB raw image as
`/dev/vtbd1`, which the installed helper selects automatically:

```sh
/root/kernel-crashdump-setup.sh
```

Take a stopped snapshot before the first intentional panic.  Then trigger the
panic from the host and wait for monitor mode to reboot the guest:

```sh
/usr/local/sbin/kernel-devvm ssh sysctl debug.kdb.panic=1
sleep 30
/usr/local/sbin/kernel-devvm ssh ls -lh /var/crash
```

The panic test should produce all of:

1. automatic dump and reboot;
2. `/var/crash/info.N` and `/var/crash/vmcore.N`;
3. `/var/crash/core.txt.N` when `crashinfo_enable=YES`;
4. a usable backtrace from the matching kernel and vmcore.

After that gate passes, rerun the full `mac_capability` suite in the VM and
retain the vmcore, matching kernel, test result database, and console log when
the coalition/prison teardown panic reproduces.
