#!/bin/sh
# build-image-authority.sh — like build-image.sh, but boots Authority as PID 1.
#
# Differences from build-image.sh:
#   - relies on installworld for /sbin/capsule and /usr/libexec/switchboard
#     (an obj overlay of pre-rename authorityd/serviced used to live here)
#   - loader.conf sets init_path with capsule first and stock init
#     as fallback, and preloads the mac_capability modules
set -e

VM=$HOME/vm
R=$VM/guestroot
OBJ=/usr/obj/usr/src/amd64.amd64

# Default to a ZFS root: it matches the ZFS host/production, and a backing
# device I/O error degrades the pool instead of triggering UFS's
# root-forcible-unmount panic (which the legacy UFS image hit when GEOM_PART
# auto-resized the mounted root).  Set UFS_ROOT=1 to build the legacy UFS image.
if [ -z "$UFS_ROOT" ]; then
	ZFS_ROOT=1
fi

# installworld installs /sbin/capsule, /usr/sbin/capsulectl and
# /usr/libexec/switchboard itself since the authorityd->capsule and
# serviced->switchboard renames.  This script used to overlay freshly built
# authorityd/serviced binaries from $OBJ here; after the renames those obj
# paths hold STALE pre-rename builds, and copying one over /sbin/capsule
# produced a PID 1 that exited 1 before printing anything ("init died
# (signal 0, exit 1)" / "Going nowhere without my init!").  installworld is
# authoritative now; remove any leftover stale copies so they cannot be
# picked up by name.
echo "==> PID 1 and switchboard come from installworld (no obj overlay)"
rm -f $R/usr/sbin/authorityd $R/usr/libexec/serviced

echo "==> staging control-socket-aware reboot/halt/shutdown"
for f in reboot halt fastboot fasthalt; do
	rm -f $R/sbin/$f; cp $OBJ/sbin/reboot/reboot $R/sbin/$f
done
for f in shutdown poweroff; do
	rm -f $R/sbin/$f; cp $OBJ/sbin/shutdown/shutdown $R/sbin/$f
done

echo "==> writing guest config files"
cat > $R/boot/loader.conf <<'EOF'
virtio_vsock_load="YES"
console="comconsole"
autoboot_delay="3"
init_path="/sbin/capsule:/sbin/init:/rescue/init"
EOF

# ZFS_ROOT=1: boot a ZFS root pool (makefs -t zfs) instead of a UFS image, to
# match the ZFS host/production environment.  A device I/O error degrades the
# pool instead of triggering UFS's root-forcible-unmount panic.
if [ -n "$ZFS_ROOT" ]; then
	echo "==> ZFS_ROOT: zfs root pool 'zroot'"
	cat >> $R/boot/loader.conf <<'EOF'
zfs_load="YES"
vfs.root.mountfrom="zfs:zroot"
EOF
fi

# CAPLANE_OFF=1: keep capsule first in init_path (it still runs as PID 1),
# but set the capability_plane="NO" loader knob so capsule itself hands off
# to stock /sbin/init.  Validates the in-kernel-init escape hatch (not the
# init_path fallback that TEST_INIT exercises).
if [ -n "$CAPLANE_OFF" ]; then
	echo "==> CAPLANE_OFF: capability_plane=NO (capsule hands off)"
	cat >> $R/boot/loader.conf <<'EOF'
capability_plane="NO"
EOF
fi


# DTRACE_TEST=1: load the DTrace stack + OES module at boot so trace scripts
# can compile against live providers (fbt/sdt/pid, kernel CTF via /dev/dtrace).
if [ -n "${DTRACE_TEST:-}" ]; then
	echo "==> DTRACE_TEST: dtraceall + oes at boot"
	cat >> $R/boot/loader.conf <<'DTEOF'
dtraceall_load="YES"
DTEOF
fi

# LINUX_TEST=1: preload the Linuxulator modules so the linux_* ATF tests
# (require.kmods linux64) run without an in-guest kldload.
if [ -n "$LINUX_TEST" ]; then
	echo "==> LINUX_TEST: preload linux/linux64/linux_common"
	cat >> $R/boot/loader.conf <<'EOF'
linux64_load="YES"
EOF
fi

# TEST_INIT=1: boot stock /sbin/init instead of capsule so nothing claims
# /dev/mac_capability, and pre-load the channel/coalition/node modules the ATF
# channel tests need.  Lets the isolation-gated device stay openable by a root
# test process.  (Production boot uses capsule and locks the device.)
if [ -n "$TEST_INIT" ]; then
	echo "==> TEST_INIT: stock init + channel modules (device stays openable)"
	sed -i '' 's|^init_path=.*|init_path="/sbin/init:/rescue/init"|' \
	    $R/boot/loader.conf
	cat >> $R/boot/loader.conf <<'EOF'
EOF
fi

cat > $R/etc/rc.conf <<'EOF'
hostname="vsockguest"
sendmail_enable="NONE"
sshd_enable="NO"
cron_enable="NO"
auditd_enable="YES"
# vtbd0p3 is the 1g swap partition mkimg appends after the root: a panic
# leaves a crash dump there, savecore moves it to /var/crash on the next boot.
dumpdev="/dev/vtbd0p3"
crashinfo_enable="YES"
# Static networking for the NAT bridge start-vm.sh builds when UPLINK is set.
# Harmless when the guest is launched vsock-only (no vtnet0): rc just skips it.
ifconfig_vtnet0="inet 10.88.0.2 netmask 255.255.255.0"
defaultrouter="10.88.0.1"
EOF
# A panic must leave a crash dump and reboot rather than sit at the ddb
# prompt: the proofs read /var/crash with lldb on the automatic reboot.
grep -q '^debug.debugger_on_panic' $R/etc/sysctl.conf 2>/dev/null || {
	chmod u+w $R/etc/sysctl.conf 2>/dev/null
	printf 'debug.debugger_on_panic=0\nkern.panic_reboot_wait_time=3\n' >> $R/etc/sysctl.conf
	# the manifest's recorded size no longer matches: drop it for this entry
	chmod u+w $R/METALOG
	sed -i '' 's#^\(\./etc/sysctl.conf type=file [^ ]* [^ ]* mode=[0-7]*\) size=[0-9]*#\1#' $R/METALOG
}
# Resolver for the NAT path (Quad9/Cloudflare); only used once vtnet0 is up.
printf 'nameserver 9.9.9.9\nnameserver 1.1.1.1\n' > $R/etc/resolv.conf

if [ -n "$ZFS_ROOT" ]; then
	echo 'zfs_enable="YES"' >> $R/etc/rc.conf
	: > $R/etc/fstab		# ZFS root mounts from the pool bootfs
else
cat > $R/etc/fstab <<'EOF'
/dev/vtbd0p2	/	ufs	rw	1	1
EOF
fi

echo "==> root autologin on serial console + empty root password"
grep -q '^al\.3wire' $R/etc/gettytab || cat >> $R/etc/gettytab <<'EOF'

al.3wire|Autologin root 3wire:\
	:al=root:tc=3wire:
EOF
sed -i '' 's|^ttyu0[[:space:]]*"/usr/libexec/getty 3wire"|ttyu0	"/usr/libexec/getty al.3wire"|' $R/etc/ttys
sed -i '' 's|^root:\*:|root::|' $R/etc/master.passwd
# serviced requires the pkgbase 'capability' sandbox identity (uid/gid 976).
grep -q '^capability:' $R/etc/master.passwd || \
	echo 'capability:*:976:976::0:0:Capability service sandbox:/nonexistent:/usr/sbin/nologin' >> $R/etc/master.passwd
grep -q '^capability:' $R/etc/group || \
	echo 'capability:*:976:' >> $R/etc/group
# SSH_TEST=1: enable sshd + a wheel test user + DHCP so the guest is reachable
# under qemu user-mode networking (10.0.2.15) with a host ssh port-forward.
# For acceptance testing only; never for a shipping image.
if [ -n "$SSH_TEST" ]; then
	echo "==> SSH_TEST: enabling sshd, DHCP, root key auth"
	sed -i '' 's|^sshd_enable="NO"|sshd_enable="YES"|' $R/etc/rc.conf
	# qemu user-net hands out 10.0.2.15 via DHCP; override the bhyve static IP.
	sed -i '' 's|^ifconfig_vtnet0=.*|ifconfig_vtnet0="DHCP"|' $R/etc/rc.conf
	sed -i '' '/^defaultrouter=/d' $R/etc/rc.conf
	cat >> $R/etc/ssh/sshd_config <<'EOF'

# SSH_TEST acceptance config (insecure — test VM only)
PermitRootLogin yes
PubkeyAuthentication yes
UseDNS no
EOF
	# Key-based root auth for automated login (no sshpass on the host).
	# root's /root homedir is already present in the base METALOG; add .ssh.
	PUB="${SSH_TEST_PUBKEY:-/tmp/claude-1001/-usr-src/866fe930-7b5f-4b29-9ca6-2930ac5e74b3/scratchpad/acctest_key.pub}"
	if [ -f "$PUB" ]; then
		mkdir -p $R/root/.ssh
		cp "$PUB" $R/root/.ssh/authorized_keys
		chmod 700 $R/root/.ssh; chmod 600 $R/root/.ssh/authorized_keys
		cat >> $R/METALOG <<'MEOF'
./root/.ssh type=dir uname=root gname=wheel mode=0700
./root/.ssh/authorized_keys type=file uname=root gname=wheel mode=0600
MEOF
	fi
fi
# Regenerate pwd.db/spwd.db with the freshly-BUILT pwd_mkdb (run via the guest's
# own rtld + libs) so the db format matches the guest libc.  The host's installed
# pwd_mkdb can emit a db version the from-source guest libc cannot read.  Fall
# back to host pwd_mkdb when the guest one is not staged yet.
if [ -x "$R/usr/sbin/pwd_mkdb" ] && [ -x "$R/libexec/ld-elf.so.1" ]; then
	LD_LIBRARY_PATH="$R/lib:$R/usr/lib" "$R/libexec/ld-elf.so.1" \
		"$R/usr/sbin/pwd_mkdb" -d $R/etc -p $R/etc/master.passwd
else
	pwd_mkdb -d $R/etc -p $R/etc/master.passwd
fi
# Register the passwd/group databases in METALOG.  `make distribution` (a
# REQUIRED staging step -- see the guard before makefs below) ships master.passwd
# / passwd / group, but NOT the generated pwd.db / spwd.db.  Without a METALOG
# entry makefs omits a file, so the guest would boot with no pwd.db -- getpwnam()/
# getgrnam() then return NULL and switchboard cannot resolve its default service
# identity (capability:capability), failing bootstrap.  Listing master.passwd et
# al. here too is a harmless safety net (deduped to these entries below).
cat >> $R/METALOG <<'EOF'
./etc/master.passwd type=file uname=root gname=wheel mode=0600
./etc/spwd.db type=file uname=root gname=wheel mode=0600
./etc/passwd type=file uname=root gname=wheel mode=0644
./etc/pwd.db type=file uname=root gname=wheel mode=0644
./etc/group type=file uname=root gname=wheel mode=0644
EOF

echo "==> installing test helpers into guest /root"
cp $VM/tools/vsock-echo $VM/tools/vsock-client $R/root/ 2>/dev/null || true

echo "==> appending METALOG entries for added files"
cat >> $R/METALOG <<'EOF'
./boot/loader.conf type=file uname=root gname=wheel mode=0644
./etc/rc.conf type=file uname=root gname=wheel mode=0644
./etc/resolv.conf type=file uname=root gname=wheel mode=0644
./etc/fstab type=file uname=root gname=wheel mode=0644
./sbin/capsule type=file uname=root gname=wheel mode=0555
EOF

echo "==> map non-host owners to numeric (makefs runs on host w/o these users)"
# The 'capability' pkgbase user (uid/gid 976) does not exist on the build
# host, so makefs cannot resolve uname=/gname=capability.  Rewrite to numeric.
sed -i '' 's/uname=capability/uid=976/g; s/gname=capability/gid=976/g' $R/METALOG

# Fail LOUDLY if the /etc tree was never registered in METALOG.  `make
# distribution` (part of guest-root staging: `make -DNO_ROOT DESTDIR=$R
# installworld distribution installkernel`) installs /etc/rc, /etc/rc.d/*, and
# the passwd/group databases AND records them in METALOG.  installworld alone
# does NOT -- so if staging skipped distribution, makefs silently omits all of
# /etc: the guest boots with no /etc/rc, rc never runs, root is never remounted
# read-write, every runtime container fails EROFS, and switchboard deadlocks at
# "switchboard ready" with no login.  Catch that here as an instant, actionable
# error instead of a 5-minute boot hang.
if ! grep -qE '^\./etc/rc( |	|$)' $R/METALOG; then
	echo "FATAL: /etc/rc is not in $R/METALOG -- guest-root staging skipped" >&2
	echo "       'make distribution'.  Re-stage with:" >&2
	echo "         make -DNO_ROOT DESTDIR=$R installworld distribution installkernel" >&2
	exit 2
fi

echo "==> dedup METALOG (makefs rejects duplicate path definitions)"
cd $R
head -1 METALOG > METALOG.clean
tail -n +2 METALOG | tail -r | awk 'NF && !seen[$1]++' | sort -k1,1 >> METALOG.clean

if [ -n "$ZFS_ROOT" ]; then
	echo "==> makefs (ZFS root pool from METALOG manifest)"
	rm -f $VM/rootfs.zfs
	makefs -t zfs -s 16g \
	    -o poolname=zroot -o bootfs=zroot -o rootpath=/ \
	    $VM/rootfs.zfs METALOG.clean

	echo "==> mkimg (GPT: pmbr + gptzfsboot + zfs)"
	# A guest from the previous run may still hold bsd-guest.img open
	# read-write: writing the new image in place lets its ZFS syncs land in
	# the fresh image (boot blocks then fail "Can't find /boot/loader").
	# Stop it, and build into a temp file that is renamed over the old one so
	# any straggler keeps the OLD inode.
	pkill -9 -f qemu-system-x86_64 2>/dev/null || true; sleep 2
	mkimg -s gpt -f raw \
	    -b $R/boot/pmbr \
	    -p freebsd-boot:=$R/boot/gptzfsboot \
	    -p freebsd-zfs:=$VM/rootfs.zfs \
	    -p freebsd-swap::1g \
	    -o $VM/bsd-guest.img.tmp && mv -f $VM/bsd-guest.img.tmp $VM/bsd-guest.img
else
	echo "==> makefs (UFS rootfs from METALOG manifest)"
	makefs -t ffs -B little -s 16g \
	    -o softupdates=1,version=2,label=rootfs \
	    $VM/rootfs.ufs METALOG.clean

	echo "==> mkimg (GPT: pmbr + gptboot + rootfs)"
	pkill -9 -f qemu-system-x86_64 2>/dev/null || true; sleep 2
	mkimg -s gpt -f raw \
	    -b $R/boot/pmbr \
	    -p freebsd-boot:=$R/boot/gptboot \
	    -p freebsd-ufs:=$VM/rootfs.ufs \
	    -o $VM/bsd-guest.img.tmp && mv -f $VM/bsd-guest.img.tmp $VM/bsd-guest.img
fi

ls -lh $VM/bsd-guest.img
echo "IMAGE_OK"
