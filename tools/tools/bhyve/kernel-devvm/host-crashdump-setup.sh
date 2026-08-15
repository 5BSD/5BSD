#!/bin/sh
# Configure unattended compressed kernel minidumps and automatic savecore.
# This script deliberately does not trigger a panic on the physical host.
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "host-crashdump-setup.sh must run as root" >&2
	exit 1
fi

if [ -n "${DUMPDEV:-}" ]; then
	dumpdev=$DUMPDEV
elif [ -c /dev/vtbd1 ]; then
	# kernel-devvm attaches a dedicated raw 20 GiB panic disk here.
	dumpdev=/dev/vtbd1
else
	dumpdev=/dev/nda0p3
fi
sysctl_local=/etc/sysctl.conf.local

[ -c "$dumpdev" ] || {
	echo "dump device is not a character device: $dumpdev" >&2
	exit 1
}

# Keep a minidump small enough for the existing dump partition and use the
# kernel's Zstandard dumper.  A dedicated RAM-sized raw device or netdump
# server is still preferable; README.md documents that capacity requirement.
sysrc dumpdev="$dumpdev"
sysrc dumpon_flags="-Z"
sysrc dumpdir="/var/crash"
sysrc savecore_enable="YES"
sysrc crashinfo_enable="YES"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
if [ -f "$sysctl_local" ]; then
	awk '
	    !/^[[:space:]]*debug\.minidump[[:space:]]*=/ &&
	    !/^[[:space:]]*debug\.debugger_on_panic[[:space:]]*=/ &&
	    !/^[[:space:]]*debug\.trace_on_panic[[:space:]]*=/ &&
	    !/^[[:space:]]*kern\.panic_reboot_wait_time[[:space:]]*=/' \
	    "$sysctl_local" > "$tmp"
fi
printf '%s\n' \
	'# Kernel-development crash recovery.' \
	'debug.minidump=1' \
	'debug.debugger_on_panic=0' \
	'debug.trace_on_panic=1' \
	'kern.panic_reboot_wait_time=15' >> "$tmp"
install -o root -g wheel -m 0644 "$tmp" "$sysctl_local"

sysctl debug.minidump=1
sysctl debug.debugger_on_panic=0
sysctl debug.trace_on_panic=1
sysctl kern.panic_reboot_wait_time=15

mkdir -p /var/crash
chown root:wheel /var/crash
chmod 0750 /var/crash
[ -f /var/crash/minfree ] || printf '1048576\n' > /var/crash/minfree
chown root:wheel /var/crash/minfree
chmod 0644 /var/crash/minfree

service dumpon restart

echo
echo "Configured dump devices:"
dumpon -l
echo "Dump configuration:"
sysrc -n dumpdev dumpon_flags dumpdir savecore_enable crashinfo_enable
echo "Panic behavior:"
sysctl debug.minidump debug.debugger_on_panic debug.trace_on_panic \
	kern.panic_reboot_wait_time
echo
echo "The current target is compressed minidump storage on $dumpdev."
echo "Do not deliberately panic this physical host. Test panic/savecore in the VM."
