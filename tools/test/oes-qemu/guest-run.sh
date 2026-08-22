#!/bin/sh

set -u

media=${1:-/mnt}
results=${OES_RESULTS:-/tmp/oes-test-results.txt}

if [ ! -f "$media/oes.ko" ]; then
	mkdir -p "$media"
	mount -t cd9660 /dev/cd0 "$media" || exit 1
fi

echo "== guest =="
uname -a

if [ -f "$media/kernel" ] && ! cmp -s "$media/kernel" \
    /boot/kernel/kernel; then
	echo "== install matching test kernel and reboot =="
	install -m 555 "$media/kernel" /boot/kernel/kernel
	if [ -f "$media/zfs.ko" ]; then
		install -m 555 "$media/zfs.ko" /boot/kernel/zfs.ko
	fi
	shutdown -r now
	exit 0
fi

echo "== install current OES userspace ABI =="
mkdir -p /usr/include/security/oes
cp "$media/include/security/oes/oes.h" \
	"$media/include/security/oes/oes_event_table.h" \
	/usr/include/security/oes/
cp "$media/lib/liboes.so.1" /usr/lib/liboes.so.1
cp "$media/bin/oeslogger" /usr/sbin/oeslogger

echo "== load current OES kernel module =="
if ! kldstat -q -m oes; then
	kldload "$media/oes.ko" || exit 1
fi
kldstat -v | grep -i oes || true
ls -l /dev/oes || exit 1

echo "== ESLogger CLI smoke test =="
/usr/sbin/oeslogger -l || exit 1

echo "== OES Kyua suite =="
cd "$media/tests" || exit 1
kyua test -k Kyuafile
test_status=$?
kyua report | tee "$results"
report_status=$?

if [ "$test_status" -ne 0 ] || [ "$report_status" -ne 0 ]; then
	kyua report --verbose
	exit 1
fi

echo "== unread SCM_RIGHTS vnode-close regressions =="
for socket_type in stream dgram; do
	work=$(mktemp -d "/tmp/unix-passfd-${socket_type}.XXXXXX") || exit 1
	if ! (cd "$work" && \
	    "$media/kern-tests/unix_passfd_${socket_type}" devfs_orphan); then
		echo "unix_passfd_${socket_type}:devfs_orphan failed" >&2
		exit 1
	fi
done
exit 0
