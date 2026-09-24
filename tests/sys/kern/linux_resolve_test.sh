# SPDX-License-Identifier: BSD-2-Clause
atf_test_case resolve cleanup
resolve_head()
{
	atf_set descr "Linux openat2 all-component symlink and magic-link restrictions"
	atf_set require.arch "amd64 arm64 aarch64"
	atf_set require.progs "clang ld.lld brandelf timeout zfs df awk"
	atf_set require.user root
	atf_set timeout 360
}
resolve_body()
{
	# The VM gate supplies these mounts and treats missing setup as a failure.
	# ATF must not replace a running host's proc or descriptor filesystem.
	[ -L /proc/self/exe ] || atf_skip "requires linprocfs mounted at /proc"
	mount -p | awk '$2 == "/dev/fd" && $3 == "fdescfs" && $4 ~ /linrdlnk/ {ok=1} END {exit !ok}' ||
	    atf_skip "requires fdescfs with linrdlnk at /dev/fd"
	case "$(uname -m)" in
	amd64) target=x86_64-linux-gnu ;;
	arm64) target=aarch64-linux-gnu ;;
	*) atf_fail "unsupported architecture" ;;
	esac
	kldstat -q -n linux64.ko || atf_check -s exit:0 kldload linux64
	atf_check -s exit:0 clang --target="$target" -fuse-ld=lld -nostdlib -static \
	    -fno-stack-protector -fno-builtin -O2 -Wall -Wextra -Werror \
	    -o resolve "$(atf_get_srcdir)/linux_resolve.c"
	atf_check -s exit:0 brandelf -t Linux resolve
	atf_check -s exit:0 -o save:cases.txt ./resolve -l
	[ "$(wc -l <cases.txt | tr -d ' ')" -eq 24 ] || atf_fail "missing cases"
	# Alternate mount coverage has fixed disposable-guest paths.
	for name in procfs fd-plain fd-rdlnk fd-nodup; do
		mkdir "/tmp/resolve-$name" || atf_fail "path already exists: /tmp/resolve-$name"
		echo "$name" >>created-dirs.txt
	done
	atf_check -s exit:0 mount -t procfs procfs /tmp/resolve-procfs
	atf_check -s exit:0 mount -t fdescfs fdescfs /tmp/resolve-fd-plain
	atf_check -s exit:0 mount -t fdescfs -o rdlnk fdescfs /tmp/resolve-fd-rdlnk
	atf_check -s exit:0 mount -t fdescfs -o nodup fdescfs /tmp/resolve-fd-nodup
	mkdir /tmp/xdev-base || atf_fail "path already exists: /tmp/xdev-base"
	touch created-xdev.txt
	mkdir /tmp/xdev-base/mnt /tmp/xdev-base/source /tmp/xdev-base/bind
	atf_check -s exit:0 mount -t tmpfs tmpfs /tmp/xdev-base/mnt
	mkdir /tmp/xdev-base/mnt/sub /tmp/xdev-base/mnt/nested
	atf_check -s exit:0 mount -t tmpfs tmpfs /tmp/xdev-base/mnt/nested
	printf safe >/tmp/xdev-base/file
	printf safe >/tmp/xdev-base/source/file
	printf safe >/tmp/xdev-base/mnt/file
	printf safe >/tmp/xdev-base/mnt/nested/file
	ln -s / /tmp/xdev-base/mnt/abs
	ln -s .. /tmp/xdev-base/mnt/up
	atf_check -s exit:0 mount -t nullfs /tmp/xdev-base/source /tmp/xdev-base/bind
	for name in autofs union; do
		mkdir "/tmp/xdev-$name" || atf_fail "path already exists: /tmp/xdev-$name"
		echo "$name" >>created-special.txt
	done
	atf_check -s exit:0 mount -t autofs -o master_options=,master_prefix=/tmp/xdev-autofs autofs /tmp/xdev-autofs
	printf lower >/tmp/xdev-union/lower
	atf_check -s exit:0 mount -t tmpfs -o union tmpfs /tmp/xdev-union
	printf upper >/tmp/xdev-union/upper
	# This suite must run inside the disposable ZFS-root VM.
	root_dataset=$(df -T / | awk 'NR == 2 && $2 == "zfs" {print $1}')
	[ -n "$root_dataset" ] || atf_fail "requires ZFS root"
	pool=${root_dataset%%/*}
	dataset="$pool/linuxulator-resolve-$$"
	mkdir /tmp/resolve-zfs || atf_fail "fixture already exists"
	atf_check -s exit:0 zfs create -o mountpoint=/tmp/resolve-zfs/child "$dataset"
	echo "$dataset" >created-zfs.txt
	printf safe >/tmp/resolve-zfs/child/file
	atf_check -s exit:0 zfs snapshot "$dataset@gate"
	atf_check -s exit:0 zfs clone -o mountpoint=/tmp/resolve-zfs/clone "$dataset@gate" "$dataset-clone"
	atf_check -s exit:0 zfs clone -o readonly=on -o mountpoint=/tmp/resolve-zfs/readonly "$dataset@gate" "$dataset-readonly"
	while read -r name; do
		mkdir "$name" || atf_fail "mkdir $name"
		(cd "$name" && timeout 30 ../resolve "$name") >stdout.txt 2>stderr.txt
		rc=$?
		cat stdout.txt stderr.txt
		[ "$rc" -eq 0 ] || atf_fail "$name: exit $rc"
	done <cases.txt
}
resolve_cleanup()
{
	if [ -f created-zfs.txt ]; then
		read -r dataset <created-zfs.txt
		zfs destroy "$dataset-readonly" 2>/dev/null || true
		zfs destroy "$dataset-clone" 2>/dev/null || true
		zfs destroy "$dataset@gate" 2>/dev/null || true
		zfs destroy "$dataset" 2>/dev/null || true
		rmdir /tmp/resolve-zfs/child /tmp/resolve-zfs/clone /tmp/resolve-zfs/readonly /tmp/resolve-zfs 2>/dev/null || true
	fi
	# A failed mount-race child can leave its private tmpfs mounted.
	umount "$(pwd)/xdev_mount_race/cross" 2>/dev/null || true
	if [ -f created-xdev.txt ]; then
		umount /tmp/xdev-base/bind 2>/dev/null || true
		umount /tmp/xdev-base/mnt/nested 2>/dev/null || true
		umount /tmp/xdev-base/mnt 2>/dev/null || true
		rm -f /tmp/xdev-base/file /tmp/xdev-base/source/file
		rmdir /tmp/xdev-base/bind /tmp/xdev-base/mnt /tmp/xdev-base/source /tmp/xdev-base 2>/dev/null || true
	fi
	if [ -f created-special.txt ]; then
		while read -r name; do
			umount "/tmp/xdev-$name" 2>/dev/null || continue
			[ "$name" != union ] || rm -f /tmp/xdev-union/lower
			rmdir "/tmp/xdev-$name" 2>/dev/null || true
		done <created-special.txt
	fi
	[ -f created-dirs.txt ] || return 0
	while read -r name; do
		umount "/tmp/resolve-$name" 2>/dev/null || true
		rmdir "/tmp/resolve-$name" 2>/dev/null || true
	done <created-dirs.txt
}
atf_init_test_cases()
{
	atf_add_test_case resolve
}
