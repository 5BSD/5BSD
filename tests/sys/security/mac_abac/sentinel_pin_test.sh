#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 The 5BSD Project
#
# The label of a vnode on a single-label file system (ZFS, UFS mounted
# without multilabel) is read from its extended attribute on first use.
# The kld, acct and swapon hooks are given such a vnode without any earlier
# hook having read it: they must still match its own label, never the
# "not yet read" marker.  Each case labels a file, remounts so that its
# vnode is new, loads one deny rule naming that label, and checks that the
# operation on the labelled file is denied (EACCES) and on an unlabelled
# copy is not.  The rule names a label only these files carry.
#

PIN_LABEL="abacpin=sentinel"
STATE=abac_state

save_policy()
{
	mac_abac_ctl mode | awk '{print $NF}' > $STATE
	mac_abac_ctl default | awk '{print $NF}' >> $STATE
}

restore_policy()
{
	mac_abac_ctl rule clear > /dev/null 2>&1
	if [ -s $STATE ]; then
		mac_abac_ctl mode "$(sed -n 1p $STATE)" > /dev/null 2>&1
		mac_abac_ctl default "$(sed -n 2p $STATE)" > /dev/null 2>&1
	else
		mac_abac_ctl mode permissive > /dev/null 2>&1
		mac_abac_ctl default allow > /dev/null 2>&1
	fi
}

# fs_up ufs|zfs: a fresh file system on a swap-backed md(4) at ./mnt.
fs_up()
{
	local md

	md=$(mdconfig -a -t swap -s 128m) || atf_skip "mdconfig failed"
	echo $md > md_unit
	mkdir -p mnt
	case $1 in
	ufs)
		newfs -U /dev/$md > /dev/null || atf_fail "newfs failed"
		mount /dev/$md mnt || atf_fail "mount failed"
		mount -p | grep -q " $(pwd)/mnt .*multilabel" &&
		    atf_fail "mounted multilabel"
		echo ufs > fs_kind
		;;
	zfs)
		pool=abacpin$$
		zpool create -f -m $(pwd)/mnt $pool /dev/$md 2> zpool.err ||
		    atf_skip "zpool create: $(cat zpool.err)"
		echo $pool > pool_name
		echo zfs > fs_kind
		;;
	esac
}

# Unmount and mount again: every vnode on it is new afterwards.
fs_cycle()
{
	case $(cat fs_kind) in
	ufs)
		umount mnt || atf_fail "umount failed"
		mount /dev/$(cat md_unit) mnt || atf_fail "remount failed"
		;;
	zfs)
		zfs unmount $(cat pool_name) || atf_fail "zfs unmount failed"
		zfs mount $(cat pool_name) || atf_fail "zfs mount failed"
		;;
	esac
}

fs_down()
{
	if [ -f pool_name ]; then
		zpool destroy -f $(cat pool_name) > /dev/null 2>&1
	elif [ -f fs_kind ]; then
		umount -f mnt > /dev/null 2>&1
	fi
	[ -f md_unit ] && mdconfig -d -u $(cat md_unit) > /dev/null 2>&1
	return 0
}

# A module that exists and is not loaded.
pick_module()
{
	local m

	for m in if_disc if_edsc filemon cd9660 sysvmsg if_vxlan; do
		[ -f /boot/kernel/$m.ko ] || continue
		kldstat -q -n $m.ko && continue
		kldstat -q -m $m && continue
		echo $m
		return 0
	done
	return 1
}

pin_enforce()
{
	save_policy
	mac_abac_ctl rule clear > /dev/null || atf_fail "rule clear"
	mac_abac_ctl default allow > /dev/null || atf_fail "default allow"
	mac_abac_ctl rule add deny "$1" '*' -> "$PIN_LABEL" > /dev/null ||
	    atf_fail "rule add"
	mac_abac_ctl mode enforcing > /dev/null || atf_fail "mode enforcing"
}

kld_case()
{
	local m out

	m=$(pick_module) || atf_skip "no unloaded module to load"
	fs_up $1
	cp /boot/kernel/$m.ko mnt/labelled.ko
	cp /boot/kernel/$m.ko mnt/plain.ko
	atf_check -o ignore mac_abac_ctl label set mnt/labelled.ko "$PIN_LABEL"
	fs_cycle
	pin_enforce exec

	# The labelled file first: its vnode has not been looked at by any
	# hook that reads labels.
	atf_check -s not-exit:0 -o ignore -e match:"Permission denied" \
	    kldload $(pwd)/mnt/labelled.ko
	if kldload $(pwd)/mnt/plain.ko 2> plain.err; then
		kldunload $m
	else
		grep -q "Permission denied" plain.err &&
		    atf_fail "unlabelled module denied: $(cat plain.err)"
	fi
	restore_policy
}

acct_case()
{
	fs_up $1
	: > mnt/labelled.acct
	: > mnt/plain.acct
	atf_check -o ignore mac_abac_ctl label set mnt/labelled.acct \
	    "$PIN_LABEL"
	fs_cycle
	pin_enforce write

	atf_check -s not-exit:0 -o ignore -e match:"Permission denied" \
	    accton $(pwd)/mnt/labelled.acct
	if accton $(pwd)/mnt/plain.acct 2> plain.err; then
		accton
	else
		grep -q "Permission denied" plain.err &&
		    atf_fail "unlabelled file denied: $(cat plain.err)"
	fi
	restore_policy
}

atf_test_case kld_ufs cleanup
kld_ufs_head()
{
	atf_set "descr" "kldload of a labelled module on non-multilabel UFS is matched against its label"
	atf_set "require.user" "root"
}
kld_ufs_body()
{
	kld_case ufs
}
kld_ufs_cleanup()
{
	restore_policy
	fs_down
}

atf_test_case kld_zfs cleanup
kld_zfs_head()
{
	atf_set "descr" "kldload of a labelled module on ZFS is matched against its label"
	atf_set "require.user" "root"
}
kld_zfs_body()
{
	kld_case zfs
}
kld_zfs_cleanup()
{
	restore_policy
	fs_down
}

atf_test_case acct_ufs cleanup
acct_ufs_head()
{
	atf_set "descr" "acct(2) to a labelled file on non-multilabel UFS is matched against its label"
	atf_set "require.user" "root"
}
acct_ufs_body()
{
	acct_case ufs
}
acct_ufs_cleanup()
{
	restore_policy
	accton > /dev/null 2>&1
	fs_down
}

atf_test_case acct_zfs cleanup
acct_zfs_head()
{
	atf_set "descr" "acct(2) to a labelled file on ZFS is matched against its label"
	atf_set "require.user" "root"
}
acct_zfs_body()
{
	acct_case zfs
}
acct_zfs_cleanup()
{
	restore_policy
	accton > /dev/null 2>&1
	fs_down
}

# swapon(2) takes a disk or an NFS file; a disk is a devfs vnode, whose
# label is never read lazily.  Pin that the hook on that path neither
# faults nor denies with a write rule loaded.  (The NFS file path, where
# a lazily read label does reach the hook first, needs an NFS server.)
atf_test_case swapon_disk cleanup
swapon_disk_head()
{
	atf_set "descr" "swapon and swapoff of an md(4) disk with a write rule loaded"
	atf_set "require.user" "root"
}
swapon_disk_body()
{
	local md

	md=$(mdconfig -a -t malloc -s 32m) || atf_skip "mdconfig failed"
	echo $md > md_unit
	pin_enforce write
	if swapon /dev/$md 2> swapon.err; then
		atf_check -o ignore -e ignore swapoff /dev/$md
	else
		grep -q "Permission denied" swapon.err &&
		    atf_fail "swapon denied: $(cat swapon.err)"
	fi
	restore_policy
}
swapon_disk_cleanup()
{
	restore_policy
	[ -f md_unit ] && swapoff /dev/$(cat md_unit) > /dev/null 2>&1
	fs_down
}

atf_init_test_cases()
{
	atf_add_test_case kld_ufs
	atf_add_test_case kld_zfs
	atf_add_test_case acct_ufs
	atf_add_test_case acct_zfs
	atf_add_test_case swapon_disk
}
