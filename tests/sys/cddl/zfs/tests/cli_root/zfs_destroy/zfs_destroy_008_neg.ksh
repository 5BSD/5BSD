#!/usr/local/bin/ksh93 -p
#
# SPDX-License-Identifier: CDDL-1.0
#
# Copyright (c) 2026 Kory Heard

. $STF_SUITE/tests/cli_root/cli_common.kshlib

verify_runnable "global"

dataset=$TESTPOOL/$TESTFS
legacy=$dataset@mac-legacy
batch=$dataset@mac-batch
missing=$dataset@mac-missing
helper=$(whence zfs_destroy_snaps) || log_fail "cannot find zfs_destroy_snaps"
zfs_deny=security.mac.test_hooks.deny.zfs_check_dataset_destroy
zfs_count=security.mac.test_hooks.counter.zfs_check_dataset_destroy
snap_deny=security.mac.test_hooks.deny.mount_check_snapshot_delete
snap_count=security.mac.test_hooks.counter.mount_check_snapshot_delete

function set_deny
{
	log_must sysctl $1=$2
}

function hook_count
{
	typeset value

	value=$(sysctl -n $1) || log_fail "cannot read $1"
	print -- $value
}

function cleanup
{
	sysctl $zfs_deny=0 >/dev/null 2>&1
	sysctl $snap_deny=0 >/dev/null 2>&1
	snapexists $legacy && $ZFS destroy -f $legacy
	snapexists $batch && $ZFS destroy -f $batch
}

log_assert "ZFS snapshot destruction honors MAC hooks on every ioctl path."
log_onexit cleanup

set_deny $zfs_deny 0
set_deny $snap_deny 0
log_must $ZFS allow nobody destroy,mount $dataset
log_must $ZFS snapshot $legacy

typeset before=$(hook_count $zfs_count)
set_deny $zfs_deny 1
log_mustnot su -m nobody -c "$helper legacy $legacy"
snapexists $legacy || log_fail "dataset-destroy denial removed $legacy"
typeset after=$(hook_count $zfs_count)
((after == before + 1)) || \
	log_fail "dataset-destroy hook count changed $before -> $after"

set_deny $zfs_deny 0
before=$(hook_count $snap_count)
set_deny $snap_deny 1
log_mustnot su -m nobody -c "$helper legacy $legacy"
snapexists $legacy || log_fail "snapshot-delete denial removed $legacy"
after=$(hook_count $snap_count)
((after == before + 1)) || \
	log_fail "snapshot-delete hook count changed $before -> $after"

set_deny $snap_deny 0
log_must su -m nobody -c "$helper legacy $legacy"
snapexists $legacy && log_fail "allowed legacy destroy retained $legacy"

log_must $ZFS snapshot $batch
typeset zfs_before=$(hook_count $zfs_count)
typeset snap_before=$(hook_count $snap_count)
log_must su -m nobody -c "$helper batch $missing $batch"
snapexists $batch && log_fail "batch destroy retained $batch"
typeset zfs_after=$(hook_count $zfs_count)
typeset snap_after=$(hook_count $snap_count)
((zfs_after == zfs_before + 1)) || \
	log_fail "missing snapshot reached dataset hook: $zfs_before -> $zfs_after"
((snap_after == snap_before + 1)) || \
	log_fail "missing snapshot reached snapshot hook: $snap_before -> $snap_after"

log_pass "MAC denials are effective and nonexistent snapshots remain unchecked."
