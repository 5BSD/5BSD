#!/usr/local/bin/ksh93 -p
#
# SPDX-License-Identifier: CDDL-1.0
#
# Copyright (c) 2026 The FreeBSD Foundation

. $STF_SUITE/tests/cli_root/cli_common.kshlib

verify_runnable "global"

snap=$TESTPOOL/$TESTFS@capsicum
writable=$TMPDIR/zfs-send-capsicum-write.$$
incapable=$TMPDIR/zfs-send-capsicum-none.$$

function cleanup
{
	snapexists $snap && log_must $ZFS destroy -f $snap
	$RM -f $writable $incapable
}

log_assert "ZFS send honors Capsicum rights on its output descriptor."
log_onexit cleanup

log_must $ZFS snapshot $snap

log_must zfs_send_capsicum $snap $writable write
[[ -s $writable ]] || log_fail "CAP_WRITE send produced an empty stream"

log_must zfs_send_capsicum $snap $incapable none
[[ ! -s $incapable ]] || \
	log_fail "send wrote through an output descriptor without CAP_WRITE"

log_pass "ZFS send requires CAP_WRITE on its output descriptor."
