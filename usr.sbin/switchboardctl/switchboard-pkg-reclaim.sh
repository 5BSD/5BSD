#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Hooks participate in the operation established by lifecycle run.
operation=${1:-}
case "$operation" in
prepare|retire|begin-install|install) shift ;;
*) echo "usage: switchboard-pkg-reclaim prepare|retire|begin-install|install source label ..." >&2; exit 64 ;;
esac
[ "$#" -ge 2 ] || exit 64
# An upgrade preserves this package slot's ownership reference. Its install
# hooks stage and commit the updated contents without retiring the owner.
if [ -n "${PKG_UPGRADE:-}" ]; then
    case "$operation" in prepare|retire) exit 0 ;; esac
fi
transaction=${SWITCHBOARD_LIFECYCLE_OPERATION:-}
if [ "${#transaction}" -ne 32 ]; then
    echo "package lifecycle requires switchboardctl lifecycle run ROOT pkg ..." >&2
    exit 75
fi
case "$transaction" in *[!0-9a-f]*|00000000000000000000000000000000) exit 64 ;; esac
root=${PKG_ROOTDIR:-/}
[ "${PKG_CHROOTED:-false}" = true ] && root=/
case "$operation" in
begin-install)
    [ -z "${PKG_UPGRADE:-}" ] || operation=begin-adopt
    ;;
install) operation=finish-install ;;
esac
ctl=/usr/sbin/switchboardctl
if [ "${SWITCHBOARD_PKG_RECLAIM_TESTING:-}" = yes ]; then
    ctl=${SWITCHBOARD_PKG_RECLAIM_CTL:?missing test control path}
    /bin/sh "$ctl" lifecycle "$operation" "$root" "$transaction" "$@"
else
    "$ctl" lifecycle "$operation" "$root" "$transaction" "$@"
fi
