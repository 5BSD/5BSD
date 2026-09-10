#!/bin/sh
#
# Reclaim provider-owned state after pkg removes a capability bundle.
#

# An alternate root has no live processes whose resources belong to it.  Never
# let pkg -r/-c accidentally ask the host SwitchBoard to retire a host label.
case "${PKG_ROOTDIR:-/}" in
/)	;;
*)	exit 0 ;;
esac
[ "${PKG_CHROOTED:-false}" = "true" ] && exit 0

# pkg does not normally run post-deinstall during an upgrade.  Keep this guard
# as defense in depth so a future pkg sequencing change cannot erase state.
[ -n "${PKG_UPGRADE:-}" ] && exit 0

if [ "$#" -eq 0 ]; then
	echo "usage: switchboard-pkg-reclaim bundle-label ..." >&2
	exit 64
fi
for label in "$@"; do
	case "$label" in
	""|*[!A-Za-z0-9._/-]*|/*|*//*|*/../*|../*|*/..)
		echo "switchboard-pkg-reclaim: invalid label: $label" >&2
		exit 64
		;;
	esac
	if [ "${#label}" -ge 64 ]; then
		echo "switchboard-pkg-reclaim: label too long: $label" >&2
		exit 64
	fi
done

ctl=/usr/sbin/switchboardctl
testing=false
if [ "${SWITCHBOARD_PKG_RECLAIM_TESTING:-}" = "yes" ]; then
	ctl="${SWITCHBOARD_PKG_RECLAIM_CTL:?missing test control path}"
	testing=true
fi

# A partial broadcast followed by a retry is safe because every provider's
# reclaim operation is required to be idempotent.  Retry the entire label set
# so a transient SwitchBoard restart cannot silently orphan package state.
attempt=1
while [ "$attempt" -le 3 ]; do
	failed=0
	for label in "$@"; do
		if "$testing"; then
			/bin/sh "$ctl" reclaim "$label" || failed=1
		else
			"$ctl" reclaim "$label" || failed=1
		fi
	done
	[ "$failed" -eq 0 ] && exit 0
	[ "$attempt" -eq 3 ] && break
	"$testing" || sleep 1
	attempt=$((attempt + 1))
done

echo "switchboard-pkg-reclaim: cleanup failed after 3 attempts;" \
    "run switchboardctl reclaim for: $*" >&2
exit 1
