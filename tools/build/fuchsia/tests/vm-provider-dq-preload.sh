#!/bin/sh
# The dq suites' modules: with sys/dq, or a program under it, among the
# suites, vm-provider.sh preloads imgact_binmisc and dtraceall, which the
# plane would refuse to load late and without which those suites fail;
# other suites get nothing extra.  Runs the actual block of vm-provider.sh.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

sed -n '/^dq_loader=$/,/^esac$/p' "$root/vm-provider.sh" > "$work/dq.sh"
grep -q imgact_binmisc_load "$work/dq.sh"
loader() {
	env -i PATH="$PATH" suites="$1" sh -c ". '$work/dq.sh'; printf '%s\n' \"\$dq_loader\""
}
for s in "sys" "sys/dq" "sys/dq lib/libdq" "lib/libdq sys/dq" \
    "sys/dq/dq_resolve_test" "sys/dq/dq_resolve_test:attached_kernel_paths"; do
	loader "$s" | grep -qx 'imgact_binmisc_load="YES"' ||
	    { echo "FAIL: no imgact_binmisc for \"$s\""; exit 1; }
	loader "$s" | grep -qx 'dtraceall_load="YES"' ||
	    { echo "FAIL: no dtraceall for \"$s\""; exit 1; }
done
for s in "sys/mac_capability" "sys/mac_capability/authority_issuer_probe_test" \
    "sys/mac_capability/authority_test_issuer_anchor_test:anchor"; do
	[ "$(loader "$s")" = 'dtraceall_load="YES"' ] ||
	    { echo "FAIL: no dtraceall alone for \"$s\""; exit 1; }
done
for s in "sys/mac_capability/mac_capability_channel_test"; do
	[ "$(loader "$s")" = 'dtraceall_load="YES"' ] ||
	    { echo "FAIL: no dtraceall alone for \"$s\""; exit 1; }
done
for s in "sys/file" "lib/libdq" "sys/dq_regress" "usr.sbin/BSDTime" \
    "sys/mac_capability/mac_capability_test" "sys/vfs" \
    "sys/vfs/ufs_suspend_atime"; do
	[ -z "$(loader "$s")" ] ||
	    { echo "FAIL: dq modules for \"$s\""; exit 1; }
done
# Written to the image's loader.conf ahead of LOADER_EXTRA.
grep -q '^\[ -z "\$dq_loader" \] || printf .*"\$x/loader.conf"$' "$root/vm-provider.sh"
echo 'PASS the dq suites get imgact_binmisc and dtraceall, the issuer-decision probe programs and the channel test dtraceall, others nothing'
