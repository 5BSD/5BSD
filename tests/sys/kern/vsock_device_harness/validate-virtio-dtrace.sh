#!/bin/sh
#
# Validate the bhyve VirtIO USDT provider without requiring a bhyve link.
# This catches provider syntax errors and wrapper/provider name drift in the
# rootless sanitizer gate, rather than deferring both to buildworld.
set -eu

# TEST-ANCHOR: probe-wrappers

srctop=${SRCTOP:-/usr/src}
provider="$srctop/usr.sbin/bhyve/vsock_provider.d"
headers="
$srctop/usr.sbin/bhyve/pci_virtio_vsock_probes.h
$srctop/usr.sbin/bhyve/virtio_pci_modern_probes.h
"

if ! command -v dtrace >/dev/null 2>&1; then
	echo "virtio dtrace: dtrace unavailable; validation skipped"
	exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
dtrace -h -s "$provider" -o "$work/vsock_provider.h"

for header in $headers; do
	awk '
		match($0, /DTRACE_PROBE[0-9]*\((vsock|virtio),[[:space:]]*/) {
			provider = substr($0, RSTART, RLENGTH)
			sub(/^.*\(/, "", provider)
			sub(/,.*/, "", provider)
			rest = substr($0, RSTART + RLENGTH)
			if (match(rest, /^[A-Za-z0-9_]+/))
				print provider, substr(rest, RSTART, RLENGTH)
		}
	' "$header"
done | sort -u >"$work/wrappers"

while read -r provider_name probe_name; do
	symbol="__dtrace_${provider_name}___${probe_name}"
	if ! grep -Fq "$symbol" "$work/vsock_provider.h"; then
		echo "virtio dtrace: wrapper lacks provider declaration: $provider_name:$probe_name" >&2
		exit 1
	fi
done <"$work/wrappers"

wrapper_count=$(wc -l <"$work/wrappers" | tr -d ' ')
test "$wrapper_count" -gt 0
echo "virtio dtrace: $wrapper_count probe wrappers validated"
