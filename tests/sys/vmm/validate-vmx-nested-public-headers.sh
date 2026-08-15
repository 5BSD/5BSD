#!/bin/sh
#
# Verify that each public nested-VMX header which exposes bool can be included
# directly by a standalone model consumer.  Kernel builds have broad ambient
# include coverage; this deliberately does not rely on it.

set -eu

src=${SRCTOP:-/usr/src}
cc=${CC:-cc}
headers=$src/sys/amd64/vmm/intel
tmp=$(mktemp -d "${TMPDIR:-/tmp}/vmx-nested-headers.XXXXXX")

cleanup()
{
	rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM

for header in "$headers"/vmx_nested_*.h; do
	[ -r "$header" ] || continue
	if [ "$(basename "$header")" = vmx_nested_types.h ]; then
		continue
	fi
	if grep -Eq '(^|[^[:alnum:]_])bool([^[:alnum:]_]|$)' "$header" &&
	    ! grep -Fq 'vmx_nested_types.h' "$header"; then
		echo "nested public header omits vmx_nested_types.h: $header" >&2
		exit 1
	fi
	name=$(basename "$header")
	printf '#include "%s"\nint main(void) { return 0; }\n' "$name" |
	    $cc -I "$headers" -I "$src/sys" -x c -fsyntax-only - \
	    >"$tmp/$name.out" 2>&1 || {
		sed -n '1,240p' "$tmp/$name.out" >&2
		echo "nested public header does not compile standalone: $name" >&2
		exit 1
	}
done

echo "nested public headers: standalone compile pass"
