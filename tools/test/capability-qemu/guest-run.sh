#!/bin/sh
# Execute every staged ATF case with an isolated work directory.

set -u

payload=${1:-/mnt}
result_dir=/tmp/capability-atf
passed=0
failed=0
skipped=0

mkdir -p "$result_dir"
export LD_LIBRARY_PATH=/lib:/usr/lib

mkdir -p /usr/src/usr.sbin/tzfsd /usr/src/usr.sbin/tzfs-flavors
cp "$payload/source/usr.sbin/tzfsd/"* /usr/src/usr.sbin/tzfsd/
cp "$payload/source/usr.sbin/tzfs-flavors/"* \
    /usr/src/usr.sbin/tzfs-flavors/

run_program()
{
	program=$1
	name=${program##*/}
	for test_case in $("$program" -l |
	    awk '/^ident: / { print $2 }'); do
		result="$result_dir/$name.$test_case.result"
		work="$result_dir/$name.$test_case.work"
		mkdir -p "$work"
		printf '%s:%s ... ' "$name" "$test_case"
		if output=$(cd "$work" && "$program" -r "$result" \
		    "$test_case" 2>&1); then
			if grep -q 'skipped' "$result" 2>/dev/null; then
				echo "SKIP $output"
				skipped=$((skipped + 1))
			else
				echo PASS
				passed=$((passed + 1))
			fi
		else
			echo FAIL
			echo "$output"
			test ! -f "$result" || cat "$result"
			failed=$((failed + 1))
		fi
		cleanup="$result_dir/$name.$test_case.cleanup"
		if ! (cd "$work" && "$program" -r "$cleanup" \
		    "$test_case:cleanup" >/dev/null 2>&1); then
			echo "$name:$test_case:cleanup ... FAIL"
			test ! -f "$cleanup" || cat "$cleanup"
			failed=$((failed + 1))
		fi
	done
}

if ! kldstat -q -m cryptodev; then
	kldload cryptodev || exit 1
fi

echo "Kernel: $(uname -K) $(uname -m)"
sysctl kern.crypto.cryptokey_objects >/dev/null || exit 1
# Kyua normally applies this test-suite configuration requirement.  This
# standalone runner must do so explicitly or software-provider cases skip.
sysctl kern.crypto.allow_soft=1 >/dev/null || exit 1

for program in "$payload"/tests/*; do
	[ -x "$program" ] || continue
	run_program "$program"
done

echo "Capability VM summary: $passed passed, $failed failed, $skipped skipped"
test "$failed" -eq 0
