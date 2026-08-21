#!/bin/sh
# Exercise stress-runner discovery, concurrency, result parsing, and failure.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
runner=$here/run-vmm-kvm-parity-stress.sh
work=$(mktemp -d /tmp/vmm-parity-stress-selftest.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM

fake=$work/fake-atf
cp /dev/null "$fake"
chmod 0700 "$fake"
sed 's/^+//' >"$fake" <<'EOF'
+#!/bin/sh
+case "${1:-}" in
+-l)
+	printf 'Content-Type: application/X-atf-tp; version="1"\n\n'
+	printf 'ident: alpha\n\nident: beta\n'
+	;;
+-r)
+	case_name=${3:-}
+	if [ "${FAKE_FAIL_CASE:-}" = "$case_name" ]; then
+		echo failed: injected
+	else
+		echo passed
+	fi
+	;;
+*) exit 2 ;;
+esac
EOF

success=$work/success
mkdir -m 0700 "$success"
REQUIRE_ROOT=no PROGRAM="$fake" ITERATIONS=3 JOBS=2 WORKDIR="$success" \
    KEEP_WORK=yes sh "$runner" >"$work/success.out" 2>&1
grep -Fq 'cases=6' "$work/success.out" || {
	echo "stress runner did not execute every fake case" >&2
	exit 1
}
[ "$(find "$success" -name result -type f | wc -l | tr -d ' ')" -eq 6 ] || {
	echo "stress runner did not isolate every fake case" >&2
	exit 1
}

failure=$work/failure
mkdir -m 0700 "$failure"
if REQUIRE_ROOT=no PROGRAM="$fake" FAKE_FAIL_CASE=beta ITERATIONS=1 JOBS=2 \
    WORKDIR="$failure" KEEP_WORK=yes sh "$runner" \
    >"$work/failure.out" 2>&1; then
	echo "stress runner accepted an injected ATF failure" >&2
	exit 1
fi
grep -Fq 'case=beta' "$work/failure.out" || {
	echo "stress runner did not identify the failed case" >&2
	exit 1
}

if REQUIRE_ROOT=no PROGRAM="$fake" ITERATIONS=1 JOBS=invalid \
    sh "$runner" >"$work/config.out" 2>&1; then
	echo "stress runner accepted an invalid job count" >&2
	exit 1
fi
grep -Fq 'JOBS must be a positive integer' "$work/config.out" || {
	echo "stress runner did not diagnose invalid configuration" >&2
	exit 1
}

echo "PASS VMM KVM-parity stress self-test"
