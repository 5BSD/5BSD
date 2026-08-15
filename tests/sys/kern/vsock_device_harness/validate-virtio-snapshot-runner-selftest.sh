#!/bin/sh
#
# Prove that the compact rootless checkpoint runner rejects an ATF protocol
# result other than "passed".  Test a temporary source copy: this is a guard
# against a later simplification which retains a successful process exit but
# drops the ATF result-record check.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
runner=$here/run-snapshot-model.sh
validator=$here/validate-virtio-requirements.sh
src=${SRCTOP:-/usr/src}
work=$(mktemp -d "${TMPDIR:-/tmp}/virtio-snapshot-runner.XXXXXX")

cleanup()
{
	status=${1:-$?}
	trap - EXIT HUP INT TERM
	rm -rf -- "$work"
	exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

[ -r "$runner" ] && [ -x "$validator" ] || {
	echo "snapshot runner selftest: missing runner or validator" >&2
	exit 1
}

fixture=$work/run-snapshot-model.sh
discovery_fixture=$work/run-snapshot-model-no-discovery-check.sh
cleanup_fixture=$work/run-snapshot-model-no-case-cleanup.sh
signal_fixture=$work/run-snapshot-model-nonterminal-signal.sh
validator_fixture=$work/validate-virtio-requirements.sh
diagnostic=$work/guard.out
# Delete exactly the check that turns an ATF result record into a pass/fail
# decision.  No real test or device source is changed.
sed '/tail -n 1 "\$case_log" | grep -qx passed/d' "$runner" > "$fixture"
chmod 500 "$fixture"

# Keep the production validator's runner location fixed.  The self-test uses
# a private copy whose only change is its local runner path, rather than
# adding an environment override that a normal validation invocation could
# misuse.
sed -e "s|^script_dir=.*$|script_dir=\"$here\"|" \
    -e "s|^snapshot_model_runner=.*$|snapshot_model_runner=\"$fixture\"|" \
    "$validator" > "$validator_fixture"
chmod 500 "$validator_fixture"

if rg -q -F 'tail -n 1 "$case_log" | grep -qx passed' "$fixture"; then
	echo "snapshot runner selftest: fixture still validates ATF results" >&2
	exit 1
fi

if "$validator_fixture" "$here/virtio-1.4-requirements.tsv" "$here" "$src" \
    >"$diagnostic" 2>&1; then
	echo "snapshot runner selftest: missing ATF result check was accepted" >&2
	exit 1
fi
if ! grep -q 'snapshot model runner omits ATF result validation: tail -n 1 "\$case_log" | grep -qx passed' "$diagnostic"; then
	echo "snapshot runner selftest: validator failed for the wrong reason" >&2
	cat "$diagnostic" >&2
	exit 1
fi

echo "PASS snapshot runner selftest rejects a missing ATF result check"

# Case enumeration is a distinct protocol boundary.  Removing the direct
# producer-status check must be rejected instead of allowing awk's successful
# status to turn a crashed test program into an empty suite.
sed '/"\$program" -l >"\$case_log" 2>&1/d' "$runner" > "$discovery_fixture"
chmod 500 "$discovery_fixture"
chmod u+w "$validator_fixture"
sed -e "s|^script_dir=.*$|script_dir=\"$here\"|" \
    -e "s|^snapshot_model_runner=.*$|snapshot_model_runner=\"$discovery_fixture\"|" \
    "$validator" > "$validator_fixture"
chmod 500 "$validator_fixture"
if "$validator_fixture" "$here/virtio-1.4-requirements.tsv" "$here" "$src" \
    >"$diagnostic" 2>&1; then
	echo "snapshot runner selftest: missing discovery check was accepted" >&2
	exit 1
fi
grep -q \
    'snapshot model runner omits ATF result validation: "\$program" -l >"\$case_log" 2>&1' \
    "$diagnostic"
echo "PASS snapshot runner selftest rejects a missing ATF discovery check"

# The case transcript is created after build and must be removed on every
# exit.  A later case failure must not leak one temporary file per run.
sed '/rm -f "\$case_log" 2>\/dev\/null || :/d' "$runner" > "$cleanup_fixture"
chmod 500 "$cleanup_fixture"
chmod u+w "$validator_fixture"
sed -e "s|^script_dir=.*$|script_dir=\"$here\"|" \
    -e "s|^snapshot_model_runner=.*$|snapshot_model_runner=\"$cleanup_fixture\"|" \
    "$validator" > "$validator_fixture"
chmod 500 "$validator_fixture"
if "$validator_fixture" "$here/virtio-1.4-requirements.tsv" "$here" "$src" \
    >"$diagnostic" 2>&1; then
	echo "snapshot runner selftest: missing temporary-output cleanup was accepted" >&2
	exit 1
fi
grep -q \
    'snapshot model runner omits ATF result validation: rm -f "\$case_log" 2>/dev/null || :' \
    "$diagnostic"
echo "PASS snapshot runner selftest rejects a missing temporary-output cleanup"

# A cleanup-only signal trap resumes the test command after deleting its
# workspace.  Require a terminal, status-preserving INT/TERM contract.
sed "s|trap 'cleanup 130' INT|trap cleanup INT|" "$runner" > "$signal_fixture"
chmod 500 "$signal_fixture"
chmod u+w "$validator_fixture"
sed -e "s|^script_dir=.*$|script_dir=\"$here\"|" \
    -e "s|^snapshot_model_runner=.*$|snapshot_model_runner=\"$signal_fixture\"|" \
    "$validator" > "$validator_fixture"
chmod 500 "$validator_fixture"
if "$validator_fixture" "$here/virtio-1.4-requirements.tsv" "$here" "$src" \
    >"$diagnostic" 2>&1; then
	echo "snapshot runner selftest: nonterminal signal trap was accepted" >&2
	exit 1
fi
grep -q \
    "snapshot model runner omits ATF result validation: trap 'cleanup 130' INT" \
    "$diagnostic"
echo "PASS snapshot runner selftest rejects a nonterminal signal trap"

# RESULT_FILE is consumed by the asynchronous lab runner.  Deleting its
# nonterminal publication must therefore be rejected by the requirements
# validator; otherwise a detached caller has no safe indication that the
# snapshot lane is still alive.
result_fixture=$work/run-snapshot-model-no-result-start.sh
sed "/printf 'RUNNING virtio-snapshot-model pid=%s\\\\n'/d" "$runner" > \
    "$result_fixture"
chmod 500 "$result_fixture"
chmod u+w "$validator_fixture"
sed -e "s|^script_dir=.*$|script_dir=\"$here\"|" \
    -e "s|^snapshot_model_runner=.*$|snapshot_model_runner=\"$result_fixture\"|" \
    "$validator" > "$validator_fixture"
chmod 500 "$validator_fixture"
if "$validator_fixture" "$here/virtio-1.4-requirements.tsv" "$here" "$src" \
    >"$diagnostic" 2>&1; then
	echo "snapshot runner selftest: missing RESULT_FILE start was accepted" >&2
	exit 1
fi
grep -Fq 'snapshot model RESULT_FILE contract is missing: printf '\''RUNNING virtio-snapshot-model pid=%s\n'\'' "$$"' \
    "$diagnostic"
echo "PASS snapshot runner selftest rejects a missing RESULT_FILE start"
