#!/bin/sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
LUA=${LUA:-/usr/libexec/flua}
lab="$here/virtio-lab.lua"
manifest="$here/virtio-lab.yaml"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

"$LUA" "$lab" host-status --bridge vltest0 >"$work/host-status"
grep -q '^bridge=vltest0$' "$work/host-status"
grep -q '^exists=no$' "$work/host-status"
grep -q '^managed=no$' "$work/host-status"

if "$LUA" "$lab" host-prepare --bridge vltest0 \
    >"$work/host-prepare-missing.out" 2>&1; then
	echo "host-prepare without an uplink unexpectedly passed" >&2
	exit 1
fi
grep -q 'host-prepare requires --uplink' "$work/host-prepare-missing.out"

if "$LUA" "$lab" host-status --bridge '../bad' \
    >"$work/host-invalid.out" 2>&1; then
	echo "invalid bridge name unexpectedly passed" >&2
	exit 1
fi
grep -q 'bridge must be a valid interface name' "$work/host-invalid.out"

if "$LUA" "$lab" run --manifest "$manifest" --profile vmfree \
    --prepare-host --workdir "$work/prepare-missing" \
    >"$work/prepare-missing.out" 2>&1; then
	echo "run --prepare-host without an uplink unexpectedly passed" >&2
	exit 1
fi
grep -q -- '--prepare-host requires --uplink' "$work/prepare-missing.out"

if "$LUA" "$lab" plan --manifest "$manifest" --prepare-host \
    >"$work/prepare-command.out" 2>&1; then
	echo "plan --prepare-host unexpectedly passed" >&2
	exit 1
fi
grep -q -- '--prepare-host is valid only with run' "$work/prepare-command.out"

"$LUA" "$lab" plan --manifest "$manifest" --profile smoke >"$work/smoke"
[ "$(grep -c '^vmfree-device	' "$work/smoke")" -eq 1 ]
grep -q '^cases=8$' "$work/smoke"

"$LUA" "$lab" coverage --manifest "$manifest" --profile release \
    >"$work/release"
[ "$(grep -c '^COVERED	' "$work/release")" -eq 11 ]
! grep -q '^MISSING	' "$work/release"

"$LUA" "$lab" plan --manifest "$manifest" --profile release \
    --fivebsd-image /tmp/disposable-5bsd.img >"$work/release-plan"
grep -q '^fivebsd-virtio	fivebsd-auto	' "$work/release-plan"

if "$LUA" "$lab" run --manifest "$manifest" --profile release \
    --iso "$work/missing-alpine.iso" \
    --fivebsd-image "$work/missing-5bsd.img" \
    --workdir "$work/missing-input-run" \
    >"$work/missing-input.out" 2>&1; then
	echo "run accepted missing VM input files" >&2
	exit 1
fi
grep -q -- '--iso must name a readable regular file:' \
    "$work/missing-input.out"

cat >"$work/incomplete.yaml" <<'EOF'
---
version: 1
defaults: { timeout: 10, env: { DEVICES: net, NET_QUEUES: "1" } }
coverage:
  - id: queue-boundary
    profiles: [release]
    variable: NET_QUEUES
    values: ["1", "8"]
cases:
  - id: one
    executor: host-selftest
    profiles: [release]
EOF
if "$LUA" "$lab" coverage --manifest "$work/incomplete.yaml" \
    --profile release >"$work/incomplete.out" 2>&1; then
	echo "incomplete coverage unexpectedly passed" >&2
	exit 1
fi
grep -q '^MISSING	queue-boundary	8$' "$work/incomplete.out"

cat >"$work/duplicate.yaml" <<'EOF'
---
version: 1
cases:
  - { id: duplicate, executor: host-selftest, profiles: [smoke] }
  - { id: duplicate, executor: host-selftest, profiles: [smoke] }
EOF
if "$LUA" "$lab" plan --manifest "$work/duplicate.yaml" \
    --profile smoke >"$work/duplicate.out" 2>&1; then
	echo "duplicate case unexpectedly passed" >&2
	exit 1
fi
grep -q 'duplicate case id: duplicate' "$work/duplicate.out"

cat >"$work/invalid-env.yaml" <<'EOF'
---
version: 1
cases:
  - id: invalid
    executor: host-selftest
    profiles: [smoke]
    env: { "BAD-NAME": value }
EOF
if "$LUA" "$lab" plan --manifest "$work/invalid-env.yaml" \
    --profile smoke >"$work/invalid-env.out" 2>&1; then
	echo "invalid environment name unexpectedly passed" >&2
	exit 1
fi
grep -q 'invalid environment name' "$work/invalid-env.out"

cat >"$work/invalid-default-env.yaml" <<'EOF'
---
version: 1
defaults: { env: { "BAD-NAME": value } }
cases:
  - id: invalid-default
    executor: host-selftest
    profiles: [smoke]
EOF
if "$LUA" "$lab" plan --manifest "$work/invalid-default-env.yaml" \
    --profile smoke >"$work/invalid-default-env.out" 2>&1; then
	echo "invalid default environment unexpectedly passed" >&2
	exit 1
fi
grep -q 'invalid environment name in defaults.env' \
    "$work/invalid-default-env.out"

mkdir "$work/status"
printf 'passed=2\nfailed=0\ntotal=2\n' >"$work/status/summary"
printf 'time\tevent\tcase\tstatus\tlog\n' >"$work/status/events.tsv"
"$LUA" "$lab" status --workdir "$work/status" >"$work/status.out"
grep -q '^passed=2$' "$work/status.out"
grep -q '^time	event	case	status	log$' "$work/status.out"
mkdir "$work/not-a-run"
if "$LUA" "$lab" status --workdir "$work/not-a-run" \
    >"$work/not-a-run.out" 2>&1; then
	echo "status accepted a directory without virtio-lab state" >&2
	exit 1
fi
grep -q 'inaccessible or is not a virtio-lab run' "$work/not-a-run.out"

cat >"$work/scheduler.yaml" <<'EOF'
---
version: 1
defaults: { timeout: 10 }
cases:
  - id: pass-one
    executor: orchestrator-probe
    profiles: [scheduler]
    resources: [serial-a]
    env: { LAB_PROBE_NAME: one }
  - id: fail-seven
    executor: orchestrator-probe
    profiles: [scheduler]
    env: { LAB_PROBE_NAME: seven, LAB_PROBE_FAIL_FIRST: "yes" }
  - id: pass-two
    executor: orchestrator-probe
    profiles: [scheduler]
    resources: [serial-a]
    env: { LAB_PROBE_NAME: two }
EOF
run="$work/run"
if "$LUA" "$lab" run --manifest "$work/scheduler.yaml" \
    --profile scheduler --jobs 3 --workdir "$run" >"$work/run.out" 2>&1; then
	echo "scheduler failure case unexpectedly passed" >&2
	exit 1
fi
grep -q '^passed=2$' "$run/summary"
grep -q '^failed=1$' "$run/summary"
grep -q '	FAIL	fail-seven	7	' "$run/events.tsv"
[ "$(cat "$run/status/pass-one.attempt")" -eq 1 ]

"$LUA" "$lab" run --manifest "$work/scheduler.yaml" \
    --profile scheduler --jobs 3 --workdir "$run" --resume >"$work/resume.out"
grep -q '^passed=3$' "$run/summary"
grep -q '^failed=0$' "$run/summary"
[ "$(cat "$run/status/pass-one.attempt")" -eq 1 ]
[ "$(cat "$run/status/fail-seven.attempt")" -eq 2 ]
grep -q '	REUSE	pass-one	0	' "$run/events.tsv"
grep -q '	PASS	fail-seven	0	' "$run/events.tsv"

resume_events=$(grep -c '	RESUME	' "$run/events.tsv")
if "$LUA" "$lab" run --manifest "$work/scheduler.yaml" \
    --profile scheduler --jobs 3 --workdir "$run" --resume \
    --set LAB_PROBE_STATUS=0 >"$work/changed-resume.out" 2>&1; then
	echo "changed resume configuration unexpectedly passed" >&2
	exit 1
fi
grep -q 'resume configuration differs' "$work/changed-resume.out"
[ "$(grep -c '	RESUME	' "$run/events.tsv")" -eq "$resume_events" ]

cat >"$work/gate.yaml" <<'EOF'
---
version: 1
defaults: { timeout: 10 }
cases:
  - id: required-gate
    executor: orchestrator-probe
    profiles: [gate]
    exclusive: true
    gate: true
    env: { LAB_PROBE_NAME: gate, LAB_PROBE_FAIL_FIRST: "yes" }
  - id: after-gate
    executor: orchestrator-probe
    profiles: [gate]
    env: { LAB_PROBE_NAME: after }
EOF
gate_run="$work/gate-run"
if "$LUA" "$lab" run --manifest "$work/gate.yaml" --profile gate --jobs 3 \
    --workdir "$gate_run" >"$work/gate-run.out" 2>&1; then
	echo "failing release gate unexpectedly passed" >&2
	exit 1
fi
grep -q '^passed=0$' "$gate_run/summary"
grep -q '^failed=1$' "$gate_run/summary"
grep -q '^blocked=1$' "$gate_run/summary"
grep -q '^total=2$' "$gate_run/summary"
grep -q '	BLOCKED	after-gate	gate:required-gate	' \
    "$gate_run/events.tsv"
[ ! -e "$gate_run/status/after-gate.attempt" ]

"$LUA" "$lab" run --manifest "$work/gate.yaml" --profile gate --jobs 3 \
    --workdir "$gate_run" --resume >"$work/gate-resume.out"
grep -q '^passed=2$' "$gate_run/summary"
grep -q '^failed=0$' "$gate_run/summary"
grep -q '^blocked=0$' "$gate_run/summary"
[ "$(cat "$gate_run/status/required-gate.attempt")" -eq 2 ]
[ "$(cat "$gate_run/status/after-gate.attempt")" -eq 1 ]

cat >"$work/late-gate.yaml" <<'EOF'
---
version: 1
cases:
  - id: ordinary
    executor: orchestrator-probe
    profiles: [late]
  - id: too-late
    executor: orchestrator-probe
    profiles: [late]
    exclusive: true
    gate: true
EOF
if "$LUA" "$lab" plan --manifest "$work/late-gate.yaml" --profile late \
    >"$work/late-gate.out" 2>&1; then
	echo "late gate unexpectedly passed validation" >&2
	exit 1
fi
grep -q 'gates must precede non-gate cases' "$work/late-gate.out"

echo "virtio-lab self-tests completed successfully"
