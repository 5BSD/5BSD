#!/bin/sh
# The enforced tier: with PLANE_OFF=1, vm-provider.sh defaults
# ISOLATION_ENFORCE to 1, writes that value to loader.conf, and the guest
# reports PLANEOFF_READY only when the booted
# kern.mac_capability_isolation.enforce is the requested value.  Runs the
# actual blocks of vm-provider.sh with sysctl and ps replaced.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

# Host side: the default chosen for each tier and an explicit override.
sed -n '/^plane_off=\${PLANE_OFF:-0}$/,/^case "\$isolation" in/p' \
    "$root/vm-provider.sh" | sed '$d' > "$work/defaults.sh"
grep -q 'isolation=' "$work/defaults.sh"
check_default() {
	got=$(env -i PATH="$PATH" ${1:+PLANE_OFF=$1} ${2:+ISOLATION_ENFORCE=$2} \
	    sh -c ". '$work/defaults.sh'; echo \$isolation")
	[ "$got" = "$3" ] || { echo "FAIL PLANE_OFF=$1 ISOLATION_ENFORCE=$2: $got, want $3"; exit 1; }
}
check_default "" "" 0
check_default 0 "" 0
check_default 1 "" 1
check_default 1 0 0
check_default 0 1 1

# Guest side: the plane-off gate.
sed -n '/^if \[ "\$PLANE_OFF" = 1 \]; then$/,/^else$/p' "$root/vm-provider.sh" |
    sed '$d' > "$work/gate.sh"
echo fi >> "$work/gate.sh"
grep -q PLANEOFF_READY "$work/gate.sh"
mkdir "$work/bin"
cat > "$work/bin/ps" <<'EOF'
#!/bin/sh
echo init
EOF
cat > "$work/bin/sysctl" <<'EOF'
#!/bin/sh
[ -n "${MOCK_ENFORCE:-}" ] || exit 1
echo "$MOCK_ENFORCE"
EOF
chmod +x "$work/bin/ps" "$work/bin/sysctl"
gate() {
	env PATH="$work/bin:$PATH" PLANE_OFF=1 ISOLATION_ENFORCE=$1 \
	    MOCK_ENFORCE=$2 sh "$work/gate.sh"
}
gate 1 1 | grep -qx PLANEOFF_READY
gate 1 1 | grep -qx PLANEOFF_ISOLATION_ENFORCE=1
gate 0 0 | grep -qx PLANEOFF_READY
if gate 1 0 | grep -qx PLANEOFF_READY; then echo "FAIL: ready with enforce 0"; exit 1; fi
gate 1 0 | grep -q '^PLANEOFF_GATE: kern.mac_capability_isolation.enforce=0 (want 1)$'
if gate 1 "" | grep -qx PLANEOFF_READY; then echo "FAIL: ready without the sysctl"; exit 1; fi
gate 1 "" | grep -q '^PLANEOFF_GATE: .*enforce=unset'

# The host verdict requires PLANEOFF_READY in the plane-off tier.
grep -q "plane_off\" = 1 \] && tr -d '\\\\r' < \"\$log\" | grep -aqx 'PLANEOFF_READY'" \
    "$root/vm-provider.sh"
echo 'PASS plane-off tier defaults to enforce=1, writes it, and gates on the booted value'
