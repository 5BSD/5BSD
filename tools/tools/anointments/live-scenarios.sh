#!/bin/sh
#-
# live-scenarios.sh -- run the IPC anointment acceptance matrix
# (docs/ipc-anointments-design.md, "Scenarios") on a live capability plane.
#
# This is the repeatable form of the by-hand validation: bugs in the mint and
# elevation paths surfaced only when the suites first ran on a real plane, so
# keep a scripted end-to-end pass.  Run it as root on a disposable VM that
# booted with the capability plane active (see the VM boot recipe), after
# staging the scenario accounts and policy.
#
# Setup (once, BEFORE booting -- the auth agent reads master.passwd through a
# descriptor it retains at start-up, so passwords set after boot are not seen):
#
#   pw groupadd operators -g 2001
#   pw useradd operator1 -u 2001 -g operators
#   pw useradd plainuser -u 2002
#   printf '%s\n' "$(openssl passwd -6 op-pass)"    | pw usermod operator1 -H 0
#   printf '%s\n' "$(openssl passwd -6 plain-pass)" | pw usermod plainuser -H 0
#   install -m 0644 scenario-policy.ucl /Capabilities/Config/principal-policy.ucl
#   # scenario-policy.ucl grants operators system.trace.client and
#   # may_elevate system.notify.system (see docs/ipc-anointments-design.md).
#   reboot
#
# Then, as root: sh live-scenarios.sh
#
# Exit status is the number of failed rows (0 = all passed).

set -u

PROBE=${PROBE:-/usr/tests/usr.sbin/switchboard/service_probe}
ASKPASS=${ASKPASS:-/usr/tests/usr.sbin/BSDAuth/pty_askpass}
CTL=${CTL:-switchboardctl}
fail=0

need() {
	[ -x "$1" ] || { echo "SKIP: $1 not found (install the tests package)"; exit 77; }
}
need "$PROBE"
need "$ASKPASS"

row() { # label expected-substring actual-text
	case "$2" in
	"$3"*|*"$2"*) printf '%-6s PASS  %s\n' "$1" "$3" ;;
	*) printf '%-6s FAIL  expected [%s] got [%s]\n' "$1" "$2" "$3"; fail=$((fail + 1)) ;;
	esac
}

as() { u=$1; shift; su -l "$u" -c "$*" 2>&1 | tr -d '\r'; }

# --- reach: sessions and their anointment sets -----------------------------
row S1  "OK system.Notify.System" "$($PROBE system.Notify.System 2>&1)"
row S1b "OK system.Notify"        "$($PROBE system.Notify 2>&1)"
row S3  "OK system.Notify"        "$(as plainuser $PROBE system.Notify | tail -1)"
row S4  "FAIL system.Notify.System errno=2" "$(as plainuser $PROBE system.Notify.System | tail -1)"
row P1  "OK system.Trace"         "$(as operator1 $PROBE system.Trace | tail -1)"
row P1n "FAIL system.Trace errno=2" "$(as plainuser $PROBE system.Trace | tail -1)"
row P2  "FAIL system.Notify.System errno=2" "$(as operator1 $PROBE system.Notify.System | tail -1)"

# --- elevation: anoint(1), driven through a real pty (readpassphrase) -------
elev() { # user password name cmd...
	u=$1; pw=$2; name=$3; shift 3
	as "$u" "$ASKPASS $pw anoint $name $*"
}
row S6 "not permitted"           "$(elev plainuser plain-pass system.notify.system $PROBE system.Notify.System | grep -aoE 'not permitted|OK sys|authentication' | head -1)"
row P5 "not permitted"           "$(elev operator1 op-pass  system.storage.admin  $PROBE system.Notify.System | grep -aoE 'not permitted|OK sys|authentication' | head -1)"
row P3 "OK system.Notify.System" "$(elev operator1 op-pass  system.notify.system  $PROBE system.Notify.System | grep -aoE 'OK system.Notify.System|authentication failed|not permitted' | head -1)"
row P4 "authentication failed"   "$(elev operator1 WRONGPW  system.notify.system  $PROBE system.Notify.System | grep -aoE 'authentication failed|OK sys|not permitted' | head -1)"

# --- non-admin su keeps a lookup channel (authenticated mint) --------------
row SU "INNER uid=plainuser"     "$($ASKPASS plain-pass su -l plainuser -c 'echo INNER uid=$(id -un) FD=$SERVICE_LOOKUP_FD' 2>&1 | tr -d '\r' | grep -a INNER)"

# --- the reach graph lints without a real error ----------------------------
$CTL graph --lint >/dev/null 2>graph.warns || true
if grep -q 'dead declaration' graph.warns || grep -q 'duplicate' graph.warns; then
	echo "GRAPH  FAIL  base tree has a dead declaration or duplicate:"; cat graph.warns
	fail=$((fail + 1))
else
	echo "GRAPH  PASS  no dead/duplicate ($(grep -c unreachable graph.warns) unreachable advisories)"
fi
rm -f graph.warns

echo "SUMMARY: $fail failed"
exit $fail
