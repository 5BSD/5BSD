#!/bin/sh
#
# OES DTrace Probe Verification Script
#
# This script demonstrates how to verify that OES DTrace probes are firing
# correctly. Run with root privileges.
#
# Usage: sudo ./test_dtrace_probes.sh [probe]
#   probe: all, auth, cache, event (default: all)
#
# DTrace Probes provided by OES:
#   oes:::auth-allow    - AUTH event allowed (event_type, pid, path)
#   oes:::auth-deny     - AUTH event denied (event_type, pid, path)
#   oes:::auth-timeout  - AUTH event timed out (event_type, pid, default_action)
#   oes:::event-enqueue - Event added to client queue (event_type, pid, msg_id)
#   oes:::event-drop    - Event dropped (queue full) (event_type, pid, msg_id)
#   oes:::cache-hit     - Decision cache hit (event_type, pid, cached_result)
#   oes:::cache-miss    - Decision cache miss (event_type, pid)
#

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

if ! kldstat -q -m oes 2>/dev/null; then
    echo "OES module is not loaded. Load it first:"
    echo "  kldload /path/to/oes.ko"
    exit 1
fi

PROBE="${1:-all}"
TESTDIR="$(dirname "$0")"

echo "=== OES DTrace Probe Verification ==="
echo ""

# List available OES probes
echo "Available OES probes:"
# Check for any probe lines (lines starting with a number)
PROBE_LIST=$(dtrace -l -P oes 2>/dev/null | grep -E '^[[:space:]]*[0-9]' || true)
if [ -z "$PROBE_LIST" ]; then
    echo "  (none found)"
    echo ""
    echo "SKIP: No OES DTrace probes available."
    echo "This may be because:"
    echo "  - The module was built without SDT support"
    echo "  - DTrace is not available in this environment (jail/VM)"
    echo "  - The kernel lacks DTrace support"
    exit 0
fi
dtrace -l -P oes 2>/dev/null
echo ""

case "$PROBE" in
    auth)
        echo "--- Testing auth-allow and auth-deny probes ---"
        echo "Running: dtrace -n 'oes:::auth-allow,oes:::auth-deny { printf(\"%s pid=%d path=%s\", probename, arg1, copyinstr(arg2)); }'"
        echo "In another terminal, run: ${TESTDIR}/test_auth_responses"
        echo ""
        dtrace -n 'oes:::auth-allow,oes:::auth-deny { printf("%s event=%d pid=%d path=%s", probename, arg0, arg1, copyinstr(arg2)); }'
        ;;

    cache)
        echo "--- Testing cache-hit and cache-miss probes ---"
        echo "Running: dtrace -n 'oes:::cache-hit,oes:::cache-miss { printf(\"%s event=%d pid=%d\", probename, arg0, arg1); }'"
        echo "In another terminal, run: ${TESTDIR}/test_decision_cache"
        echo ""
        dtrace -n 'oes:::cache-hit,oes:::cache-miss { printf("%s event=%d pid=%d", probename, arg0, arg1); }'
        ;;

    event)
        echo "--- Testing event-enqueue and event-drop probes ---"
        echo "Running: dtrace -n 'oes:::event-enqueue,oes:::event-drop { printf(\"%s event=%d pid=%d\", probename, arg0, arg1); }'"
        echo "In another terminal, run: ${TESTDIR}/test_memory_pressure"
        echo ""
        dtrace -n 'oes:::event-enqueue,oes:::event-drop { printf("%s event=%d pid=%d msg_id=%d", probename, arg0, arg1, arg2); }'
        ;;

    timeout)
        echo "--- Testing auth-timeout probe ---"
        echo "Running: dtrace -n 'oes:::auth-timeout { printf(\"timeout event=%d pid=%d default=%d\", arg0, arg1, arg2); }'"
        echo "In another terminal, run: ${TESTDIR}/test_auth_timeout"
        echo ""
        dtrace -n 'oes:::auth-timeout { printf("timeout event=%d pid=%d default=%d", arg0, arg1, arg2); }'
        ;;

    all|*)
        echo "--- Tracing all OES probes (Ctrl+C to stop) ---"
        echo "In another terminal, run the test suite: cd ${TESTDIR} && make run"
        echo ""
        dtrace -n '
oes:::auth-allow { printf("ALLOW  event=%d pid=%d", arg0, arg1); }
oes:::auth-deny { printf("DENY   event=%d pid=%d", arg0, arg1); }
oes:::auth-timeout { printf("TIMEOUT event=%d pid=%d default=%d", arg0, arg1, arg2); }
oes:::cache-hit { printf("CACHE HIT  event=%d pid=%d result=%d", arg0, arg1, arg2); }
oes:::cache-miss { printf("CACHE MISS event=%d pid=%d", arg0, arg1); }
oes:::event-enqueue { printf("ENQUEUE event=%d pid=%d id=%d", arg0, arg1, arg2); }
oes:::event-drop { printf("DROP    event=%d pid=%d id=%d", arg0, arg1, arg2); }
'
        ;;
esac
