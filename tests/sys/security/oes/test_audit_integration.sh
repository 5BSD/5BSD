#!/bin/sh
#
# OES Audit Integration Verification Script
#
# This script demonstrates how to verify that OES audit records are being
# generated for authorization denials. Run with root privileges.
#
# Prerequisites:
#   - OES module loaded
#   - Audit daemon running (auditd)
#   - Appropriate audit policy configured
#
# Usage: sudo ./test_audit_integration.sh
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

TESTDIR="$(dirname "$0")"

echo "=== OES Audit Integration Verification ==="
echo ""

# Check if audit daemon is running
if ! pgrep -q auditd; then
    echo "WARNING: auditd is not running."
    echo "Audit records will not be written to the audit trail."
    echo ""
    echo "To enable auditing:"
    echo "  1. Edit /etc/security/audit_control"
    echo "  2. service auditd start"
    echo ""
fi

echo "OES generates audit records when authorization is denied."
echo "The audit record includes the text 'OES: authorization denied'"
echo ""
echo "To verify audit integration:"
echo ""
echo "1. Enable auditing (if not already enabled):"
echo "   service auditd start"
echo ""
echo "2. Run the AUTH deny test to generate denials:"
echo "   ${TESTDIR}/test_auth_responses"
echo ""
echo "3. Check the audit trail for OES records:"
echo "   praudit /var/audit/current | grep -i oes"
echo ""
echo "4. Or search the audit trail:"
echo "   auditreduce -m text /var/audit/current | praudit | grep OES"
echo ""

# If test binary exists, offer to run it
if [ -x "${TESTDIR}/test_auth_responses" ]; then
    echo "Would you like to run the AUTH response test now? (y/n)"
    read -r answer
    if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
        echo ""
        echo "Running test_auth_responses..."
        "${TESTDIR}/test_auth_responses"
        echo ""
        echo "Test complete. Check audit trail with:"
        echo "  praudit /var/audit/current | grep -i oes"
    fi
fi
