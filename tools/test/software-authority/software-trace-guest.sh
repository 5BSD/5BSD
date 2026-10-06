#!/bin/sh
set -eu
[ "$(hostname)" = auth-policy-vm ]
/usr/bin/trace-allow allow
/usr/bin/trace-deny deny
su - policyuser -c '/usr/bin/trace-allow allow'
su - policyuser -c '/usr/bin/trace-deny deny'
printf '%s\n' SOFTWARE_TRACE_PROVIDER_PASS
