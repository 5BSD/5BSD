#!/bin/sh
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Kory Heard

set -eu
[ "$(hostname)" = auth-policy-vm ]
/usr/bin/trace-allow allow
/usr/bin/trace-deny deny
su - policyuser -c '/usr/bin/trace-allow allow'
su - policyuser -c '/usr/bin/trace-deny deny'
printf '%s\n' SOFTWARE_TRACE_PROVIDER_PASS
