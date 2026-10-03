#!/bin/sh
# Runs as the authenticated user through su, login, and SSH.
set -eu
[ "$(id -u)" = 2001 ] || [ "$(id -u)" = 2002 ]
probe=/usr/bin/policy-probe
"$probe" open system.Notify 0
"$probe" mint 0 1
"$probe" open system.Notify.System 2
"$probe" stop system.Auth/bsdauth 1
if [ "$(id -u)" = 2001 ]; then
    "$probe" open system.Trace 0
    "$probe" start test.policy.network/worker 1
    "$probe" stop test.policy.network/worker 1
else
    "$probe" open system.Trace 2
    "$probe" stop test.policy.network/worker 0
    "$probe" start test.policy.network/worker 0
fi
# Forged identity does not change endpoint authority.
if [ "$(id -u)" = 2001 ]; then
    USER=root LOGNAME=root "$probe" stop test.policy.storage/worker 1
else
    USER=root LOGNAME=root "$probe" open system.Trace 2
fi
# Removing the inherited capability must fail; no ambient uid-based fallback.
channel_log=$(mktemp)
if (unset SERVICE_LOOKUP_FD; exec 3<&-; "$probe" open system.Notify 0
"$probe" mint 0 1) > "$channel_log" 2>&1; then
    rm -f "$channel_log"
    exit 1
fi
grep -q 'missing ambient session channel' "$channel_log"
rm -f "$channel_log"
# An ordinary user cannot replace the policy or rewrite its grants.
if (printf 'forged policy\n' > /Capabilities/Config/principal-policy.ucl) 2>/dev/null; then
    exit 1
fi
if touch /Capabilities/Config/untrusted-user-policy 2>/dev/null; then
    exit 1
fi
echo SESSION_AUTHORITY_BOUNDARIES_PASS
# Ordinary shell, files, permissions and child processes continue to work.
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT HUP INT TERM
printf 'session data\n' > "$d/a"
cp "$d/a" "$d/b"
cmp "$d/a" "$d/b"
(sleep 1) & wait
chmod 000 "$d/a"
if cat "$d/a" 2>/dev/null; then exit 1; fi
printf 'SESSION_CAPABILITIES_PASS uid=%s\n' "$(id -u)"
