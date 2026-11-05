#!/bin/sh
# Runtime prerequisites for capability-plane-ON qualification, not a grant audit.
set -eu
if plane=$(kenv -q capability_plane 2>/dev/null); then
 :
else
 rc=$?
 # All failed KENV_GET calls return 255, not just an absent variable.
 # Accept rc policy's default only after a successful dump proves absence.
 if [ "$rc" -ne 255 ] || [ -n "$plane" ] ||
     ! settings=$(kenv 2>/dev/null); then
  echo "CAPABILITY-PLANE-FAIL loader-query-error=$rc"; exit 1
 fi
 if printf '%s\n' "$settings" | grep -q '^capability_plane='; then
  echo 'CAPABILITY-PLANE-FAIL loader-query-inconsistent'; exit 1
 fi
 unset settings
fi
case "$plane" in
''|[Yy][Ee][Ss]|[Oo][Nn]|1) ;;
*) echo "CAPABILITY-PLANE-FAIL loader=$plane"; exit 1 ;;
esac
if ! kldstat -q -m mac_capability; then
 echo 'CAPABILITY-PLANE-FAIL policy-module-missing'; exit 1
fi
if [ "$(sysctl -n kern.mac_capability_isolation.enforce 2>/dev/null)" != 1 ]; then
 echo 'CAPABILITY-PLANE-FAIL isolation-not-enforced'; exit 1
fi
if ! pgrep -x switchboard >/dev/null; then
 echo 'CAPABILITY-PLANE-FAIL switchboard-not-running'; exit 1
fi
echo 'CAPABILITY-PLANE-ON policy=loaded isolation=1 switchboard=running'
