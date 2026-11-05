#!/bin/sh
set -eu
kit=${1:?kit}
t=$(mktemp -d /tmp/boot-deadline.XXXXXX)
pid=
trap '[ -z "$pid" ] || kill "$pid" 2>/dev/null || :; rm -rf "$t"' EXIT
HT_KIT=$kit HT_WORK=$t HT_OUT=$t HT_LOG=$t/log O=$t
export HT_KIT HT_WORK HT_OUT HT_LOG
. "$kit/lib/common.sh"
# Sourcing common.sh installs cleanup traps; retain our fixture cleanup.
trap '[ -z "$pid" ] || kill "$pid" 2>/dev/null || :; rm -rf "$t"' EXIT
log() { echo "$*" >> "$t/log"; }
vm_boot_diagnostics() { echo "$1" >> "$t/diagnostics"; }
printf 'HOSTTEST-GUEST-READY\nroot@test:~ #\n' > "$t/test.console"
vm_sync_shell() { return 1; }
if vm_wait test HOSTTEST-GUEST-READY 1; then echo 'FAIL ready without responsive shell'; exit 1; fi
echo 'PASS boot requires responsive guest shell'
: > "$t/test.console"
start=$(date +%s)
if vm_wait test HOSTTEST-GUEST-READY 1; then exit 1; fi
[ $(( $(date +%s) - start )) -le 3 ]
grep -qx test "$t/diagnostics"
echo 'PASS host boot deadline captures failure'
# A ready marker cannot reset an already-expired launch budget.
printf 'HOSTTEST-GUEST-READY\nroot@test:~ #\n' > "$t/test.console"
echo $(( $(date +%s) - 5 )) > "$t/test.boot-start"
vm_sync_shell() { return 0; }
if vm_wait test HOSTTEST-GUEST-READY 1; then echo 'FAIL boot budget restarted'; exit 1; fi
rm "$t/test.boot-start"
: > "$t/test.console"
echo 'PASS loader/attachment time remains part of boot budget'

awk '/^nested_progress\(\)/ {p=1} p {print} p && /^}/ {exit}' "$kit/phases/nested.sh" > "$t/progress"
. "$t/progress"
vm_destroy() { echo "$1" >> "$t/destroyed"; }
vm=test; l0d=$t/diag; L2C=240; HT_L2_BOOT_TIMEOUT=1
mkdir "$l0d"
: > "$t/alive"; echo "$t/alive" > "$t/test.lifetime"
sleep 15 & pid=$!
nested_progress "$pid" 1
[ ! -e "$t/alive" ]
grep -qx test "$t/destroyed"
kill "$pid"; wait "$pid" 2>/dev/null || :; pid=
echo 'PASS host cancels unbooted L2 at readiness deadline'
# A fresh boot marker permits deliberate post-boot runtime beyond 1 second.
printf 'HOSTTEST-L2-MARKER fresh ncpu=1\n' > "$t/test.console"
: > "$t/alive"
sleep 2 & pid=$!
nested_progress "$pid" 1
[ -e "$t/alive" ]
wait "$pid"; pid=
echo 'PASS boot marker permits post-boot workload'
mkdir "$t/bin"
printf '#!/bin/sh\nexec /bin/sleep 20\n' > "$t/bin/dtracedctl"
chmod +x "$t/bin/dtracedctl"
PATH=$t/bin:$PATH
start=$(date +%s)
if ht_wait_forwarder missing 1; then exit 1; fi
[ $(( $(date +%s) - start )) -le 3 ]
echo 'PASS hung HyperTrace stats bounded by registration deadline'
