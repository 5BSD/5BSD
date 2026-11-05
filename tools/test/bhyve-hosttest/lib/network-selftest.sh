#!/bin/sh
# Unprivileged fixtures only: no host networking changes or VMs.
set -u
HT_KIT=$(cd "$(dirname "$0")/.." && pwd -P)
. "${HT_NETWORK_COMMON:-$HT_KIT/lib/common.sh}"
trap - EXIT
T=$1
mkdir -p "$T/bin" || exit 1
T=$(cd "$T" && pwd -P); export T
fail=0
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
cat > "$T/bin/query" <<'STUB'
#!/bin/sh
printf '%s\n' "${0##*/} $*" >> "$T/queries"
case ${0##*/} in
ifconfig) cat "$T/interfaces" ;;
route) echo 'interface: bridge0'; exit 7 ;;
arp) echo 'incomplete on bridge0';;
netstat) echo 'fixture counters/routes';;
sysctl) echo 'diagnostic unavailable' >&2; exit 1 ;;
esac
STUB
chmod +x "$T/bin/query"
for cmd in ifconfig route arp netstat sysctl; do ln -sf query "$T/bin/$cmd"; done
PATH=$T/bin:$PATH; export PATH
printf '%s\n' 'bridge0: flags=8843<UP>' '    inet 10.231.77.1 netmask 0xffffff00' 'bridge1: flags=8843<UP>' '    inet 10.231.77.1 netmask 0xffffff00' > "$T/interfaces"
ht_net_diagnostics "$T/capture" bridge1 tap1 10.231.77.2
if grep -q bridge0 "$T/capture.interfaces" && grep -q bridge1 "$T/capture.interfaces" &&
    grep -q 'interface: bridge0' "$T/capture.route-to-guest" && grep -q 'rc=7$' "$T/capture.route-to-guest" &&
    grep -q 'incomplete on bridge0' "$T/capture.arp" && grep -q 'rc=1$' "$T/capture.bridge-sysctls" &&
    grep -q '^ifconfig bridge1 addr$' "$T/queries" && grep -q '^ifconfig tap1$' "$T/queries" &&
    grep -q '^netstat -inb$' "$T/queries"; then ok 'duplicate bridges, wrong route, ARP and query errors retained'; else bad 'diagnostic evidence'; fi
ht_net_capture "$T/missing" /no/such/hosttest-command
if grep -q 'rc=127$' "$T/missing"; then ok 'missing query reported'; else bad 'missing query'; fi
start=$(date +%s)
ht_net_capture "$T/timeout" sh -c 'echo partial-evidence; exec sleep 30'
elapsed=$(( $(date +%s) - start ))
if grep -q partial-evidence "$T/timeout" && grep -q 'rc=124$' "$T/timeout" && [ "$elapsed" -lt 15 ]; then ok 'timeout bounded with partial evidence'; else bad "timeout elapsed=$elapsed"; fi
printf '%s\n' '2 packets transmitted, 2 packets received, 0.0% packet loss' > "$T/ping"
ht_net_ping_ok "$T/ping" && ok 'complete successful ping' || bad 'successful ping'
for summary in '2 packets transmitted, 0 packets received, 100.0% packet loss' '2 packets transmitted, 1 packets received, 50.0% packet loss' '0 packets transmitted, 0 packets received, 0.0% packet loss' 'echo 2 packets transmitted, 2 packets received, 0.0% packet loss' 'diagnostic rc=0'; do
 printf '%s\n' "$summary" > "$T/ping"
 if ht_net_ping_ok "$T/ping"; then bad "accepted: $summary"; fi
done
: > "$T/ping"
if ht_net_ping_ok "$T/ping"; then bad 'empty ping'; fi
ok 'loss, zero packets, echoed commands and absent summaries exercised'
# Prefix matching must not confuse .77 with .770 or IPv6, and aliases count.
printf '%s\n' 'bridge2: flags=8843<UP>' '    inet6 fe80::77 prefixlen 64' '    inet 10.231.7.1 netmask 0xffffff00' > "$T/interfaces"
ht_private_net_preflight 10.231.77 "$T/preflight" || bad 'unrelated/IPv6 collision'
printf '%s\n' '    inet 10.231.77.99 netmask 0xffffff00' >> "$T/interfaces"
if ht_private_net_preflight 10.231.77 "$T/preflight"; then bad 'missed alias collision'; fi
case "$HT_NET_CONFLICT" in *bridge2=10.231.77.99*) ok 'alias ownership retained';; *) bad 'alias ownership';; esac
# Cleanup must expose which stage did not return, and retain destroy errors.
HT_WORK=$T; HT_LOG=$T/cleanup.log
vm_detach_console() { echo detached >> "$HT_LOG"; }
sleep() { :; }
bhyvectl() { echo 'fixture destroy failure' >&2; return 9; }
vm_destroy ht-fixture
if grep -q 'console detach begin' "$HT_LOG" && grep -q 'console detach end' "$HT_LOG" &&
    grep -q 'bhyvectl destroy begin' "$HT_LOG" && grep -q 'destroy end rc=9' "$HT_LOG" &&
    grep -q 'fixture destroy failure' "$HT_LOG"; then ok 'cleanup stages and failure status retained'; else bad 'cleanup logging'; fi
exit "$fail"
