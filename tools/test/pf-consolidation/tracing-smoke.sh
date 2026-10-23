#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Run as root ONLY in a disposable VM; DTrace runs outside the VNET jails.
set -eu
[ "${1-}" = "--disposable-vm" ] || { echo 'requires --disposable-vm' >&2; exit 2; }
[ "$(id -u)" = 0 ]
[ "$(sysctl -n hw.ncpu)" = 4 ]
work=$(mktemp -d /tmp/pf-tracing.XXXXXX)
a=pft_a_$$
b=pft_b_$$
ea=
eb=
cleanup()
{
    jail -r "$a" 2>/dev/null || true
    jail -r "$b" 2>/dev/null || true
    [ -z "$ea" ] || ifconfig "$ea" destroy 2>/dev/null || true
    echo "PF tracing evidence: $work"
}
trap cleanup EXIT
# 5BSD: the capability plane denies kldload(2) after boot.  pf and the
# DTrace providers are loader defaults, if_epair must be preloaded and
# dummynet may come from the SystemExtension broker.
for mod in pf if_epair dtraceall; do
    kldstat -q -m "$mod" || { echo "not preloaded: $mod" >&2; exit 1; }
done
kldstat -q -m dummynet || sysextctl load dummynet
kldstat -q -m dummynet
dtrace -l -P pf > "$work/probes.txt"
# OpenBSD PF probes (sys/netpfil/openbsd-pf/pf_sdt.c, pf_dummynet.c;
# dtrace_pf(4)) as "module function name".
for probe in 'ip test entry' 'ip test finish' 'ip rules entry' \
    'ip anchor enter' ' reason set' 'state state create' \
    'state state insert' 'state state remove' 'state state transition' \
    'state state free' 'ip dummynet submit' 'ip dummynet returned' \
    'ip dummynet reinject' 'ip dummynet error'; do
    m=${probe%% *}; rest=${probe#* }
    set -- $rest
    # An empty module (pf::reason:set) matches whatever dtrace -l shows there.
    awk -v m="$m" -v f="$1" -v n="$2" '$2 == "pf" && $(NF-1) == f && $NF == n && (m == "" || $3 == m) {found=1} END {exit !found}' "$work/probes.txt"
done
dtrace -l -P dummynet > "$work/dn-probes.txt"
for probe in 'sched enqueue result' 'sched dequeue packet' 'sched credit wait' \
    'delay release packet' 'queue enqueue done' 'queue drop reason' \
    'io input error' 'io output packet'; do
    set -- $probe
    awk -v m="$1" -v f="$2" -v n="$3" '$2 == "dummynet" && $3 == m && $4 == f && $5 == n {found=1} END {exit !found}' "$work/dn-probes.txt"
done
ea=$(ifconfig epair create)
eb=${ea%a}b
jail -c name="$a" persist vnet vnet.interface="$ea" allow.raw_sockets
jail -c name="$b" persist vnet vnet.interface="$eb" allow.raw_sockets
jexec "$a" ifconfig "$ea" inet 192.0.2.1/24 up
jexec "$b" ifconfig "$eb" inet 192.0.2.2/24 up
jexec "$a" ifconfig "$ea" inet6 -ifdisabled
jexec "$b" ifconfig "$eb" inet6 -ifdisabled
jexec "$a" ifconfig "$ea" inet6 2001:db8::1/64
jexec "$b" ifconfig "$eb" inet6 2001:db8::2/64
sleep 3
jexec "$a" ping -c 1 -t 5 192.0.2.2
jexec "$a" ping -6 -c 1 -t 5 2001:db8::2
jexec "$b" dnctl pipe 4242 config delay 10ms
printf '%s\n' 'pass dnpipe 4242 keep state label "pf-trace-test"' | jexec "$b" pfctl -f -
jexec "$b" pfctl -e
cat > "$work/traffic.sh" <<EOF
#!/bin/sh
set -eu
jexec $a ping -c 3 -t 10 192.0.2.2
jexec $a ping -6 -c 3 -t 10 2001:db8::2
jexec $b dnctl pipe 4242 config bw 8Kbit/s queue 1 delay 10ms
# Loss is expected; the trace must show credit waiting and queue-limit drops.
jexec $a ping -c 6 -i .01 -s 1400 -t 8 192.0.2.2 || :
jexec $b dnctl pipe 4242 config plr 1
if jexec $a ping -c 2 -t 3 192.0.2.2; then exit 1; fi
jexec $b pfctl -F states
printf '%s\n' 'pass inet proto icmp keep state (max 1) label "pf-trace-limit"' | jexec $b pfctl -f -
jexec $a ping -c 1 -t 5 192.0.2.2
if jexec $a ping -c 1 -t 2 192.0.2.2; then exit 1; fi
jexec $b pfctl -F states
printf '%s\n' 'block all' | jexec $b pfctl -f -
if jexec $a ping -c 1 -t 2 192.0.2.2; then exit 1; fi
if jexec $a ping -6 -c 1 -t 2 2001:db8::2; then exit 1; fi
echo PF_TRACE_TRAFFIC_PASS
EOF
cat > "$work/trace.d" <<EOF
#pragma D option quiet
pf:state:state:create
/stringof(args[1]->label) == "pf-trace-test"/
{ @events["create"] = count(); }
pf:state:state:insert,
pf:state:state:remove,
pf:state:state:transition
{ @events[probename] = count(); }
pf:ip:dummynet:submit
/(arg2 & 0xffff) == 4242/
{ @events["submit"] = count(); }
pf:ip:dummynet:returned
/(arg0 & 0xffff) == 4242/
{ @events["returned"] = count(); }
pf:ip:dummynet:reinject
/args[0] != 0 && stringof(args[0]->if_xname) == "$eb"/
{ @events["reinject"] = count(); }
pf:ip:test:entry
/stringof(args[2]->if_xname) == "$eb"/
{ @af[arg0] = count(); }
pf:ip:test:finish
/stringof(args[2]->if_xname) == "$eb"/
{ @result[arg0] = count(); }
dummynet:queue:drop:reason
/stringof(args[2]) == "loss model"/
{ @events["loss_drop"] = count(); }
dummynet:queue:drop:reason
/stringof(args[2]) == "queue limit"/
{ @events["queue_limit"] = count(); }
dummynet:sched:credit:wait
{ @events["credit_wait"] = count(); }
pf::reason:set
/arg0 == 12/
{ @events["state_limit"] = count(); }
ERROR { exit(2); }
END {
    printa("EVENT %s %@d\\n", @events);
    printa("AF %d %@d\\n", @af);
    printa("RESULT %d %@d\\n", @result);
}
EOF
dtrace -s /usr/share/dtrace/pf-observe -s /usr/share/dtrace/dn-observe -s "$work/trace.d" -c "/bin/sh $work/traffic.sh" > "$work/trace.out" 2> "$work/trace.err"
cat "$work/trace.out"
cat "$work/trace.err"
grep -q '^DN_SUMMARY faults=0$' "$work/trace.out"
for metric in DN_DEQUEUED DN_RELEASED; do
    awk -v m="$metric" '$1 == m && $2 > 0 {found=1} END {exit !found}' "$work/trace.out"
done
# pf-observe's verdict table: "  <dir> <action> <count>".
for verdict in 'in pass' 'in drop'; do
    set -- $verdict
    awk -v d="$1" -v a="$2" '$1 == d && $2 == a && $3 > 0 {found=1} END {exit !found}' "$work/trace.out"
done
grep -q '^PF_TRACE_TRAFFIC_PASS$' "$work/trace.out"
! grep -Ei 'drop|error|invalid|fault' "$work/trace.err"
for event in create insert remove transition submit returned reinject loss_drop queue_limit credit_wait state_limit; do
    awk -v e="$event" '$1 == "EVENT" && $2 == e && $3 > 0 {found=1} END {exit !found}' "$work/trace.out"
done
# FreeBSD AF_INET=2, AF_INET6=28; PF_PASS=0, PF_DROP=1.
for af in 2 28; do
    awk -v af="$af" '$1 == "AF" && $2 == af && $3 > 0 {found=1} END {exit !found}' "$work/trace.out"
done
for action in 0 1; do
    awk -v a="$action" '$1 == "RESULT" && $2 == a && $3 > 0 {found=1} END {exit !found}' "$work/trace.out"
done
echo PF_TRACING_PASS
