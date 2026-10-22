#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
#
# Runs inside a QEMU guest booted by live-qemu-hypertrace.py.  Each check
# prints "HTQ <name> PASS|FAIL <detail>" on the console; raw output follows
# between "HTQ-BEGIN <name>" and "HTQ-END <name>".  Expected values come from
# the test programs' sources (pid-target.c, pid-late-*.c) and the documented
# D semantics, not from earlier output.
#
# $1 is the test selection: "full" (default) or "kyua".

HT=/root/ht
SEL=${1:-full}
T=/usr/bin/timeout
cd $HT || exit 1

out() {	# name, command...: run and capture output
	name=$1; shift
	echo "HTQ-BEGIN $name"
	"$@" > /tmp/$name.out 2>&1
	rc=$?
	cat /tmp/$name.out
	echo "HTQ-END $name rc=$rc"
	return $rc
}

verdict() {	# name, condition-status, detail
	if [ "$2" -eq 0 ]; then echo "HTQ $1 PASS $3"; else echo "HTQ $1 FAIL $3"; fi
}

has() { grep -q -- "$2" /tmp/$1.out; }

echo "HTQ-START $(uname -rv | tr '\n' ' ') ncpu=$(sysctl -n hw.ncpu)"
kldstat > /tmp/kld.txt; cat /tmp/kld.txt

# --- tier 3 probe: can vmm(4) attach under QEMU TCG? -----------------------
out vmm-load kldload vmm
vmrc=$?
dmesg | grep -iE 'svm|vmm|amd-v|nested|nrip' > /tmp/vmm-dmesg.out
cat /tmp/vmm-dmesg.out
verdict vmm-attach $vmrc "$(tr '\n' ' ' < /tmp/vmm-dmesg.out)"

if [ "$SEL" = kyua ]; then
	echo "HTQ-BEGIN kyua"
	cd /usr/tests/cddl/usr.sbin/dtrace && \
	    $T 21600 kyua test -k Kyuafile > /tmp/kyua.out 2>&1
	tail -40 /tmp/kyua.out
	kyua report --verbose --results-filter broken,failed 2>&1 | head -400
	echo "HTQ-END kyua"
	summary=$(grep -E '^[0-9]+/[0-9]+ passed' /tmp/kyua.out | tail -1)
	echo "HTQ kyua INFO $summary"
	echo HTQ-DONE
	/sbin/shutdown -p now
	exit 0
fi

# --- basics ------------------------------------------------------------------
out begin $T 60 dtrace -q -n 'BEGIN { printf("BEGIN-OK\n"); exit(0); }'
has begin BEGIN-OK; verdict begin $? ""

out syscall $T 60 dtrace -q -n 'syscall::openat:entry /pid == $target/ { printf("OPENAT\n"); exit(0); }' -c '/bin/cat /etc/motd'
has syscall OPENAT; verdict syscall $? ""

# fbt entry probe: the kernel stack from the invop (breakpoint) frame must
# unwind through the syscall path to sys_openat and amd64_syscall.
out fbt-stack $T 60 dtrace -q -n 'fbt::kern_openat:entry /pid == $target/ { stack(); exit(0); }' -c '/bin/cat /etc/motd'
has fbt-stack sys_openat && has fbt-stack amd64_syscall; verdict fbt-stack $? ""

# fbt return probe: arg1 is the return value; kern_openat returns 0 on success.
out fbt-return $T 60 dtrace -q -n 'fbt::kern_openat:return /pid == $target/ { printf("RET=%d\n", arg1); exit(0); }' -c '/bin/cat /etc/motd'
has fbt-return 'RET=0'; verdict fbt-return $? ""

out immstack $T 60 dtrace -q -n 'fbt::kern_openat:entry /pid == $target/ { immstack(); exit(0); }' -c '/bin/cat /etc/motd'
has immstack sys_openat; verdict immstack $? ""

# The DTrace fault handler: wild user-range and kernel-range loads must be
# reported as invalid-address errors, without a panic, and dtrace continues.
out fault-user $T 60 dtrace -q -n 'BEGIN { trace(*(int *)0x10); } BEGIN { printf("AFTER\n"); exit(0); }'
has fault-user 'invalid address' && has fault-user AFTER; verdict fault-user $? ""
out fault-kernel $T 60 dtrace -q -n 'BEGIN { trace(*(int *)0xfffffffffff00000); } BEGIN { printf("AFTER\n"); exit(0); }'
has fault-kernel 'invalid address' && has fault-kernel AFTER; verdict fault-kernel $? ""

# SMP: profile probes must fire on every CPU (cross-calls at enable/disable).
ncpu=$(sysctl -n hw.ncpu)
out smp $T 120 dtrace -q -n 'profile-199 { @c[cpu] = count(); } tick-2s { printa("CPU %d %@d\n", @c); exit(0); }'
seen=$(grep -c '^CPU ' /tmp/smp.out); [ "$seen" -eq "$ncpu" ]
verdict smp $? "cpus=$seen/$ncpu"

# speculation and aggregation across CPUs commit through cross-calls too
out spec $T 60 dtrace -q -n 'BEGIN { s = speculation(); } BEGIN { speculate(s); printf("SPEC\n"); } BEGIN { commit(s); exit(0); }'
has spec SPEC; verdict spec $? ""

# --- -x checkmodref ------------------------------------------------------------
out checkmodref $T 60 dtrace -x checkmodref -q -n 'BEGIN { x = 1; } BEGIN { trace(x); exit(0); }'
has checkmodref 'ref-after-mod' && has checkmodref global; verdict checkmodref $? ""

# --- pid provider and USDT (targets built here from the test sources) -------------
out build-targets sh -c '
cc -O2 -fno-jump-tables -g -c pid-target.c &&
cc -O2 -g -c pid-target-switch.c &&
cc -c pid-target-asm.S &&
cc pid-target.o pid-target-switch.o pid-target-asm.o -o pid-target &&
dtrace -h -s pid-late.d -o pid-late.h &&
cc -g -fPIC -c pid-late-lib.c &&
dtrace -G -s pid-late.d -o pid-late-dof.o pid-late-lib.o &&
cc -shared -o libhtlate.so pid-late-lib.o pid-late-dof.o &&
cc -g -o pid-late-target pid-late-target.c &&
dtrace -h -s pid-usdt-exe.d -o pid-usdt-exe.h &&
cc -g -c pid-usdt-exe.c &&
dtrace -G -s pid-usdt-exe.d -o pid-usdt-exe-dof.o pid-usdt-exe.o &&
cc -o pid-usdt-exe pid-usdt-exe.o pid-usdt-exe-dof.o'
verdict build-targets $? ""

# main(argc=1): ht_branch(1) calls ht_leaf(1); ht_tail(1) calls ht_leaf(2).
out pid-entry $T 120 dtrace -q -n 'pid$target:a.out:ht_leaf:entry { printf("LEAF %d\n", arg0); }' -c ./pid-target
has pid-entry 'LEAF 1' && has pid-entry 'LEAF 2'; verdict pid-entry $? ""

# ht_leaf(x) returns 3x + 1: 4 and 7.
out pid-return $T 120 dtrace -q -n 'pid$target:a.out:ht_leaf:return { printf("RV %d\n", arg1); }' -c ./pid-target
has pid-return 'RV 4' && has pid-return 'RV 7'; verdict pid-return $? ""

# A library dlopen()ed after compilation: ht_late(5) (pid-late-target.c).
out pid-late $T 180 dtrace -Z -q -n 'pid$target:libhtlate.so:ht_late:entry { printf("LATE %d\n", arg0); }' -c "./pid-late-target $HT/libhtlate.so /tmp/late-base"
has pid-late 'LATE 5'; verdict pid-late $? ""

out usdt-late $T 180 dtrace -Z -q -n 'htlate$target:::fire { printf("FIRE %d %s\n", arg0, copyinstr(arg1)); }' -c "./pid-late-target $HT/libhtlate.so /tmp/late-base"
has usdt-late 'FIRE 5 late'; verdict usdt-late $? ""

# pid-usdt-exe.c: HTEXE_GO(argc) with argc 1.
out usdt-exe $T 120 dtrace -q -n 'htexe$target:::go { printf("GO %d\n", arg0); }' -c ./pid-usdt-exe
has usdt-exe 'GO 1'; verdict usdt-exe $? ""

# --- dtraced against the real /dev/dtrace ----------------------------------------
mkdir -p /var/ddtrace
out dtraced-start sh -c '/usr/sbin/dtraced -O -d -D /var/ddtrace > /tmp/dtraced.log 2>&1 & echo $! > /tmp/dtraced.pid; sleep 15; kill -0 $(cat /tmp/dtraced.pid) && echo ALIVE'
has dtraced-start ALIVE; verdict dtraced-start $? ""
out dtracedctl $T 60 /usr/sbin/dtracedctl --show-stats
verdict dtracedctl $? ""
out dtraced-stop sh -c 'kill -TERM $(cat /tmp/dtraced.pid); for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 $(cat /tmp/dtraced.pid) 2>/dev/null || { echo STOPPED; break; }; sleep 2; done; cat /tmp/dtraced.log | tail -30'
has dtraced-stop STOPPED; verdict dtraced-stop $? ""

echo "HTQ-BEGIN dmesg-tail"; dmesg | tail -60; echo "HTQ-END dmesg-tail"
dmesg | grep -qE 'panic|lock order reversal|witness' && echo "HTQ kernel-diagnostics INFO see dmesg-tail"
echo HTQ-DONE
/sbin/shutdown -p now
