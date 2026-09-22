#!/bin/sh
# amd64-only register contracts; invoked by the isolated guest gate.
set -u
mkdir -p /proc || exit 1
kldstat -q -n linprocfs.ko || kldload /boot/kernel/linprocfs.ko || exit 1
mount -t linprocfs linprocfs /proc || exit 1
cp /root/linux_ptrace_registers /tmp/linux_ptrace_registers || exit 1
chmod 0755 /tmp/linux_ptrace_registers || exit 1
cp /root/linux_ptrace_user /tmp/linux_ptrace_user || exit 1
chmod 0755 /tmp/linux_ptrace_user || exit 1
for round in 1 2 3; do
    for case in fp_read fp_write fp_setregset fp_bad_mxcsr gpr_read gpr_write gpr_partial gpr_rax gpr_bad_base lengths faults unknown xstate_read protected_memory bounds permissions unprivileged gpr_fault_progress tls_write thread_target repeated; do
        timeout 60 /tmp/linux_ptrace_registers "$case"
        rc=$?
        echo GATE_PTRACE "$round" "$case" "$rc"
        [ "$rc" -eq 0 ] || exit 1
    done
    for case in linux_ptrace_lifecycle linux_ptrace_user linux_ptrace_metadata linux_ptrace_sigmask linux_proc_task linux_ptrace_kill_native; do
        timeout -k 3 60 /root/"$case"
        rc=$?
        echo GATE_PTRACE_OPTIONS "$round" "$case" "$rc"
        [ "$rc" -eq 0 ] || exit 1
    done
    timeout -k 3 60 /tmp/linux_ptrace_user unprivileged
    rc=$?
    echo GATE_PTRACE_OPTIONS "$round" user_unprivileged "$rc"
    [ "$rc" -eq 0 ] || exit 1
    /root/ptrace_native
    rc=$?
    echo GATE_PTRACE_NATIVE "$round" "$rc"
    [ "$rc" -eq 0 ] || exit 1
    /root/ptrace_capmode /root/ptrace_capmode_probe
    rc=$?
    echo GATE_PTRACE_CAPMODE "$round" "$rc"
    [ "$rc" -eq 0 ] || exit 1
done
umount /proc || exit 1
echo GATE_PTRACE_DONE
