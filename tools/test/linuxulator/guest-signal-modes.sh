#!/bin/sh
# amd64 Linux64 pending signals, tracing reattach and multicast transitions.
set -u
sha256 /root/linux_ptrace_pending /root/linux_mcast_filter || exit 1
cp /root/linux_ptrace_pending /tmp/linux_ptrace_pending || exit 1
cp /root/linux_mcast_filter /tmp/linux_mcast_filter || exit 1
chmod 0755 /tmp/linux_ptrace_pending /tmp/linux_mcast_filter || exit 1
for round in 1 2 3; do
    for user in root unprivileged; do
        for case in shared thread standard validation faults reattach lifetime; do
            timeout -k 3 60 /tmp/linux_ptrace_pending "$case" "$user"
            rc=$?
            echo GATE_PENDING "$round" "$user" "$case" "$rc"
            [ "$rc" -eq 0 ] || exit 1
        done
        for case in transitions transition_delivery; do
            timeout -k 3 60 /tmp/linux_mcast_filter "$case" vtnet0 "$user"
            rc=$?
            echo GATE_TRANSITIONS "$round" "$user" "$case" "$rc"
            [ "$rc" -eq 0 ] || exit 1
        done
    done
done
echo GATE_SIGNAL_MODES_DONE
