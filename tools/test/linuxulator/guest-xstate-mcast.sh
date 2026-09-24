#!/bin/sh
# amd64 Linux64 XSAVE writes and full-state multicast source filters.
set -u
ifconfig vtnet0 inet 10.0.2.15/24 up || exit 1
ifconfig vtnet0 inet6 fd00::1 prefixlen 64 alias || exit 1
route add -net 224.0.0.0/4 -iface vtnet0 || exit 1
route -6 add -net ff00::/8 -iface vtnet0 || exit 1
# Let IPv6 duplicate-address detection finish before binding the sender.
sleep 2
for name in linux_ptrace_xstate linux_mcast_filter; do
    cp "/root/$name" "/tmp/$name" || exit 1
    chmod 0755 "/tmp/$name" || exit 1
done
for round in 1 2 3; do
    for user in root unprivileged; do
        for case in roundtrip write_resume lengths invalid init_state faults metadata; do
            timeout -k 3 30 /tmp/linux_ptrace_xstate "$case" "$user"
            rc=$?
            echo GATE_XSTATE "$round" "$user" "$case" "$rc"
            [ "$rc" -eq 0 ] || exit 1
        done
        for case in mixed mixed_delivery mixed_churn roundtrip replace leave lengths invalid faults lifetime duplicates delivery interfaces churn; do
            timeout -k 3 60 /tmp/linux_mcast_filter "$case" vtnet0 "$user"
            rc=$?
            echo GATE_MCAST "$round" "$user" "$case" "$rc"
            [ "$rc" -eq 0 ] || exit 1
        done
    done
    timeout -k 3 60 /root/mcast_native vtnet0 /tmp/linux_mcast_filter
    rc=$?
    echo GATE_MCAST_NATIVE "$round" "$rc"
    [ "$rc" -eq 0 ] || exit 1
done
echo GATE_XSTATE_MCAST_DONE
