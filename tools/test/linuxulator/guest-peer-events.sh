#!/bin/sh
# amd64 Linux64 peer-name getter and process ptrace event regression gate.
set -u
sha256 /root/linux_socket_peername /root/linux_ptrace_events /root/peer_caps /root/peer_caps_probe /root/ptrace_exit_native || exit 1
for name in linux_socket_peername linux_ptrace_events; do
    cp "/root/$name" "/tmp/$name" || exit 1
    chmod 0755 "/tmp/$name" || exit 1
done
for round in 1 2 3; do
    for user in root unprivileged; do
        for case in inet4 inet6 local pathname state faults lifetime; do
            timeout -k 3 60 /tmp/linux_socket_peername "$case" "$user"
            rc=$?
            echo GATE_PEER "$round" "$user" "$case" "$rc"
            [ "$rc" -eq 0 ] || exit 1
        done
        for case in exec fork vfork clone exit signal vfork_done selective isolation waitid; do
            timeout -k 3 60 /tmp/linux_ptrace_events "$case" "$user"
            rc=$?
            echo GATE_EVENT "$round" "$user" "$case" "$rc"
            [ "$rc" -eq 0 ] || exit 1
        done
    done
    timeout -k 3 60 /root/peer_caps /root/peer_caps_probe
    rc=$?
    echo GATE_PEER_CAPS "$round" "$rc"
    [ "$rc" -eq 0 ] || exit 1
    timeout -k 3 60 /root/ptrace_exit_native
    rc=$?
    echo GATE_EXIT_NATIVE "$round" "$rc"
    [ "$rc" -eq 0 ] || exit 1
done
echo GATE_PEER_EVENTS_DONE
