#!/bin/sh
# amd64 Linux64 socket identity and native descriptor-right regressions.
set -u
cp /root/linux_socket_cookie /tmp/linux_socket_cookie || exit 1
chmod 0755 /tmp/linux_socket_cookie || exit 1
for round in 1 2 3; do
    for case in identity lifetime rights bounds faults churn; do
        timeout -k 3 60 /tmp/linux_socket_cookie "$case"
        rc=$?
        echo GATE_COOKIE "$round" "$case" "$rc"
        [ "$rc" -eq 0 ] || exit 1
    done
    timeout -k 3 120 /tmp/linux_socket_cookie --unprivileged
    rc=$?
    echo GATE_COOKIE "$round" unprivileged "$rc"
    [ "$rc" -eq 0 ] || exit 1
    timeout -k 3 30 /root/cookie_caps /root/cookie_caps_probe
    rc=$?
    echo GATE_COOKIE "$round" caps "$rc"
    [ "$rc" -eq 0 ] || exit 1
done
echo GATE_COOKIE_DONE
