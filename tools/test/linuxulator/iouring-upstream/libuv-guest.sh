#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Each invocation owns a fresh loop/process. Preserve fallback and timeout output.
set -u
binary=${1:?usage: libuv-guest.sh /path/to/libuv-compat}
failed=0
for mode in default sqpoll; do
    for test in fs poll cancel; do
        echo "LIBUV_BEGIN $mode $test"
        timeout -k 5 45 "$binary" "$mode" "$test"
        rc=$?
        echo "LIBUV_RESULT $mode $test $rc"
        if [ "$rc" -ne 0 ]; then
            failed=1
        fi
    done
done
echo "LIBUV_DONE $failed"
exit "$failed"
