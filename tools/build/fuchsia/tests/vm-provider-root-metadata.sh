#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/stage"
check() {
    printf '%s\n' "$2" > "$work/stage/METALOG"
    status=0
    sh "$root/vm-provider.sh" "$work/stage" "$work/unused" lib/libfidl 1 > "$work/log" 2>&1 || status=$?
    [ "$status" = 2 ]
    if [ "$1" = accept ]; then
        grep -q 'stage lacks /sbin/capsule' "$work/log"
    else
        grep -q 'METALOG must explicitly describe a searchable root' "$work/log"
    fi
    [ ! -e "$work/unused" ]
}
check reject '#mtree 2.0'
check reject '. type=dir uname=root gname=wheel mode=0700'
check reject '. type=dir uname=root gname=wheel mode=0644'
check reject '. type=file uname=root gname=wheel mode=0755'
check accept '. type=dir uname=root gname=wheel mode=0755'
check accept './ type=dir uname=root gname=wheel mode=555'
echo 'PASS: root metadata preflight rejects four malformed stages and accepts two searchable roots before image creation'
