#!/bin/sh
# Run only inside a disposable VM. Arguments: payload directory, work directory.
set -u
payload=$1
work=$2
mkdir -p "$work"
ulimit -c 0
uname -a
for name in $(cat "$payload/cases.txt"); do
 if [ "$name" = hardlink ] && [ "$(uname -s)" = FreeBSD ]; then
  echo UPSTREAM_QUARANTINE hardlink known-namei-assertion
  continue
 fi
 mkdir -p "$work/$name"
 ln -sf "$payload/tests/exec-target.t" "$work/$name/exec-target"
 ln -sf "$payload/tests/exec-target.t" "$work/$name/exec-target.t"
 echo UPSTREAM_BEGIN "$name"
 (cd "$work/$name" && timeout -k 5 "${CASE_TIMEOUT:-45}" "$payload/tests/$name.t") > "$work/$name.log" 2>&1
 rc=$?
 cat "$work/$name.log"
 echo UPSTREAM_RESULT "$name" "$rc"
done
for mode in buffered direct registered sqpoll; do
 case "$mode" in
 buffered) opts='--direct=0' ;;
 direct) opts='--direct=1' ;;
 registered) opts='--direct=1 --fixedbufs=1 --registerfiles=1' ;;
 sqpoll) opts='--direct=1 --fixedbufs=1 --registerfiles=1 --sqthread_poll=1' ;;
 esac
 echo FIO_BEGIN "$mode"
 timeout -k 5 180 "$payload/fio" --name="$mode" --directory="$work" --ioengine=io_uring --size=16m --bs=4k --iodepth=16 --rw=write --verify=crc32c --do_verify=1 --verify_fatal=1 --fallocate=none --eta=never --output-format=json $opts > "$work/fio-$mode.json" 2>&1
 rc=$?
 cat "$work/fio-$mode.json"
 echo FIO_RESULT "$mode" "$rc"
 rm -f "$work/$mode.0.0"
done
echo UPSTREAM_DONE
