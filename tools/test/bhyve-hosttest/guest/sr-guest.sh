#!/bin/sh
# Guest side of the save/restore checks (sr2). Every line it prints starts
# with an SR* tag that lib/common.sh parses on the host.
#   sr-guest.sh prep MB SEED        pattern file + memory holder (srtool hold)
#   sr-guest.sh spin N              N CPU-bound workers, worker i pinned to CPU i
#   sr-guest.sh read                holder verification, file digest, workers, clock
#   sr-guest.sh write TAG MB SEED   write after restore, sync, read back
#   sr-guest.sh exists TAG          is /var/tmp/srpost.TAG present?
#   sr-guest.sh tcp-listen PORT     background listener -> /var/tmp/srtcp.PORT
#   sr-guest.sh tcp-got PORT        what the listener received
#   sr-guest.sh tcp-send HOST PORT TOKEN
#   sr-guest.sh dirty MB            start the memory-dirtying workload
#   sr-guest.sh dirty-read          its status line
#   sr-guest.sh cpuleaves           CPUID host-CPU-local leaves on every vCPU
#   sr-guest.sh stop                stop every worker started here
set -u
T=/root/hosttest/srtool
# Data that must survive on disk: /var/tmp (UFS). Status and pid files: a
# tmpfs, so they are part of the memory image and the workers never write
# the disk (a checkpoint taken while the guest runs then stays consistent
# with the disk copy).
D=/var/tmp R=/var/run/sr
mkdir -p $R
mount | grep -q " on $R " || mount -t tmpfs -o size=16m tmpfs $R 2>/dev/null ||
    echo "SRTMPFS unavailable; status files on UFS"
cmd=${1:?command}; shift
case "$cmd" in
prep)
	mb=${1:?MB} seed=${2:?SEED}
	"$T" pattern "$mb" "$seed" > $D/srfile.tmp && sync && mv $D/srfile.tmp $D/srfile && sync
	echo "SRFILE sha256=$(sha256 -q $D/srfile) bytes=$(stat -f %z $D/srfile)"
	rm -f $R/srhold.status
	daemon -p $R/srhold.pid "$T" hold "$mb" "$seed" $R/srhold.status
	i=0; while [ ! -s $R/srhold.status ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i + 1)); done
	cat $R/srhold.status 2>/dev/null || echo "SRHOLD-MISSING status=$R/srhold.status"
	;;
spin)
	n=${1:?N}; i=0
	while [ $i -lt "$n" ]; do
		rm -f $R/srspin.$i
		daemon -p $R/srspin.$i.pid cpuset -l $i nice -n 10 "$T" spin $R/srspin.$i
		i=$((i + 1))
	done
	sleep 1
	i=0; while [ $i -lt "$n" ]; do echo "SRSPIN-$i $(cat $R/srspin.$i 2>/dev/null)"; i=$((i + 1)); done
	;;
read)
	"$T" clock
	if [ -f $R/srhold.status ]; then "$T" verify $R/srhold.status 60; fi
	[ -f $D/srfile ] && echo "SRFILE sha256=$(sha256 -q $D/srfile) bytes=$(stat -f %z $D/srfile)"
	for f in $R/srspin.[0-9]*; do
		case "$f" in *.pid|*.tmp.*) continue ;; esac
		[ -f "$f" ] && echo "SRSPIN-${f##*.} $(cat "$f")"
	done
	"$T" clock
	;;
write)
	tag=${1:?TAG} mb=${2:?MB} seed=${3:?SEED}
	"$T" pattern "$mb" "$seed" > $D/srpost.$tag && sync
	echo "SRPOST tag=$tag sha256=$(sha256 -q $D/srpost.$tag)"
	;;
exists)
	[ -e $D/srpost.${1:?TAG} ] && echo "SREXISTS tag=$1 yes" || echo "SREXISTS tag=$1 no"
	;;
tcp-listen)
	p=${1:?PORT}; rm -f $R/srtcp.$p
	daemon -p $R/srtcp.$p.pid sh -c "timeout 120 nc -l $p > $R/srtcp.$p"
	sleep 0.5; echo "SRTCP-LISTEN port=$p"
	;;
tcp-got)
	p=${1:?PORT}; i=0
	while [ ! -s $R/srtcp.$p ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
	echo "SRTCP-GOT port=$p data=$(head -1 $R/srtcp.$p 2>/dev/null)"
	;;
tcp-send)
	echo "${3:?TOKEN}" | timeout 20 nc -N "${1:?HOST}" "${2:?PORT}"; echo "SRTCP-SENT rc=$?"
	;;
dirty)
	rm -f $R/srdirty.status
	daemon -p $R/srdirty.pid "$T" dirty "${1:?MB}" $R/srdirty.status
	i=0; while [ ! -s $R/srdirty.status ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i + 1)); done
	cat $R/srdirty.status 2>/dev/null || echo "SRDIRTY-MISSING"
	;;
dirty-read)
	if [ -f $R/srdirty.pid ] && kill -0 "$(cat $R/srdirty.pid)" 2>/dev/null; then a=yes; else a=no; fi
	echo "$(cat $R/srdirty.status 2>/dev/null || echo SRDIRTY-MISSING) alive=$a"
	;;
cpuleaves)
	# Host-CPU-local CPUID leaves (AMD 0x80000026 extended topology, Intel
	# 0x1A hybrid core type). vmm must report the same value on every vCPU
	# (zero since the gen4 fix); the max leaves say whether they exist.
	ncpu=$(sysctl -n hw.ncpu); i=0
	[ -e /dev/cpuctl0 ] || { echo "SRLEAF-NOCPUCTL"; exit 0; }
	while [ $i -lt "$ncpu" ]; do
		mb=$(cpucontrol -i 0 /dev/cpuctl$i 2>&1 | awk '{print $(NF-3)}')
		me=$(cpucontrol -i 0x80000000 /dev/cpuctl$i 2>&1 | awk '{print $(NF-3)}')
		for l in 0x1a 0x80000026; do
			v=$(cpucontrol -i $l,0 /dev/cpuctl$i 2>&1 | sed 's/.*: //')
			echo "SRLEAF cpu=$i leaf=$l maxbasic=$mb maxext=$me value=$v"
		done
		i=$((i + 1))
	done
	;;
stop)
	for p in $R/srhold.pid $R/srdirty.pid $R/srspin.*.pid $R/srtcp.*.pid; do
		[ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null
		rm -f "$p"
	done
	echo "SRSTOPPED"
	;;
*)
	echo "unknown command $cmd" >&2; exit 2 ;;
esac
