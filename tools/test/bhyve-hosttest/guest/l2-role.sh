#!/bin/sh
# Run by rc.local in the L2 guest (role l2). Prints the marker, then the
# optional CPU-bound checksum workload (hosttest.l2work MiB per vCPU, one
# worker pinned to each vCPU with cpuset -l) and the optional hold
# (hosttest.l2hold seconds of ticks while L1 pings or the host checkpoints
# L1). rc.local powers off afterwards.
# Arguments override the loader environment (QEMU smoke): MARKER WORK HOLD.
c=${L2_CONSOLE:-/dev/console}
m=${1:-$(kenv -q hosttest.marker)}
work=${2:-$(kenv -q hosttest.l2work)}; work=${work:-0}
hold=${3:-$(kenv -q hosttest.l2hold)}; hold=${hold:-0}
T=/root/hosttest/srtool
n=$(sysctl -n hw.ncpu)
echo "HOSTTEST-L2-MARKER $m model=$(sysctl -n hw.model) ncpu=$n" > $c
if [ "$work" -gt 0 ]; then
	t0=$(date +%s); i=0
	while [ $i -lt "$n" ]; do
		# srtool work prints "<sha256> cpu=<cpu it finished on>".
		( set -- $(cpuset -l $i "$T" work "$work" $((1000 + i)) 2>&1)
		  echo "HOSTTEST-L2-WORK cpu=$i sum=$1 ran_on=${2#cpu=}" > $c ) &
		i=$((i + 1))
	done
	wait
	echo "HOSTTEST-L2-WORK-DONE seconds=$(( $(date +%s) - t0 ))" > $c
fi
devices=$(kenv -q hosttest.l2devices)
if [ "$devices" = storage ]; then
 sh /root/hosttest/l2-devices.sh before > "$c" 2>&1
fi
if [ "$hold" -gt 0 ]; then
	echo "HOSTTEST-L2-HOLD start seconds=$hold" > $c
	i=0
	while [ $i -lt "$hold" ]; do
		echo "HOSTTEST-L2-TICK n=$i $("$T" clock)" > $c
		sleep 1; i=$((i + 1))
	done
	echo "HOSTTEST-L2-HOLD-END" > $c
fi

if [ "$devices" = storage ]; then
 sh /root/hosttest/l2-devices.sh after > "$c" 2>&1
fi
