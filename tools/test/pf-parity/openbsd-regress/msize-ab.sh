#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# MSIZE A/B on the DUT: boot each kernel once with nextboot(8), configure
# the topology, run msize-bench.sh.  Kernels are expected in /boot/msizeA
# (MSIZE 256) and /boot/msizeB (MSIZE 512) on the DUT.  usage: msize-ab.sh OUT
set -u
out=$1
S="ssh -F /usr/obj/5BSD-pf-parity/keys/ssh_config"
d=$(dirname $0)
for k in msizeA msizeB; do
	bt=$($S dut 'sysctl -n kern.boottime')
	$S dut "nextboot -k $k && shutdown -r now" >/dev/null 2>&1 || true
	sleep 30
	until nbt=$($S -o ConnectTimeout=10 dut 'sysctl -n kern.boottime' 2>/dev/null) &&
	    [ -n "$nbt" ] && [ "$nbt" != "$bt" ]; do sleep 10; done
	$S dut 'sh -s' < $d/setup-dut-5bsd.sh > /dev/null 2>&1
	sh $d/msize-bench.sh "$k $($S dut 'sysctl -n kern.ipc.msize')" "$out"
done
