#!/bin/sh
# Copy rebuilt kernel/programs into the disposable 5BSD DUT and reboot.
# usage: push-files.sh [kernel] [pf] [prog:OBJREL:DEST ...]
set -eu
S="ssh -F /usr/obj/5BSD-pf-parity/keys/ssh_config"
O=/usr/obj/5BSD-pf-parity/obj/usr/obj/5BSD-pf-src/amd64.amd64
$S dut 'test -f /root/pf-parity-disposable'
for a in "$@"; do
	case $a in
	kernel)	cat $O/sys/GENERIC/kernel | $S dut 'cat > /boot/kernel/kernel.new && mv /boot/kernel/kernel.new /boot/kernel/kernel' ;;
	pf)	cat $O/sys/modules/pf/pf.ko | $S dut 'cat > /boot/kernel/pf.ko.new && mv /boot/kernel/pf.ko.new /boot/kernel/pf.ko' ;;
	prog:*)	rel=${a#prog:}; src=${rel%%:*}; dst=${rel#*:}
		cat $O/$src | $S dut "cat > $dst.new && chmod 555 $dst.new && mv $dst.new $dst" ;;
	esac
done
bt=$($S dut 'sysctl -n kern.boottime')
$S dut 'shutdown -r now' >/dev/null 2>&1 || true
sleep 30
# Wait for the new boot, not the old system shutting down.
until nbt=$($S -o ConnectTimeout=10 dut 'sysctl -n kern.boottime' 2>/dev/null) &&
    [ -n "$nbt" ] && [ "$nbt" != "$bt" ]; do sleep 10; done
$S dut 'sh -s' < $(dirname $0)/setup-dut-5bsd.sh | tail -1
$S dut 'uname -v; kldstat | grep pf.ko'
