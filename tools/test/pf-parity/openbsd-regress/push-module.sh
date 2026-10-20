#!/bin/sh
# Copy a freshly built pf.ko (and optionally pfctl) into the 5BSD DUT and
# reboot it (OpenBSD PF cannot be unloaded).  Disposable guests only.
set -eu
H=${1:-dut}
S="ssh -F /usr/obj/5BSD-pf-parity/keys/ssh_config"
O=/usr/obj/5BSD-pf-parity/obj/usr/obj/5BSD-pf-src/amd64.amd64
$S $H 'test -f /root/pf-parity-disposable'
cat $O/sys/modules/pf/pf.ko | $S $H 'cat > /boot/kernel/pf.ko.new && mv /boot/kernel/pf.ko.new /boot/kernel/pf.ko'
if [ "${PUSH_PFCTL:-no}" = yes ]; then
	cat $O/sbin/pfctl/pfctl | $S $H 'cat > /sbin/pfctl.new && chmod 555 /sbin/pfctl.new && mv /sbin/pfctl.new /sbin/pfctl'
fi
$S $H 'sha256 -q /boot/kernel/pf.ko; shutdown -r now' || true
sleep 40
until $S -o ConnectTimeout=10 $H true 2>/dev/null; do sleep 10; done
$S $H 'kldstat | grep pf.ko'
