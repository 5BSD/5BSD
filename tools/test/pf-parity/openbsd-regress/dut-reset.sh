#!/bin/sh
# Reset a panicked/hung disposable DUT from ddb and wait for ssh.
set -u
cd /usr/obj/5BSD-pf-parity/vms
python3.12 /usr/obj/5BSD-pf-src/tools/test/pf-parity/console.py --timeout 20 \
    --log dut-reset.log dut-serial.sock 'send:' 'sleep:2' 'send:reset' 'sleep:3' >/dev/null 2>&1 || true
python3.12 /usr/obj/5BSD-pf-src/tools/test/pf-parity/qmp.py dut-qmp.sock system_reset >/dev/null 2>&1 || true
sleep 30
until ssh -F /usr/obj/5BSD-pf-parity/keys/ssh_config -o ConnectTimeout=10 dut true 2>/dev/null; do sleep 10; done
echo dut-up
