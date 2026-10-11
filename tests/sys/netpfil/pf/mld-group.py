#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Distinguish MLD group payloads sharing one outer IPv6 tuple in PF state."""
import argparse
import logging
import subprocess
import time
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import Ether, IPv6, IPv6ExtHdrHopByHop, RouterAlert
from scapy.all import ICMPv6MLQuery, ICMPv6MLReport, sendp, get_if_hwaddr

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--interface', required=True)
p.add_argument('--jail', required=True)
a = p.parse_args()
source = 'fe80::1234'

def states():
    output = subprocess.check_output(['jexec', a.jail, 'pfctl', '-S', '-ss'], text=True)
    return [line for line in output.splitlines() if source in line]

def expect_count(expected):
    deadline = time.monotonic() + 15
    while True:
        found = states()
        if len(found) == expected:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f'expected {expected} group states, got {len(found)}: {found}')
        time.sleep(0.2)

for name, header in [('query', ICMPv6MLQuery), ('report', ICMPv6MLReport)]:
    subprocess.run(['jexec', a.jail, 'pfctl', '-F', 'states'], check=True)
    expect_count(0)
    # Keep the outer tuple fixed deliberately: only the group payload changes.
    # The groups have different folded identifiers in the OpenBSD mapping.
    for group, count in [('ff02::101', 1), ('ff02::101', 1),
                         ('ff02::102', 2), ('ff02::101', 2)]:
        packet = (Ether(src=get_if_hwaddr(a.interface), dst='33:33:00:00:00:01') /
                  IPv6(src=source, dst='ff02::1', hlim=1) /
                  IPv6ExtHdrHopByHop(options=[RouterAlert(value=0)]) /
                  header(mladdr=group))
        sendp(packet, iface=a.interface, verbose=False)
        # Give the receive path time to update the state before checking reuse.
        time.sleep(0.2)
        expect_count(count)
    print('MLD_GROUP_CASE', name, 'passed', flush=True)
