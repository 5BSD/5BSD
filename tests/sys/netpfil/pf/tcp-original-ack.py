#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Verify wire ACK validation on resets through a disposable PF router."""
import argparse
import logging
import subprocess
import threading
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import AsyncSniffer, Ether, IP, IPv6, TCP, Raw, get_if_hwaddr, sendp

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--family', choices=['inet', 'inet6'], required=True)
p.add_argument('--left', required=True)
p.add_argument('--right', required=True)
p.add_argument('--left-mac', required=True)
p.add_argument('--right-mac', required=True)
p.add_argument('--jail', required=True)
a = p.parse_args()
layer = IP if a.family == 'inet' else IPv6
client, server = ('192.0.2.10', '198.51.100.20') if a.family == 'inet' else ('2001:db8:1::10', '2001:db8:2::20')
mask = 0xffffffff


def pfctl(*args):
    return subprocess.check_output(['jexec', a.jail, 'pfctl', *args], text=True)


def exchange(forward, sport, seq, ack, flags, payload=b'', admitted=True):
    source, destination = (client, server) if forward else (server, client)
    tx, rx = (a.left, a.right) if forward else (a.right, a.left)
    mac = a.left_mac if forward else a.right_mac
    sport, dport = (sport, 42001) if forward else (42001, sport)
    tcp = TCP(sport=sport, dport=dport, seq=seq & mask, ack=ack & mask,
              flags=flags, window=4096)
    packet = Ether(src=get_if_hwaddr(tx), dst=mac) / layer(src=source, dst=destination) / tcp
    if payload:
        packet /= Raw(payload)

    def matches(candidate):
        return (candidate.haslayer(layer) and candidate.haslayer(TCP)
                and candidate[layer].src == source and candidate[layer].dst == destination
                and candidate[TCP].sport == sport and candidate[TCP].dport == dport
                and candidate[TCP].seq == tcp.seq and candidate[TCP].ack == tcp.ack
                and int(candidate[TCP].flags) == int(tcp.flags)
                and bytes(candidate[TCP].payload) == payload)

    ready = threading.Event()
    captured = threading.Event()
    # Start the observation window after injection. A fixed sniffer timeout
    # can expire while sendp opens its BPF socket on a busy test machine.
    sniffer = AsyncSniffer(iface=rx, lfilter=matches,
                          prn=lambda packet: captured.set(),
                          started_callback=ready.set)
    sniffer.start()
    try:
        assert ready.wait(20), 'capture did not become ready'
        sendp(packet, iface=tx, verbose=False)
        captured.wait(10 if admitted else 3)
        sniffer.stop()
        count = len(sniffer.results)
        assert count == (1 if admitted else 0), (
            f'{source}:{sport} flags={flags} seq={seq & mask} ack={ack & mask}: '
            f'forwarded {count}, expected {int(admitted)}')
    finally:
        if sniffer.running:
            sniffer.stop()


def assert_established(sport):
    states = pfctl('-ss')
    endpoint = client + (f':{sport}' if a.family == 'inet' else f'[{sport}]')
    selected = [line for line in states.splitlines() if endpoint in line]
    assert len(selected) == 1 and 'ESTABLISHED:ESTABLISHED' in selected[0], states


# Separate states prevent one accepted reset from influencing another case.
for index, variant in enumerate(['zero', 'wrong', 'correct', 'no_ack', 'exact_zero', 'wrap_zero']):
    pfctl('-F', 'states')
    sport = 43000 + index
    cseq = 0xfffffffa if variant == 'wrap_zero' else 0x10203040
    sseq = 0x50607080
    exchange(True, sport, cseq, 0, 'S')
    exchange(False, sport, sseq, cseq + 1, 'SA')
    cseq, sseq = (cseq + 1) & mask, (sseq + 1) & mask
    exchange(True, sport, cseq, sseq, 'A')
    if variant == 'wrap_zero':
        exchange(True, sport, cseq, sseq, 'PA', b'wraptest')
        cseq = (cseq + 8) & mask
        exchange(False, sport, sseq, cseq, 'A')
    assert_established(sport)
    reset_seq = cseq if variant == 'exact_zero' else (cseq - 10) & mask
    reset_ack = sseq if variant == 'correct' else ((sseq + 7) & mask if variant == 'wrong' else 0)
    admitted = variant in ['correct', 'exact_zero']
    exchange(True, sport, reset_seq, reset_ack,
             'R' if variant == 'no_ack' else 'RA', admitted=admitted)
    if not admitted:
        assert_established(sport)
        exchange(True, sport, cseq, sseq, 'PA', b'alive')
        exchange(False, sport, sseq, cseq + 5, 'A')
        assert_established(sport)
    print('ORIGINAL_ACK_CASE', a.family, variant, 'passed', flush=True)
