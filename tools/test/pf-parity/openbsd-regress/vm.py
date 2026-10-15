#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Start or stop the two disposable guests of the OpenBSD-regress topology.

Roles:
  dut     system under test (OpenBSD reference or 5BSD), PF_IFIN/PF_IFOUT
  helper  OpenBSD guest acting as SRC (rdomain 0), RT (rdomain 2) and
          ECO (rdomain 3); it runs the multi-host regress Makefiles

Each guest gets a control NIC (QEMU user networking, ssh forwarded to a
127.0.0.1 port only, no other host access) and two point-to-point test links
(QEMU dgram over unix sockets):  link A = SRC_IF <-> PF_IFIN,
link B = RT_IN <-> PF_IFOUT.  Guests use the patched QEMU only, 4 vCPUs.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

BASE = Path('/usr/obj/5BSD-pf-parity/vms')
QEMU = '/usr/obj/5bsd-qemu-fstt/qemu-system-x86_64-fstt-fixed'
SSH_PORT = {'dut': 2241, 'helper': 2242, 'dut2': 2243, 'rdom': 2251}
# MACs follow the upstream Makefile defaults where they matter (SRC_MAC/PF_MAC).
MACS = {
    'dut': ['52:54:00:12:34:40', '52:54:00:12:34:50', '52:54:00:12:34:51'],
    'helper': ['52:54:00:12:34:60', 'fe:e1:ba:d1:0a:dc', '52:54:00:12:34:61'],
    # second DUT for local-only suites while the helper is not running
    'dut2': ['52:54:00:12:34:70', '52:54:00:12:34:71', '52:54:00:12:34:72'],
    # local-only DUT of the routing domain (rdomain) series
    'rdom': ['52:54:00:12:34:80', '52:54:00:12:34:81', '52:54:00:12:34:82'],
}


def sock(role, link):
    return str(BASE / 'net' / ('%s-%s.sock' % (role, link)))


def start(a):
    (BASE / 'net').mkdir(parents=True, exist_ok=True)
    peer = {'dut': 'helper', 'helper': 'dut', 'dut2': 'none', 'rdom': 'none'}[a.role]
    disk = Path(a.disk).resolve()
    if not str(disk).startswith(('/usr/obj/5BSD-pf-parity/',
                                 '/usr/obj/5BSD-pf-rdomains-work/')):
        raise SystemExit('disk must be below /usr/obj/5BSD-pf-parity')
    for link in 'ab':
        try:
            os.unlink(sock(a.role, link))
        except FileNotFoundError:
            pass
    fmt = 'qcow2' if disk.suffix == '.qcow2' else 'raw'
    netuser = 'user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:%d-:22' % SSH_PORT[a.role]
    cmd = [QEMU, '-L', '/usr/local/share/qemu', '-accel', 'tcg,thread=multi',
           '-machine', 'q35', '-cpu', 'max', '-m', str(a.memory), '-smp', str(a.cpus),
           '-drive', 'file=%s,format=%s,if=virtio' % (disk, fmt),
           '-netdev', netuser,
           '-device', 'virtio-net-pci,netdev=n0,mac=' + MACS[a.role][0]]
    for i, link in enumerate('ab', 1):
        cmd += ['-netdev', 'dgram,id=l%s,local.type=unix,local.path=%s,'
                'remote.type=unix,remote.path=%s' % (link, sock(a.role, link), sock(peer, link)),
                '-device', 'virtio-net-pci,netdev=l%s,mac=%s' % (link, MACS[a.role][i])]
    serial = BASE / (a.role + '-serial.sock')
    cmd += ['-display', 'none', '-monitor', 'none',
            '-serial', 'unix:%s,server,nowait' % serial,
            '-qmp', 'unix:%s,server,nowait' % (BASE / (a.role + '-qmp.sock'))]
    if a.snapshot:
        cmd.append('-snapshot')
    log = open(BASE / (a.role + '-qemu.log'), 'ab')
    child = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log,
                             stderr=subprocess.STDOUT, start_new_session=True)
    (BASE / (a.role + '.json')).write_text(json.dumps(
        {'pid': child.pid, 'started': time.time(), 'command': cmd,
         'os': a.os, 'disk': str(disk)}, indent=2) + '\n')
    print(child.pid)


def stop(a):
    meta = BASE / (a.role + '.json')
    info = json.loads(meta.read_text())
    try:
        os.kill(info['pid'], signal.SIGTERM)
    except ProcessLookupError:
        pass
    meta.rename(meta.with_suffix('.stopped.json'))


p = argparse.ArgumentParser(description=__doc__,
                            formatter_class=argparse.RawDescriptionHelpFormatter)
sub = p.add_subparsers(dest='action', required=True)
s = sub.add_parser('start')
s.add_argument('role', choices=['dut', 'helper', 'dut2', 'rdom'])
s.add_argument('os', choices=['openbsd', '5bsd'])
s.add_argument('disk')
s.add_argument('--memory', type=int, default=2048)
s.add_argument('--snapshot', action='store_true')
s.add_argument('--cpus', type=int, default=2)
s.set_defaults(func=start)
t = sub.add_parser('stop')
t.add_argument('role', choices=['dut', 'helper', 'dut2', 'rdom'])
t.set_defaults(func=stop)
a = p.parse_args()
a.func(a)
