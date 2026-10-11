#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Run the imported OpenBSD PF regress suites against a DUT guest.

The upstream Makefiles run unchanged through OpenBSD's bsd.regress.mk
(REGRESS_LOG gives one SUCCESS/FAIL/SKIP line per target).  Only plumbing
variables (machine roles, interfaces, addresses, ssh targets) are supplied.
Local suites run on the DUT itself; multi-host suites run on the OpenBSD
helper (SRC/LOCAL role) and reach the DUT through PF_SSH/REMOTE_SSH.

Results: OUT/results.json plus per-suite console output and REGRESS_LOG.
"""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import time

HERE = Path(__file__).resolve().parent
TREE = HERE.parents[3] / 'contrib/openbsd-pf/regress'
SSHCFG = '/usr/obj/5BSD-pf-parity/keys/ssh_config'
GUEST_SRC = '/usr/src'          # upstream layout: /usr/src/regress/...
DUT_ADDR = '10.188.210.50'
SRC_ADDR = '10.188.210.10'
P6 = 'fdd7:e83e:66bc'


def mkvars(name, field):
    """Collect `NAME=`/`NAME+=` word lists from an upstream Makefile."""
    words = []
    for line in field.splitlines():
        m = re.match(r'^%s\s*\+?=\s*(.*)$' % name, line)
        if m:
            words += m.group(1).split()
    return words


def pfctl_targets():
    mk = (TREE / 'sbin/pfctl/Makefile').read_text()
    v = {n: mkvars(n, mk) for n in ['PFTESTS', 'PFFAIL', 'PFSIMPLE', 'PFSETUP',
         'PFLOAD', 'PFTABLE', 'PFOPT', 'PFIF2IP', 'PFCHKSUM', 'PFCMD',
         'PFCMDFAIL', 'PFLOADANCHORS']}
    t = ['pf-include-setup']
    t += ['pf%s' % n for n in v['PFTESTS']]
    t += ['selfpf%s' % n for n in v['PFTESTS']]
    t += ['pfail%s' % n for n in v['PFFAIL']]
    t += ['pfsimple%s' % n for n in v['PFSIMPLE']]
    t += ['pfload%s' % n for n in v['PFLOAD']]
    t += ['pfoptimize%s' % n for n in v['PFLOAD']]
    t += ['pfr%s' % n for n in v['PFTABLE']]
    t += ['pfi%s' % n for n in v['PFIF2IP']]
    t += ['pfopt%s' % n for n in v['PFOPT']]
    t += ['pfcmd%s' % n for n in v['PFCMD']]
    t += ['pfcmdfail%s' % n for n in v['PFCMDFAIL']]
    t += ['pfsetup%s' % n for n in v['PFSETUP']]
    t += ['pfchksum%s' % n for n in v['PFCHKSUM']]
    t += ['pf-loadanchors-setup']
    t += ['pfloadanchors%s' % n for n in v['PFLOADANCHORS']]
    t += ['pf-changerule']
    return t


SETUP_TARGETS = {'pf-include-setup', 'pf-loadanchors-setup'}


def suites(dut_os):
    ifin, ifout = ('vio1', 'vio2') if dut_os == 'openbsd' else ('vtnet1', 'vtnet2')
    pf_ssh = 'root@' + DUT_ADDR
    four = {'SRC_IF': 'vio1', 'PF_IFIN': ifin, 'PF_IFOUT': ifout,
            'PF_SSH': pf_ssh, 'RT_SSH': 'rt-in-rdomain-2', 'ECO_SSH': 'eco-in-rdomain-3'}
    two = {'LOCAL_IF': 'vio1', 'LOCAL_ADDR': SRC_ADDR, 'REMOTE_ADDR': DUT_ADDR,
           'LOCAL_ADDR6': P6 + ':210:fce1:baff:fed1:561f',
           'REMOTE_ADDR6': P6 + ':210:5054:ff:fe12:3450',
           'REMOTE_SSH': pf_ssh}
    sec = dict(two, LOCAL_MAC='fe:e1:ba:d1:0a:dc', REMOTE_MAC='52:54:00:12:34:50')
    return {
        'pfctl': dict(host='dut', dir='regress/sbin/pfctl', targets=pfctl_targets(), timeout=28800),
        'pf_table': dict(host='dut', dir='regress/sys/net/pf_table'),
        'pf_trans': dict(host='dut', dir='regress/sys/net/pf_trans',
                         vars={'TIMEOUT': '60'}),  # max allowed; TCG guests fork slowly
        'pf_print': dict(host='dut', dir='regress/sys/net/pf_print'),
        'pf_policy': dict(host='dut', dir='regress/sys/net/pf_policy',
                          vars={'REMOTE_ADDR': SRC_ADDR}),
        'pf_opts': dict(host='dut', dir='regress/sys/net/pf_opts'),
        'pflog': dict(host='dut', dir='regress/sys/net/pflog'),
        'pflow': dict(host='dut', dir='regress/sys/net/pflow'),
        'pf_forward': dict(host='helper', dir='regress/sys/net/pf_forward', vars=four, timeout=28800),
        'pf_fragment': dict(host='helper', dir='regress/sys/net/pf_fragment', vars=four, timeout=28800),
        'pf_state': dict(host='helper', dir='regress/sys/net/pf_state', vars=dict(two,
                         FAKE_NET='10.188.219.0/24', FAKE_NET_ADDR='10.188.219.188',
                         FAKE_NET6=P6 + ':219::/64', FAKE_NET_ADDR6=P6 + ':219::188')),
        'pf_divert': dict(host='helper', dir='regress/sys/net/pf_divert', vars=dict(two,
                          FAKE_ADDR='10.188.222.188', FAKE_ADDR6=P6 + ':222::188'),
                          timeout=28800),
        # Secondary tier: IP-stack suites that use pf as a tool.
        'frag': dict(tier=2, host='helper', dir='regress/sys/netinet/frag', vars=sec),
        'frag6': dict(tier=2, host='helper', dir='regress/sys/netinet6/frag6', vars=sec),
        'rh0': dict(tier=2, host='helper', dir='regress/sys/netinet6/rh0', vars=dict(sec,
                    OTHER_ADDR6=P6 + ':211:5054:ff:fe12:3450',
                    OTHER_FAKE1_ADDR6=P6 + ':211::dead', OTHER_FAKE2_ADDR6=P6 + ':211::beef')),
        'tcpstate': dict(tier=2, host='helper', dir='regress/sys/netinet/tcpstate', vars=dict(sec,
                         FAKE_NET='10.188.219.0/24', FAKE_NET_ADDR='10.188.219.188')),
        'pmtu': dict(tier=2, host='helper', dir='regress/sys/netinet/pmtu', vars=dict(sec,
                     FAKE_NET='10.188.219.0/24', FAKE_NET_ADDR='10.188.219.188',
                     FAKE_NET6=P6 + ':219::/64', FAKE_NET_ADDR6=P6 + ':219::188')),
        'pair': dict(tier=2, host='dut', dir='regress/sys/net/pair'),
    }


def ssh(host, command, timeout, out=None):
    cmd = ['ssh', '-F', SSHCFG, host, command]
    o = open(out, 'wb') if out else subprocess.DEVNULL
    try:
        return subprocess.run(cmd, stdout=o, stderr=subprocess.STDOUT,
                              timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        return 124
    finally:
        if out:
            o.close()


def run_suite(name, s, out, hosts, make):
    host = hosts[s['host']]
    log = '/tmp/regress-%s.log' % name
    vars_ = dict(s.get('vars', {}))
    words = ['REGRESS_LOG=' + log, 'REGRESS_FAIL_EARLY=no']
    if 'targets' in s:
        words.append('REGRESS_TARGETS=' + ' '.join(s['targets']))
    words += ['%s=%s' % kv for kv in vars_.items()]
    # Plumbing: some suites flush the main ruleset (pfchksum uses -Fa), so
    # restore the DUT's baseline pf.conf ("pass; anchor regress") first.
    ssh(hosts['dut'], 'pfctl -a "regress/*" -Fa >/dev/null 2>&1; pfctl -Fa >/dev/null 2>&1; '
        'pfctl -f /etc/pf.conf && pfctl -e >/dev/null 2>&1; true', 300)
    command = 'rm -f %s; touch %s; cd %s/%s && %s %s regress; echo REGRESS_EXIT $?' % (
        log, log, GUEST_SRC, s['dir'], make, ' '.join(shlex.quote(w) for w in words))
    started = time.time()
    rc = ssh(host, command, s.get('timeout', 14400), out / (name + '.out'))
    subprocess.run(['ssh', '-F', SSHCFG, host, 'cat ' + log],
                   stdout=open(out / (name + '.regress.log'), 'wb'), timeout=600)
    results = {}
    for line in (out / (name + '.regress.log')).read_text(errors='replace').splitlines():
        m = re.match(r'^(SUCCESS|FAIL|SKIP|XFAIL|XPASS) \S*/([^/\s]+)$', line)
        if m:
            results[m.group(2)] = m.group(1)
    for t in s.get('targets', []):
        if t not in SETUP_TARGETS and t not in results:
            results[t] = 'NOT_RUN'
    for t in SETUP_TARGETS:
        results.pop(t, None)
    text = (out / (name + '.out')).read_text(errors='replace')
    suite_skip = 'SKIPPED' in text and not results
    return {'rc': rc, 'seconds': round(time.time() - started), 'suite_skipped': suite_skip,
            'targets': results}


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('dut_os', choices=['openbsd', '5bsd'])
    p.add_argument('out', type=Path)
    p.add_argument('--suite', action='append')
    p.add_argument('--dut', default='dut')
    p.add_argument('--helper', default='helper')
    p.add_argument('--make', default='make',
                   help='make invocation on the DUT for local suites')
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    all_s = suites(a.dut_os)
    names = a.suite or [n for n, x in all_s.items() if x.get('tier', 1) == 1]
    resfile = a.out / 'results.json'
    res = json.loads(resfile.read_text()) if resfile.exists() else {}
    for name in names:
        s = all_s[name]
        make = a.make if s['host'] == 'dut' else 'make'
        print('==> %s on %s' % (name, s['host']), flush=True)
        res[name] = run_suite(name, s, a.out, {'dut': a.dut, 'helper': a.helper}, make)
        c = {}
        for v in res[name]['targets'].values():
            c[v] = c.get(v, 0) + 1
        print('    %s rc=%s %ss skipped=%s' % (c, res[name]['rc'], res[name]['seconds'],
                                             res[name]['suite_skipped']), flush=True)
        resfile.write_text(json.dumps(res, indent=1, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
