#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare OpenBSD-regress results of the reference and a 5BSD DUT run.

usage: report.py REFERENCE_DIR CANDIDATE_DIR [--json OUT]
Prints per-suite totals and lists of candidate failures for targets that
pass on the reference.  With --json, also writes a machine-readable summary
including each failing target's console excerpt (from SUITE.out).
"""
import argparse
import json
from pathlib import Path
import re


def load(d):
    return json.loads((Path(d) / 'results.json').read_text())


def excerpts(d, suite):
    """Map target -> console text between its ==== markers."""
    p = Path(d) / (suite + '.out')
    if not p.exists():
        return {}
    out, cur, buf = {}, None, []
    for line in p.read_text(errors='replace').splitlines():
        m = re.match(r'^==== (\S+) ====$', line)
        if m:
            if cur:
                out[cur] = '\n'.join(buf)
            cur, buf = m.group(1).replace('run-regress-', ''), []
        else:
            buf.append(line)
    if cur:
        out[cur] = '\n'.join(buf)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('reference')
    p.add_argument('candidate')
    p.add_argument('--json', type=Path)
    a = p.parse_args()
    ref, cand = load(a.reference), load(a.candidate)
    summary = {}
    tot = {'targets': 0, 'ref_pass': 0, 'cand_pass': 0}
    print('%-12s %6s %8s %8s %8s %8s' % ('suite', 'total', 'ref_ok', 'ref_bad', '5bsd_ok', '5bsd_bad'))
    for suite in sorted(set(ref) | set(cand)):
        r = ref.get(suite, {}).get('targets', {})
        c = cand.get(suite, {}).get('targets', {})
        names = sorted(set(r) | set(c))
        rok = [t for t in names if r.get(t) == 'SUCCESS']
        cok = [t for t in names if c.get(t) == 'SUCCESS']
        fails = [t for t in names if r.get(t) == 'SUCCESS' and c.get(t) != 'SUCCESS']
        ex = excerpts(a.candidate, suite)
        summary[suite] = {
            'total': len(names), 'reference_pass': len(rok), 'candidate_pass': len(cok),
            'reference_not_pass': {t: r.get(t, 'MISSING') for t in names if r.get(t) != 'SUCCESS'},
            'candidate_fail': {t: {'status': c.get(t, 'MISSING'), 'excerpt': ex.get(t, '')[-4000:]}
                               for t in fails},
            'reference_suite_skipped': ref.get(suite, {}).get('suite_skipped'),
            'candidate_suite_skipped': cand.get(suite, {}).get('suite_skipped'),
        }
        print('%-12s %6d %8d %8d %8d %8d' % (suite, len(names), len(rok), len(names) - len(rok),
                                             len(cok), len(names) - len(cok)))
        tot['targets'] += len(names)
        tot['ref_pass'] += len(rok)
        tot['cand_pass'] += len(cok)
    print('%-12s %6d %8d %8s %8d' % ('TOTAL', tot['targets'], tot['ref_pass'], '', tot['cand_pass']))
    if a.json:
        a.json.write_text(json.dumps({'totals': tot, 'suites': summary}, indent=1) + '\n')


if __name__ == '__main__':
    main()
