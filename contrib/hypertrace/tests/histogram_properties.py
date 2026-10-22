# SPDX-License-Identifier: BSD-2-Clause
"""Seeded histogram models and metamorphic count transformations.

This models displayed bucket labels with exact rational arithmetic. It does not
call production helpers or reproduce distribution-bar rendering.
"""
from fractions import Fraction
import random
import struct

SEED = 0x5b5d2026

def build_cases():
    rng = random.Random(SEED)
    cases, groups = [], []
    for family in ('quantize', 'lquantize', 'llquantize'):
        for sample in range(32):
            header = b''
            params = {}
            if family == 'quantize':
                labels = [-(1 << p) for p in range(62,-1,-1)] + [0] + [1 << p for p in range(63)]
                empty = (62,65)
            elif family == 'lquantize':
                base, step, levels = rng.randrange(-100,101), rng.randrange(1,8), rng.randrange(1,21)
                params = dict(base=base, step=step, levels=levels)
                header = struct.pack('<Q',(step << 48) | (levels << 32) | (base & 0xffffffff))
                labels = ['< '+str(base)] + [base+i*step for i in range(levels)] + ['>= '+str(base+levels*step)]
                empty = (0,3)
            else:
                factor = rng.choice((2,3,4,5,10))
                low = rng.randrange(4); high = low + rng.randrange(1,4)
                steps = rng.choice((factor, factor**2, 20 if factor == 10 else factor))
                params = dict(factor=factor, low=low, high=high, steps=steps)
                header = struct.pack('<Q',(factor << 48) | (low << 32) | (high << 16) | steps)
                labels = ['< '+str(factor**low)]
                for order in range(low,high+1):
                    left, right = factor**order, factor**(order+1)
                    width = max(Fraction(1), Fraction(right,steps))
                    assert width.denominator == 1
                    labels.extend(range(left,right,int(width)))
                labels.append('>= '+str(factor**(high+1)))
                empty = (0,2)
            counts = [0]*len(labels)
            # Empty, endpoint-only, sparse, and dense signed populations.
            if sample % 8 == 1:
                counts[0] = 7
            elif sample % 8 == 2:
                counts[-1] = -9
            elif sample % 8 != 0:
                for i in range(len(counts)):
                    if sample % 8 == 3 or rng.randrange(4) == 0:
                        counts[i] = rng.randrange(-50,51)
            occupied = [i for i,count in enumerate(counts) if count]
            start, end = (max(0,min(occupied)-1),min(len(labels),max(occupied)+2)) if occupied else empty
            names = []
            for suffix, multiplier in (('base',1),('scale',3),('negate',-1)):
                name = family+'-property-'+str(sample)+'-'+suffix
                values = [count*multiplier for count in counts]
                expected = dict(zip(labels[start:end],values[start:end]))
                payload = header + struct.pack('<'+str(len(values))+'q',*values)
                cases.append((name,'%d',[payload],expected)); names.append(name)
            groups.append(dict(family=family, sample=sample, parameters=params,
                names=names, total=sum(counts), bucket_count=len(labels)))
    return cases, groups

def check_relations(results, groups):
    by_name = {r['case']:r for r in results}
    checks = []
    for group in groups:
        base, scaled, negated = [by_name[name]['parsed_output'] for name in group['names']]
        valid = all(isinstance(output,dict) for output in (base,scaled,negated))
        checks.append(dict(group=group, passed=valid and
            scaled == {k:3*v for k,v in base.items()} and
            negated == {k:-v for k,v in base.items()} and
            sum(base.values()) == group['total'] and
            sum(scaled.values()) == 3*group['total'] and
            sum(negated.values()) == -group['total']))
    return checks
