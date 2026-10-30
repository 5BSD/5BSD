# SPDX-License-Identifier: BSD-2-Clause
"""Select programs from the effective bsd.progs.mk inventory."""
import shlex


def selections(metadata):
    programs = shlex.split(metadata['PROGS'])
    cxx = shlex.split(metadata['PROGS_CXX'])
    if len(programs) != len(set(programs)) or len(cxx) != len(set(cxx)):
        raise ValueError('duplicate program inventory')
    if not set(cxx) <= set(programs):
        raise ValueError('C++ program absent from effective PROGS inventory')
    return [(name, ['PROG=' + name] + (['PROG_CXX=' + name] if name in cxx else []))
            for name in programs]
