# SPDX-License-Identifier: BSD-2-Clause
"""Collect supported source-tree header inputs for declared include roots.

This is a conservative source snapshot, not compiler dependency discovery.
Extensionless files are included for standard C++ headers and private textual
headers. This may include non-header files in an include root; generated files
and textual includes with other suffixes still need explicit inputs.
"""
HEADER_SUFFIXES = frozenset(('.h', '.hh', '.hpp', '.hxx', '.inc', '.def', '.tcc', '.ipp'))


def collect(directory):
    return sorted(path for path in directory.rglob('*')
                  if path.is_file() and (not path.suffix or path.suffix in HEADER_SUFFIXES))
