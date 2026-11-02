# SPDX-License-Identifier: BSD-2-Clause
"""Reconcile explicit linker order with the complete declared object inventory."""


def ordered_objects(files, names):
    if not names:
        return files
    if len(names) != len(depset(names).to_list()):
        fail("duplicate name in explicit object order")
    if any([not name or name in [".", ".."] or "/" in name or "\\" in name for name in names]):
        fail("explicit object order requires basenames")
    indexed = {}
    for file in files:
        if file.basename in indexed:
            fail("ambiguous object basename: " + file.basename)
        indexed[file.basename] = file
    if sorted(indexed) != sorted(names):
        fail("explicit object order must cover the complete object inventory")
    return [indexed[name] for name in names]
