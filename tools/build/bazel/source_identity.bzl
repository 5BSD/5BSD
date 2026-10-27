# SPDX-License-Identifier: BSD-2-Clause
"""Bind configured source keys to declared files independently of package paths."""

def source_files(files, identities, description):
    by_path = {file.path: file for file in files}
    if len(by_path) != len(files):
        fail("duplicate declared " + description)
    if not identities:
        result = {file.short_path: file for file in files}
        if len(result) != len(files):
            fail("ambiguous default " + description + " identity")
        return result
    result = {}
    observed = {}
    for target, key in identities.items():
        artifacts = target[DefaultInfo].files.to_list()
        if len(artifacts) != 1:
            fail("one file required per " + description + " identity")
        file = artifacts[0]
        if not key or key in result:
            fail("unique nonempty " + description + " identities required")
        if file.path not in by_path or file.path in observed:
            fail(description + " identity does not select one declared file")
        observed[file.path] = True
        result[key] = file
    if len(observed) != len(by_path):
        fail(description + " identities must cover every declared file")
    return result
