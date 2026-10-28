# SPDX-License-Identifier: BSD-2-Clause
def encoding_index_layout(encodings, families):
    expected = {stem: True for stem, _, _ in encodings}
    observed = {}
    rows = []
    for index, (directory, code, prefix, parts) in enumerate(families):
        rows.append("H\t" + code)
        for part in parts:
            canonical = prefix + part
            stem = directory + "/" + canonical.replace(":", "@")
            if stem in observed or stem not in expected:
                fail("duplicate or unbuilt encoding index member: " + stem)
            observed[stem] = True
            rows.append("\t".join(["E", canonical, stem + ".esdb", part, str(index)]))
    if len(observed) != len(expected):
        fail("encoding index omits generated databases")
    return rows
