# SPDX-License-Identifier: BSD-2-Clause
"""Analysis-time File selection for source-declared package inspection aliases."""

def inspection_paths(path, records):
    pending = path.split("/")
    aliases = {}
    for expansion in range(41):
        resolved = []
        expanded = False
        for index, component in enumerate(pending):
            if component in ["", "."]:
                continue
            if component == "..":
                if resolved:
                    resolved.pop()
                continue
            candidate = "/" + "/".join(resolved + [component])
            record = records.get(candidate)
            if record != None and record["type"] == "symlink":
                if expansion == 40:
                    fail("package inspection exceeds 40 symlinks: " + path)
                aliases[candidate] = True
                link = record["link"]
                pending = ([] if link.startswith("/") else resolved) + link.split("/") + pending[index + 1:]
                expanded = True
                break
            resolved.append(component)
        if not expanded:
            aliases["/" + "/".join(resolved)] = True
            return aliases.keys()
    fail("unreachable symlink traversal")
