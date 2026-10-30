#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Emit the source/header list blocks of the 5BSD protobuf/abseil/nghttp2
Makefiles from pb-vendor/lists.json.  The blocks are pasted between
'# BEGIN generated' / '# END generated' markers so the rest of each
Makefile stays hand-written; rerun after an import update."""
import json, os, re, sys

lists = json.load(open(sys.argv[1]))
src = sys.argv[2]                       # tree root (worktree)


def wrap(var, items, op="+="):
    out = []
    for it in items:
        out.append("%s%s\t%s" % (var, op, it))
    return "\n".join(out)


def groups(prefix_var, root_strip, headers, incdir, group_prefix, pkg=None):
    """INCSGROUPS, one per directory, installing under incdir."""
    bydir = {}
    for h in headers:
        rel = h[len(root_strip):] if h.startswith(root_strip) else h
        bydir.setdefault(os.path.dirname(rel), []).append(rel)
    out, names = [], []
    for i, d in enumerate(sorted(bydir)):
        g = "%s%d" % (group_prefix, i)
        names.append(g)
        out.append("%sDIR=\t%s/%s" % (g, incdir, d) if d else
                   "%sDIR=\t%s" % (g, incdir))
        for h in sorted(bydir[d]):
            out.append("%s+=\t%s" % (g, h))
    return names, "\n".join(out), sorted(bydir)


def replace_block(path, text):
    body = open(path).read()
    new = re.sub(r"(# BEGIN generated[^\n]*\n).*?(# END generated)",
                 lambda m: m.group(1) + text + "\n" + m.group(2), body,
                 flags=re.S)
    open(path, "w").write(new)


pb = lists["protobuf"]["lists"]
ab = lists["abseil-cpp"]["lists"]
ng = lists["nghttp2"]["lists"]

# ----- abseil
ab_hdrs = ab["headers"]
names, text, dirs_ab = groups("", "", ab_hdrs, "${INCLUDEDIR}/private",
                              "ABSL_INC")
blk = wrap("SRCS", sorted(ab["libabsl"])) + "\n\nINCSGROUPS=\t" + \
    " ".join(names) + "\n" + text
replace_block(os.path.join(src, "lib/libabsl/Makefile"), blk)

# ----- protobuf runtime headers: installed are the runtime (lite + full)
# headers and the compiler headers protoc plugins use; not upb.
pb_hdrs = [h for h in pb["headers"] if h.startswith("src/google/protobuf/")
           and "/compiler/cpp/" not in h]
names, text, dirs_pb = groups("", "src/", pb_hdrs, "${INCLUDEDIR}/private",
                              "PB_INC")
protos = [p for p in pb["protos"]]
pnames, ptext, dirs_pp = groups("", "src/", protos, "${INCLUDEDIR}/private",
                                "PB_PROTO")
blk = wrap("SRCS", sorted(pb["libprotobuf"])) + "\n\nINCSGROUPS=\t" + \
    " ".join(names + pnames) + "\n" + text + "\n" + ptext
replace_block(os.path.join(src, "lib/protobuf/libprotobuf/Makefile"), blk)
replace_block(os.path.join(src, "lib/protobuf/libprotobuf-lite/Makefile"),
              wrap("SRCS", sorted(pb["libprotobuf_lite"])))
replace_block(os.path.join(src, "lib/protobuf/libprotoc/Makefile"),
              wrap("SRCS", sorted(pb["libprotoc"])))
replace_block(os.path.join(src, "lib/protobuf/libupb/Makefile"),
              wrap("SRCS", sorted(pb["libupb"])))
for g in ("protoc-gen-upb", "protoc-gen-upb_minitable",
          "protoc-gen-upbdefs"):
    replace_block(os.path.join(src, "libexec/%s/Makefile" % g),
                  wrap("SRCS", sorted(pb[g])))
replace_block(os.path.join(src, "lib/libnghttp2/Makefile"),
              wrap("SRCS", [s for s in ng["libnghttp2"]]))

# mtree directories for the installed private headers
mt = sorted(set(["absl/" + d[len("absl/"):] if d.startswith("absl/") else d
                 for d in dirs_ab] + dirs_pb + dirs_pp))
json.dump(mt, open(os.path.join(os.path.dirname(sys.argv[1]),
                                "incdirs.json"), "w"), indent=1)
print("\n".join(mt))
