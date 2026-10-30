#!/usr/bin/env python3.12
# SPDX-License-Identifier: BSD-2-Clause
"""Compute the trimmed 5BSD import trees for protobuf, abseil-cpp, nghttp2
and opentelemetry-proto from pristine upstream trees.

Keep sets: the upstream CMake source lists for the components base builds,
plus every file reachable through #include "..." from them (resolved against
each tree's include roots), plus licence/notice files and well-known .proto
files.  Writes the trees to OUT/<name> and the per-component source lists to
OUT/lists.json.
"""
import json, os, re, shutil, sys

SRC = sys.argv[1]   # directory with the extracted upstream trees
OUT = sys.argv[2]   # output directory
PB = os.path.join(SRC, "protobuf-29.6")
AB = os.path.join(SRC, "abseil-cpp-20250127.1")
NG = os.path.join(SRC, "nghttp2-1.70.0")
OP = os.path.join(SRC, "opentelemetry-proto-1.10.0")

INC_RE = re.compile(r'^\s*#\s*include\s*"([^"]+)"', re.M)


def cmake_lists(path):
    text = open(path).read()
    out = {}
    for m in re.finditer(r"set\(([\w-]+)\n(.*?)\n\)", text, re.S):
        items = [l.strip().replace("${protobuf_SOURCE_DIR}/", "")
                 for l in m.group(2).splitlines() if l.strip()]
        out[m.group(1)] = items
    return out


# Language generators protoc does not carry in base (C++ only; upb plugins).
PB_DROP_DIRS = tuple("src/google/protobuf/compiler/%s/" % d for d in
                     ("csharp", "java", "kotlin", "objectivec", "php",
                      "python", "ruby", "rust"))


def pb_filter(files):
    return [f for f in files if not f.startswith(PB_DROP_DIRS)
            and not f.startswith("upb_generator/common/names")
            or f.startswith("upb_generator/") and False]


def closure(root, seeds, roots, extra_roots=()):
    """Return the set of files (relative to root) reachable from seeds."""
    seen = set()
    todo = list(seeds)
    missing = set()
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        p = os.path.join(root, f)
        if not os.path.exists(p):
            missing.add(f)
            continue
        seen.add(f)
        try:
            text = open(p, errors="replace").read()
        except IsADirectoryError:
            continue
        for inc in INC_RE.findall(text):
            cands = [os.path.normpath(os.path.join(os.path.dirname(f), inc))]
            cands += [os.path.normpath(os.path.join(r, inc)) if r else inc
                      for r in roots]
            for c in cands:
                if os.path.exists(os.path.join(root, c)):
                    todo.append(c)
                    break
            else:
                # absl includes from protobuf are resolved in the abseil tree.
                for er, tag in extra_roots:
                    if os.path.exists(os.path.join(er, inc)):
                        extra_hits.setdefault(tag, set()).add(inc)
                        break
    return seen, missing


extra_hits = {}

# ---------------------------------------------------------------- protobuf
L = cmake_lists(os.path.join(PB, "src/file_lists.cmake"))
pb_lists = {
    "libprotobuf_lite": L["libprotobuf_lite_srcs"],
    "libprotobuf": L["libprotobuf_srcs"],
    "libprotoc": [f for f in L["libprotoc_srcs"]
                  if not f.startswith(PB_DROP_DIRS)
                  and not f.startswith("upb_generator/")],
    "libupb": L["libupb_srcs"],
    "protoc-gen-upb": L["protoc-gen-upb_srcs"],
    "protoc-gen-upb_minitable": L["protoc-gen-upb_minitable_srcs"],
    "protoc-gen-upbdefs": L["protoc-gen-upbdefs_srcs"],
}
pb_boot = [
    "upb/reflection/cmake/google/protobuf/descriptor.upb.h",
    "upb/reflection/cmake/google/protobuf/descriptor.upb_minitable.h",
    "upb/reflection/cmake/google/protobuf/descriptor.upb_minitable.c",
    "upb_generator/cmake/google/protobuf/compiler/plugin.upb.h",
    "upb_generator/cmake/google/protobuf/compiler/plugin.upb_minitable.h",
    "upb_generator/cmake/google/protobuf/compiler/plugin.upb_minitable.c",
]
utf8 = ["third_party/utf8_range/utf8_range.c",
        "third_party/utf8_range/utf8_range.h",
        "third_party/utf8_range/utf8_validity.cc",
        "third_party/utf8_range/utf8_validity.h"]
pb_hdrs = [f for f in L["libprotobuf_hdrs"] + L["libprotobuf_lite_hdrs"]
           + L["libupb_hdrs"] + L["libprotoc_hdrs"]
           if not f.startswith(PB_DROP_DIRS)
           and not f.startswith("upb_generator/")]
pb_protos = (L["wkt_protos_files"] + L["descriptor_proto_proto_srcs"]
             + L["plugin_proto_proto_srcs"]
             + L["cpp_features_proto_proto_srcs"])
seeds = set(sum(pb_lists.values(), [])) | set(pb_boot) | set(utf8) | \
    set(pb_hdrs) | set(pb_protos)
pb_roots = ["src", "", "third_party/utf8_range",
            "upb/reflection/cmake", "upb_generator/cmake"]
pb_keep, pb_missing = closure(PB, seeds, pb_roots, [(AB, "absl")])
pb_keep |= {"LICENSE", "README.md", "CONTRIBUTORS.txt", "version.json",
            "src/libprotobuf.map", "src/libprotobuf-lite.map",
            "third_party/utf8_range/LICENSE",
            "third_party/utf8_range/README.md"}
pb_lists["utf8_range"] = ["third_party/utf8_range/utf8_range.c"]
pb_lists["utf8_validity"] = ["third_party/utf8_range/utf8_validity.cc"]
pb_lists["protos"] = sorted(pb_protos)
pb_lists["headers"] = sorted(f for f in pb_keep if re.search(
    r"\.(h|hpp|inc)$", f))

# ------------------------------------------------------------------ abseil
dll = open(os.path.join(AB, "CMake/AbseilDll.cmake")).read()
m = re.search(r"set\(ABSL_INTERNAL_DLL_FILES\n(.*?)\n\)", dll, re.S)
ab_files = [l.strip().strip('"') for l in m.group(1).splitlines()
            if l.strip()]
ab_srcs = sorted(set("absl/" + f for f in ab_files if f.endswith(".cc")))
ab_seeds = set(ab_srcs) | {"absl/" + f for f in ab_files}
ab_seeds |= set(extra_hits.get("absl", ()))
ab_keep, ab_missing = closure(AB, ab_seeds, [""])
ab_keep |= {"LICENSE", "README.md", "AUTHORS", "FAQ.md", "UPGRADES.md"}
ab_lists = {"libabsl": ab_srcs,
            "headers": sorted(f for f in ab_keep
                              if re.search(r"\.(h|inc)$", f))}

# ----------------------------------------------------------------- nghttp2
ng_srcs = sorted("lib/" + f for f in os.listdir(os.path.join(NG, "lib"))
                 if f.endswith(".c"))
ng_seeds = set(ng_srcs) | {"lib/includes/nghttp2/nghttp2.h",
                           "lib/includes/nghttp2/nghttp2ver.h.in"}
ng_keep, ng_missing = closure(NG, ng_seeds, ["lib", "lib/includes"])
ng_keep |= {"COPYING", "README.rst", "AUTHORS", "ChangeLog",
            "lib/includes/nghttp2/nghttp2ver.h.in"}
ng_lists = {"libnghttp2": ng_srcs}

# ----------------------------------------------------- opentelemetry-proto
op_keep = set()
for dp, dn, fn in os.walk(OP):
    for f in fn:
        rel = os.path.relpath(os.path.join(dp, f), OP)
        if rel.endswith(".proto") or rel in ("LICENSE", "README.md",
                                              "CHANGELOG.md"):
            op_keep.add(rel)
op_lists = {"protos": sorted(f for f in op_keep if f.endswith(".proto"))}


def emit(name, src, keep):
    dst = os.path.join(OUT, name)
    if os.path.exists(dst):
        shutil.rmtree(dst)
    for f in sorted(keep):
        os.makedirs(os.path.dirname(os.path.join(dst, f)), exist_ok=True)
        shutil.copy2(os.path.join(src, f), os.path.join(dst, f))
    return len(keep)


report = {
    "protobuf": {"files": emit("protobuf", PB, pb_keep),
                 "missing": sorted(pb_missing), "lists": pb_lists},
    "abseil-cpp": {"files": emit("abseil-cpp", AB, ab_keep),
                   "missing": sorted(ab_missing), "lists": ab_lists},
    "nghttp2": {"files": emit("nghttp2", NG, ng_keep),
                "missing": sorted(ng_missing), "lists": ng_lists},
    "opentelemetry-proto": {"files": emit("opentelemetry-proto", OP,
                                          op_keep),
                            "missing": [], "lists": op_lists},
}
json.dump(report, open(os.path.join(OUT, "lists.json"), "w"), indent=1)
for k, v in report.items():
    print(k, v["files"], "missing:", v["missing"][:20])
