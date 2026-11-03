# SPDX-License-Identifier: BSD-2-Clause
"""One source inventory; independently compiled standalone and EFI Ficl contexts."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_archive")

_SOURCES = ["dict.c", "ficl.c", "fileaccess.c", "float.c", "loader.c", "math64.c",
    "prefix.c", "search.c", "stack.c", "tools.c", "vm.c", "words.c"]
_HEADERS = ["ficl.h", "math64.h"] + select({
    "@platforms//cpu:x86_64": ["amd64/sysdep.h"],
    "@platforms//cpu:aarch64": ["aarch64/sysdep.h"],
    "@platforms//cpu:riscv64": ["riscv/sysdep.h"], "//conditions:default": [],
})

def loader_ficl_library(name, prefix, copts, deps, features, compatible):
    cc_library(name = prefix + "core", srcs = _SOURCES + [":softcore_source"] + select({
        "@platforms//cpu:x86_64": ["amd64/sysdep.c"],
        "@platforms//cpu:aarch64": ["aarch64/sysdep.c"],
        "@platforms//cpu:riscv64": ["riscv/sysdep.c"], "//conditions:default": [],
    }), hdrs = _HEADERS, textual_hdrs = select({"@platforms//cpu:x86_64": ["x86/sysdep.c"], "//conditions:default": []}),
        copts = copts, deps = deps, features = features,
        linkstatic = True, target_compatible_with = compatible)
    cc_library(name = prefix + "gfx", srcs = ["gfx_loader.c"], hdrs = _HEADERS,
        copts = copts + ["-Isys/teken", "-Icontrib/pnglite"],
        deps = deps, features = features, linkstatic = True, target_compatible_with = compatible)
    bsd_component_archive(name = name, groups = [":" + prefix + "core", ":" + prefix + "gfx"],
        object_order = [source[:-2] + ".o" for source in _SOURCES] + ["gfx_loader.o", "sysdep.o", "softcore.o"],
        visibility = ["//visibility:public"])
