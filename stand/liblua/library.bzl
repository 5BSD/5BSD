# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned Lua groups shared by standalone and private EFI contexts."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_archive")

_SOURCES = ['//contrib/lua/src:lapi.c', '//contrib/lua/src:lcode.c', '//contrib/lua/src:lctype.c', '//contrib/lua/src:ldebug.c', '//contrib/lua/src:ldo.c', '//contrib/lua/src:ldump.c', '//contrib/lua/src:lfunc.c', '//contrib/lua/src:lgc.c', '//contrib/lua/src:llex.c', '//contrib/lua/src:lmem.c', '//contrib/lua/src:lobject.c', '//contrib/lua/src:lopcodes.c', '//contrib/lua/src:lparser.c', '//contrib/lua/src:lstate.c', '//contrib/lua/src:lstring.c', '//contrib/lua/src:ltable.c', '//contrib/lua/src:ltm.c', '//contrib/lua/src:lundump.c', '//contrib/lua/src:lvm.c', '//contrib/lua/src:lzio.c', '//contrib/lua/src:lauxlib.c', '//contrib/lua/src:lbaselib.c', '//contrib/lua/src:lstrlib.c', '//contrib/lua/src:loadlib.c', 'lerrno.c', 'lpager.c', 'lstd.c', 'lutils.c', 'gfx_utils.c', '//libexec/flua/lfs:lfs.c', '//libexec/flua/libhash:lhash.c']
_HEADERS = ["locale.h", "lstd.h", "luaconf.local.h", "float.h", "lerrno.h", "lutils.h", "math.h"]

def loader_lua_library(name, prefix, copts, deps, features, compatible):
    groups = []
    for group, selected, extra, headers in [
        ("core", [s for s in _SOURCES if s not in ["gfx_utils.c", "//libexec/flua/libhash:lhash.c"]], [], ["//libexec/flua/lfs:lfs.h"]),
        ("gfx_utils", ["gfx_utils.c"], ["-Isys/teken", "-Icontrib/pnglite"], []),
        ("lhash", ["//libexec/flua/libhash:lhash.c"], ["-Ilibexec/flua/libhash", "-Isys/crypto/sha2"], ["//libexec/flua/libhash:lhash.h"]),
    ]:
        label = prefix + group
        cc_library(name = label, srcs = selected, hdrs = _HEADERS + headers,
            copts = copts + extra, deps = deps, features = features,
            linkstatic = True, target_compatible_with = compatible)
        groups.append(":" + label)
    bsd_component_archive(name = name, groups = groups,
        object_order = [s.rsplit(":", 1)[-1].rsplit("/", 1)[-1][:-2] + ".o" for s in _SOURCES],
        visibility = ["//visibility:public"])
