# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:defs.bzl", "cc_library")
def rescue_objects(name, srcs, assembly = False, extra_copts = []):
    cc_library(name = name, srcs = srcs, hdrs = ["//sys/modules/zfs:zfs_config.h"],
        deps = ["//sys/contrib/openzfs:icp_headers"],
        local_defines = ["IN_BASE", "HAVE_ISSETUGID", "NEED_SOLARIS_BOOLEAN", "HAVE_STRLCAT", "HAVE_STRLCPY", "__amd64", "_SYS_STACK_H", "RESCUE"] + (["LOCORE"] if assembly else []),
        copts = extra_copts + ["-UHAVE_AVX", "-include", "sys/contrib/openzfs/include/sys/simd_config.h", "-include", "sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h", "-include", "sys/modules/zfs/zfs_config.h"] + ([] if assembly else ["-std=c99"]),
        linkstatic = True, target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"])
