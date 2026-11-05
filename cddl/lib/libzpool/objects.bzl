# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:defs.bzl", "cc_library")
def zpool_objects(name, srcs, deps, extra_copts = []):
    cc_library(name = name, srcs = srcs, hdrs = ["//sys/modules/zfs:zfs_config.h"],
        implementation_deps = ["//cddl/compat/opensolaris/include:headers"],
        deps = deps + ["//sys/modules/zfs:build_headers", "//sys/contrib/openzfs:zpool_build_headers"],
        local_defines = ["IN_BASE", "HAVE_ISSETUGID", "NEED_SOLARIS_BOOLEAN", "HAVE_STRLCAT", "HAVE_STRLCPY",
            "HAVE_TOOLCHAIN_SSE2", "HAVE_TOOLCHAIN_SSSE3", "__x86_64", "HAVE_TOOLCHAIN_AVX2", "HAVE_TOOLCHAIN_AVX", "HAVE_TOOLCHAIN_AVX512F", "HAVE_TOOLCHAIN_AVX512BW",
            "LIB_ZPOOL_BUILD", "ZFS_DEBUG", "XXH_INLINE_ALL", "WANTS_MUTEX_OWNED", "DEBUG=1"],
        copts = extra_copts + ["-std=c99", "-g", "-Wno-error=typedef-redefinition", "-include", "sys/contrib/openzfs/include/sys/simd_config.h", "-include", "sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h", "-include", "sys/modules/zfs/zfs_config.h"],
        linkopts = ["-pthread"], linkstatic = True,
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"])
