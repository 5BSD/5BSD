# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:defs.bzl", "cc_library")

def zfs_objects(name, sources, flags, deps, platform):
    cc_library(name = name, srcs = sources, hdrs = ["//sys/modules/zfs:zfs_config.h"],
        implementation_deps = ["//cddl/compat/opensolaris/include:headers"],
        deps = deps + ["//sys/contrib/openzfs:zfs_headers"],
        local_defines = ["IN_BASE", "HAVE_ISSETUGID", "HAVE_EXECVPE", "NEED_SOLARIS_BOOLEAN", "HAVE_STRLCAT", "HAVE_STRLCPY",
            "HAVE_TOOLCHAIN_SSE2", "HAVE_TOOLCHAIN_SSSE3", "__x86_64", "HAVE_TOOLCHAIN_AVX2", "HAVE_TOOLCHAIN_AVX", "HAVE_TOOLCHAIN_AVX512F",
            'SYSCONFDIR=\\"/etc\\"', 'PKGDATADIR=\\"/usr/share/zfs\\"', 'ZFSEXECDIR=\\"/usr/libexec/zfs\\"'],
        copts = flags + ["-std=c99", "-include", "sys/contrib/openzfs/include/sys/simd_config.h", "-include", "sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h", "-include", "sys/modules/zfs/zfs_config.h"],
        linkopts = ["-pthread"], linkstatic = True, target_compatible_with = platform)
