# SPDX-License-Identifier: BSD-2-Clause
"""Architecture-selected freestanding runtime-linker compilation policy."""
RTLD_COPTS = ["-Wall", "-ffreestanding"] + select({
    "@platforms//cpu:x86_64": ["-mno-mmx", "-mno-sse", "-mno-avx", "-mno-avx2", "-msoft-float", "-fvisibility=hidden"],
    "//conditions:default": [],
})
RTLD_DEFINES = ["IN_RTLD", "_FORTIFY_SOURCE=0"] + select({
    "//tools/build/bazel/config:dtrace_enabled": ["WITH_COVERAGE_DTRACE"],
    "//conditions:default": [],
})
RTLD_PLATFORM = ["@platforms//os:freebsd"] + select({
    "@platforms//cpu:x86_64": [],
    "@platforms//cpu:aarch64": [],
    "//conditions:default": ["@platforms//:incompatible"],
})
