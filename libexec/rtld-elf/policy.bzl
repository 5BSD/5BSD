# SPDX-License-Identifier: BSD-2-Clause
"""Native amd64 runtime-linker compilation policy."""
RTLD_COPTS = ["-Wall", "-ffreestanding", "-mno-mmx", "-mno-sse", "-mno-avx", "-mno-avx2", "-msoft-float", "-fvisibility=hidden"]
RTLD_DEFINES = ["IN_RTLD", "_FORTIFY_SOURCE=0"] + select({
    "//tools/build/bazel/config:dtrace_enabled": ["WITH_COVERAGE_DTRACE"],
    "//conditions:default": [],
})
RTLD_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
