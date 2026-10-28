# SPDX-License-Identifier: BSD-2-Clause
"""Sources rebuilt with rtld's private namespace, not ordinary libc objects."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load(":policy.bzl", "RTLD_COPTS", "RTLD_DEFINES", "RTLD_PLATFORM")
RTLD_LIBC_SOURCES = {
    "lib/libc/gen": [
        "fdopendir", "opendir", "opendir2", "closedir",
        "readdir", "telldir", "errlst", "getcwd",
        "getprogname", "raise", "sigsetops", "sysctlnametomib",
        "__xuname",
    ],
    "lib/libc/stdlib": [
        "reallocf", "realpath", "merge", "reallocarray",
    ],
    "lib/libc/string": [
        "bcopy", "bzero", "memchr", "memcmp",
        "memcpy", "memmove", "memset", "strcat",
        "strchr", "strchrnul", "strcmp", "strcpy",
        "strcspn", "strdup", "strlcat", "strlcpy",
        "strlen", "strncmp", "strncpy", "strrchr",
        "strsep", "strspn", "strstr", "strtok",
    ],
    "libexec/rtld-elf/rtld-libc": [
        "rtld_libc",
    ],
}
_SOURCE_WARNINGS = {
    "merge": ["-Wno-error=null-pointer-arithmetic"],
    "memchr": ["-Wno-cast-qual"], "strchr": ["-Wno-cast-qual"],
    "strchrnul": ["-Wno-cast-qual"], "strcspn": ["-Wno-sign-compare"],
    "strrchr": ["-Wno-cast-qual"], "strspn": ["-Wno-sign-compare"],
    "strstr": ["-Wno-cast-qual", "-Wno-sign-compare"], "strtok": ["-Wno-cast-qual"],
}
_TEXTUAL_SOURCES = {
    "bzero": ["//lib/libc/string:rtld_source_memset"],
    "memcpy": ["//lib/libc/string:rtld_source_bcopy"],
    "memmove": ["//lib/libc/string:rtld_source_bcopy"],
}
RTLD_LIBC_GROUPS = [":rtld_libc_" + name for names in RTLD_LIBC_SOURCES.values() for name in names]

def rtld_libc_source_exports(package):
    for name in RTLD_LIBC_SOURCES[package]:
        native.filegroup(name = "rtld_source_" + name, srcs = [name + ".c"],
            visibility = ["//libexec/rtld-elf:__pkg__"])

def rtld_libc_objects():
    for package, names in RTLD_LIBC_SOURCES.items():
        for name in names:
            cc_library(name = "rtld_libc_" + name,
                srcs = ["//" + package + ":rtld_source_" + name],
                textual_hdrs = _TEXTUAL_SOURCES.get(name, []),
                implementation_deps = [":core_headers", "//lib/libc/gen:rtld_directory_headers"] +
                    (["//lib/libc/include:rtld_errlst_header"] if name == "errlst" else []),
                local_defines = RTLD_DEFINES, copts = RTLD_COPTS + _SOURCE_WARNINGS.get(name, []),
                features = ["-bsd_ssp"], target_compatible_with = RTLD_PLATFORM)
