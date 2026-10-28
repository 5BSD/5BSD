# SPDX-License-Identifier: BSD-2-Clause
"""Extract target layout/constants without executing target code.

Callers compile objects with the kernel's configuration and -fcommon, and must
supply the offset-layout check object as a prerequisite of assembly constants.
"""
load(":bsd_script_output.bzl", "bsd_script_output")

def kernel_constants(name, object, kind, output, prerequisites = [], **kwargs):
    if kind not in ["assym", "offset"]:
        fail("kernel constant kind must be assym or offset")
    tools = {"@bsd_sdk//toolchain:bin/llvm-nm": "nm"}
    libraries = ["@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"]
    if kind == "assym":
        tools["//usr.bin/awk:awk"] = "awk"
        libraries.append("//lib/msun:m_shared")
    else:
        tools.update({"//usr.bin/grep:grep": "grep", "//usr.bin/sed:sed": "sed", "//usr.bin/sort:sort": "sort"})
        libraries += ["//lib/libregex:regex_shared", "//lib/libmd:md_shared", "@bsd_sdk//toolchain:sysroot/lib/libthr.so.3"]
    defaults = {
        "shell": "@bsd_sdk//toolchain:sh",
        "redirect": "@bsd_sdk//toolchain:stdout_redirect",
        "runtime": ["@bsd_sdk//toolchain:sh_runtime", "@bsd_sdk//toolchain:llvm-nm_runtime"],
        "runtime_libraries": libraries,
        "path_tools": tools,
    }
    defaults.update(kwargs)
    bsd_script_output(name = name, src = object, input_mode = "argument",
        script = "//sys/kern:gen" + kind + ".sh", output = output,
        inputs = prerequisites, **defaults)
