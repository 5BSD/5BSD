# SPDX-License-Identifier: BSD-2-Clause
"""Native Citrus loadable modules, sharing the maintained SHLIB_MAJOR=5 ABI."""
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_shared_library")
load("//tools/build/bazel:bsd_program_test.bzl", "bsd_program_test")

load(":installation.bzl", "module_installation")

def citrus_module(name, src):
    cc_library(
        name = name + "_objects",
        srcs = [src],
        implementation_deps = [":headers", "//lib/libc/iconv:module_headers", "//lib/libc:shared_link_interface"],
        local_defines = ["bool=_Bool"],
        linkstatic = True,
    )
    cc_shared_library(
        name = name,
        deps = [":" + name + "_objects"],
        dynamic_deps = ["//lib/libc:c_shared", "//lib/libsys:sys_shared"],
        shared_lib_name = "lib" + name + ".so.5",
        user_link_flags = ["-nodefaultlibs", "-Wl,-soname,lib" + name + ".so.5"],
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + select({
            "//tools/build/bazel/config:iconv_enabled": [],
            "//conditions:default": ["@platforms//:incompatible"],
        }),
        visibility = ["//visibility:public"],
    )
    interface = "mapper" if name.startswith("mapper_") else ("iconv" if name.startswith("iconv_") else "stdenc")
    bsd_program_test(
        name = name + "_load_test",
        program = ":module_load_program",
        args = ["lib" + name + ".so.5", "_citrus_" + name + "_" + interface + "_getops"],
        runtime_lib = [":" + name, "//lib/libc:c_shared", "//lib/libsys:sys_shared"],
        runner = "//tools/build/bazel:program_test_runner",
        size = "small",
    )
    module_installation(name)
