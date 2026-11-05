# SPDX-License-Identifier: BSD-2-Clause
"""NIS program construction and original package installation."""
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")
load("//tools/build/bazel:bsd_rpcgen.bzl", "bsd_rpcgen")
load("//tools/build/bazel:bsd_filter.bzl", "bsd_filter")

def nis_rpc(name, schema, output, mode, flags = [], state = ""):
    bsd_rpcgen(name = name + "_raw" if state else name, source = schema,
        output = output + ".raw" if state else output, mode = mode, flags = flags,
        output_to_stdout = bool(state), cpp_flags = ["-E", "-x", "c", "-nostdinc"],
        rpcgen = "//usr.bin/rpcgen:rpcgen", cpp = "@bsd_sdk//toolchain:bin/cpp",
        compiler_inputs = "@bsd_sdk//toolchain:compile_inputs", runtime = ["@bsd_sdk//toolchain:cpp_runtime"])
    if state:
        # The maintained Make rules expose one shared server state variable.
        bsd_filter(name = name, src = ":" + name + "_raw", output = output,
            tool = "@bsd_sdk//toolchain:sed", arguments = [state],
            runtime = ["@bsd_sdk//toolchain:sed_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")

def nis_program(name, srcs, deps = [], shared = [], defines = [], copts = [], manual = "", extra_entries = [], extra_manifests = [], directories = {}):
    cc_binary(name = name, srcs = srcs,
        deps = deps + ["//lib/libc:shared_abi_interface", "//lib/libc/yp:protocol_headers", "//include/rpcsvc:nis_client_headers"],
        dynamic_deps = shared,
        local_defines = defines, copts = ["-fPIE"] + copts, linkopts = ["-nodefaultlibs", "-pie"], linkstatic = True,
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + select({
            "//tools/build/bazel/config:nis_enabled": [], "//conditions:default": ["@platforms//:incompatible"]}), visibility = ["//visibility:public"])
    utility_installation(name = "install_manifest", program = name, manual = manual,
        package = "yp", bindir = "/usr/sbin", man_section = "8", extra_entries = extra_entries)
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"] + extra_manifests,
        directories = {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=yp","dbg"]}' for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/sbin"]} | directories,
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.var.dist": "/var", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])
