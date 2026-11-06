# SPDX-License-Identifier: BSD-2-Clause
"""Kernel installation entries and configured directory policy; no host writes."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("//tools/build/bazel:bsd_install.bzl", "BsdInstallManifestInfo", "bsd_install_file", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")


def kernel_installation_directory(value, allow_empty = False):
    if type(value) != "string":
        fail("kernel directory setting must be a string")
    if not value:
        if allow_empty:
            return ""
        fail("kernel base directory must not be empty")
    value = value.rstrip("/") or "/"
    if not value.startswith("/") or (value != "/" and any([part in ["", ".", ".."] for part in value[1:].split("/")])):
        fail("kernel directory setting must be an absolute directory without traversal")
    return value


def _directories(ctx):
    base = kernel_installation_directory(ctx.attr.base[BuildSettingInfo].value)
    prefix = kernel_installation_directory(ctx.attr.debug_prefix[BuildSettingInfo].value, allow_empty = True)
    enabled = ctx.attr.debug[BuildSettingInfo].value
    if type(enabled) != "bool":
        fail("kernel debug setting must be boolean")
    tags = ["package=" + ctx.attr.package]
    directories = {base: tags}
    if enabled:
        debug = (prefix.rstrip("/") + base).rstrip("/") or "/"
        if debug not in directories:
            directories[debug] = tags + ["dbg"]
        directories[debug.rstrip("/") + "/gdb"] = tags + ["dbg"]
    records = [{"type": "dir", "destination": path, "owner": "root", "group": "wheel",
                "mode": "0755", "tags": directories[path], "flags": ""}
               for path in sorted(directories)]
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(output, json.encode({"format": 1, "files": records}) + "\n")
    return [DefaultInfo(files = depset([output])),
            OutputGroupInfo(manifest = depset([output])),
            BsdInstallManifestInfo(manifest = output, payload = depset(), records = records)]


_kernel_directories = rule(implementation = _directories, attrs = {
    "base": attr.label(providers = [BuildSettingInfo], mandatory = True),
    "debug_prefix": attr.label(providers = [BuildSettingInfo], mandatory = True),
    "debug": attr.label(providers = [BuildSettingInfo], mandatory = True),
    "package": attr.string(mandatory = True),
})


def kernel_installation(name, kernel, debug, package = "kernel", epoch = 0):
    """Install the Make kernel/debug/GDB family with declared configurable prefixes."""
    base = "//tools/build/bazel/config:kernel_base_directory"
    debug_prefix = "//tools/build/bazel/config:kernel_debug_directory"
    _kernel_directories(name = name + "_directories", base = base, debug_prefix = debug_prefix,
        debug = "//tools/build/bazel/config:kernel_debug", package = package)
    bsd_install_file(name = name + "_kernel", src = kernel, destination = "/kernel",
        destination_prefixes = [base], owner = "root", group = "wheel", mode = "0444",
        install_tags = ["package=" + package])
    bsd_install_file(name = name + "_debug", src = debug, destination = "/kernel.debug",
        destination_prefixes = [debug_prefix, base], owner = "root", group = "wheel", mode = "0444",
        install_tags = ["package=" + package, "dbg"])
    bsd_install_file(name = name + "_gdb_loader", src = "//sys/tools:kernel-gdb.py",
        destination = "/kernel-gdb.py", destination_prefixes = [debug_prefix, base],
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=" + package, "dbg"])
    # Original sys/conf/kern.post.mk GDB_FILES inventory; scripts remain unchanged.
    helpers = ["acttrace.py", "freebsd.py", "pcpu.py", "selftest.py", "vnet.py"]
    for helper in helpers:
        bsd_install_file(name = name + "_gdb_" + helper[:-3], src = "//sys/tools/gdb:" + helper,
            destination = "/gdb/" + helper, destination_prefixes = [debug_prefix, base],
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=" + package, "dbg"])
    bsd_install_manifest(name = name,
        entries = [":" + name + "_kernel"] + select({
            "//tools/build/bazel/config:kernel_debug_enabled": [":" + name + "_debug", ":" + name + "_gdb_loader"] +
                [":" + name + "_gdb_" + helper[:-3] for helper in helpers],
            "//conditions:default": [],
        }), manifests = [":" + name + "_directories"], visibility = ["//visibility:public"])
    native.filegroup(name = name + "_metadata", srcs = [":" + name], output_group = "manifest",
        visibility = ["//visibility:public"])
    bsd_install_archive(name = name + "_archive", manifests = [":" + name], epoch = epoch,
        supplemental_mtree_setting = "//tools/build/bazel/config:kernel_directory_policy",
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr",
                       "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree",
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = ["//visibility:public"])
