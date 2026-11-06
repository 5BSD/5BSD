# SPDX-License-Identifier: BSD-2-Clause
"""Compose base-kernel installation from typed, layout-independent module files."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load(":bsd_artifacts.bzl", "BsdDebugInfo")
load(":bsd_install.bzl", "BsdInstallFileInfo", "install_manifest_result")
load(":bsd_kernel_installation.bzl", "kernel_installation_directory")

BsdKernelModuleInfo = provider(fields = ["binary", "debug", "aliases", "package", "file_metadata", "alias_metadata"])

def _product(ctx):
    info = ctx.attr.src[BsdDebugInfo]
    if not info.binary.basename.endswith(".ko"):
        fail("kernel module runtime product must end in .ko")
    if len(depset(ctx.attr.aliases).to_list()) != len(ctx.attr.aliases):
        fail("duplicate module installation alias")
    for alias in ctx.attr.aliases:
        if not alias or "/" in alias or alias in [".", "..", info.binary.basename]:
            fail("module installation aliases must be distinct basenames")
    if sorted(ctx.attr.file_metadata) != ["flags", "group", "mode", "owner"] or sorted(ctx.attr.alias_metadata) != ["group", "mode", "owner"]:
        fail("explicit module file and alias attributes required")
    files = [info.binary] + ([info.debug] if info.debug != None else [])
    return [DefaultInfo(files = depset(files)),
            BsdKernelModuleInfo(binary = info.binary, debug = info.debug,
                                aliases = ctx.attr.aliases, package = ctx.attr.package,
                                file_metadata = ctx.attr.file_metadata, alias_metadata = ctx.attr.alias_metadata)]

bsd_kernel_module_product = rule(implementation = _product, attrs = {
    "src": attr.label(providers = [BsdDebugInfo], mandatory = True),
    "aliases": attr.string_list(), "package": attr.string(mandatory = True),
    "file_metadata": attr.string_dict(mandatory = True),
    "alias_metadata": attr.string_dict(mandatory = True),
})

def _modules(ctx):
    if not ctx.attr.modules:
        fail("explicit selected kernel module products required")
    base = kernel_installation_directory(ctx.attr._base[BuildSettingInfo].value)
    debug = kernel_installation_directory(ctx.attr._debug[BuildSettingInfo].value, allow_empty = True)
    entries = []
    for target in ctx.attr.modules:
        info = target[BsdKernelModuleInfo]
        tags = ["package=" + info.package]
        entries.append(BsdInstallFileInfo(source = info.binary,
            metadata = dict(info.file_metadata, type = "file", destination = base.rstrip("/") + "/" + info.binary.basename,
                            tags = tags)))
        if info.debug != None:
            entries.append(BsdInstallFileInfo(source = info.debug,
                metadata = dict(info.file_metadata, type = "file", destination = debug.rstrip("/") + base.rstrip("/") + "/" + info.debug.basename,
                                tags = tags + ["dbg"])))
        for alias in info.aliases:
            entries.append(BsdInstallFileInfo(source = None,
                metadata = dict(info.alias_metadata, type = "symlink", destination = base.rstrip("/") + "/" + alias,
                                tags = tags, link = info.binary.basename)))
    return install_manifest_result(ctx, [], entries)

bsd_kernel_module_installation = rule(implementation = _modules, attrs = {
    "modules": attr.label_list(providers = [BsdKernelModuleInfo], mandatory = True),
    "_base": attr.label(default = Label("//tools/build/bazel/config:kernel_base_directory"), providers = [BuildSettingInfo]),
    "_debug": attr.label(default = Label("//tools/build/bazel/config:kernel_debug_directory"), providers = [BuildSettingInfo]),
})
