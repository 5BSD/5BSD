# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:defs.bzl", "cc_library", "cc_binary", "cc_import")
load(":entry.bzl", "PROFILES", "VIEWS", "DEPS")
load("//tools/build/bazel:bsd_architecture_headers.bzl", "bsd_architecture_headers")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_objects")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//tools/build/bazel:bsd_loader_generated.bzl", "bsd_loader_version", "bsd_loader_help")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split")
load("//stand/liblua:config.bzl", "loader_lua_paths")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def _variant(interp):
    profile = PROFILES[interp]
    feature = "loader_lua" if interp == "lua" else "forth"
    native.config_setting(name = interp + "_profile", flag_values = {
        "//tools/build/bazel/config:" + feature: "true",
        "//tools/build/bazel/config:loader_geli": "true",
        "//tools/build/bazel/config:loader_disk": "true",
        "//tools/build/bazel/config:loader_zfs": "true",
    })
    compatible = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + select({
        ":" + interp + "_profile": [], "//conditions:default": ["@platforms//:incompatible"],
    }) + select({"//tools/build/bazel/config:veriexec_enabled": ["@platforms//:incompatible"], "//conditions:default": []})
    bsd_loader_version(name = interp + "_version", version = "version", output = interp + "/vers.c",
        description = "User boot " + interp, machine = "amd64",
        reproducible = select({"//tools/build/bazel/config:reproducible_build_enabled": True, "//conditions:default": False}),
        metadata = "//tools/build/bazel/config:loader_version_metadata", target_compatible_with = compatible)
    for name, source, flags in profile["rows"]:
        target = interp + "_entry_" + name
        cc_library(name = target, srcs = [source], copts = profile["contexts"][flags],
            deps = DEPS + ([":lua_paths"] if name == "interp_lua" else []),
            features = ["-opt", "-bsd_debug_info", "-bsd_ssp", "-bsd_riscv_userland_abi", "bsd_small_pic"],
            linkstatic = True, target_compatible_with = compatible)
        bsd_component_objects(name = target + "_objects", group = ":" + target, pic = True, target_compatible_with = compatible)
    native.filegroup(name = interp + "_objects", srcs = [":" + interp + "_entry_" + row[0] + "_objects" for row in profile["rows"]], target_compatible_with = compatible, visibility = ["//stand/userboot:__subpackages__"])
    cc_import(name = interp + "_interpreter", static_library = "//stand/liblua:static_archive" if interp == "lua" else "//stand/ficl:static_archive", target_compatible_with = compatible)
    cc_import(name = interp + "_standalone", static_library = "//stand/libsa:static_archive", target_compatible_with = compatible)
    bsd_link_sequence(name = interp + "_archives", deps = [":" + interp + "_interpreter", ":" + interp + "_standalone"], target_compatible_with = compatible)
    cc_binary(name = interp + "/userboot.full.so", srcs = [":" + interp + "_objects"], deps = [":" + interp + "_archives"],
        linkshared = True, linkstatic = True,
        linkopts = ["-nostdlib", "-Wl,-Bsymbolic", "-Wl,-x", "-Wl,--fatal-warnings", "-Wl,--warn-shared-textrel", "-Wl,-soname,userboot_" + interp + ".so"],
        features = ["-bsd_riscv_userland_abi"], target_compatible_with = compatible)
    bsd_debug_split(name = interp + "_image", src = ":" + interp + "/userboot.full.so", binary_name = interp + "/userboot_" + interp + ".so", debug_name = interp + "/userboot_" + interp + ".so.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs", target_compatible_with = compatible, visibility = ["//visibility:public"])


    native.filegroup(name = interp + "_debug", srcs = [":" + interp + "_image"], output_group = "debug_files", target_compatible_with = compatible)
    entries = []
    for kind, source, path, tags in [
        ("binary", ":" + interp + "_image", "/boot/userboot_" + interp + ".so", ["package=bootloader"]),
        ("debug", ":" + interp + "_debug", "/usr/lib/debug/boot/userboot_" + interp + ".so.debug", ["package=bootloader", "dbg"]),
    ]:
        name = interp + "_install_" + kind
        bsd_install_file(name = name, src = source, destination = path, owner = "root", group = "wheel", mode = "0444", install_tags = tags, target_compatible_with = compatible)
        entries.append(":" + name)
    bsd_install_link(name = interp + "_install_default", destination = "/boot/userboot.so", target = "/boot/userboot_" + interp + ".so", kind = "hardlink",
        owner = "root", group = "wheel", mode = "0444", install_tags = ["package=bootloader"], target_compatible_with = compatible)
    entries += select({"//tools/build/bazel/config:loader_default_" + interp: [":" + interp + "_install_default"], "//conditions:default": []})
    if interp == "lua":
        bsd_loader_help(name = "userboot_help", srcs = ["//stand/common:help.common"], output = "loader.help.userboot", target_compatible_with = compatible)
        bsd_install_file(name = "install_help", src = ":userboot_help", destination = "/boot/loader.help.userboot", owner = "root", group = "wheel", mode = "0444", install_tags = ["package=bootloader"], target_compatible_with = compatible)
        entries += [":install_help"]
    bsd_install_manifest(name = interp + "_manifest", entries = entries, target_compatible_with = compatible, visibility = ["//stand/userboot:__subpackages__"])
    bsd_install_archive(name = interp + "_archive", manifests = [":" + interp + "_manifest"],
        directories = {"/usr/lib/debug/boot": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bootloader","dbg"]}'},
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree",
        epoch_setting = "//tools/build/bazel/config:loader_source_date_epoch", python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], target_compatible_with = compatible, visibility = ["//stand/userboot:__subpackages__"])

def userboot_variants():
    bsd_architecture_headers(name = "architecture_headers", headers = VIEWS)
    loader_lua_paths(name = "lua_paths")
    for interp in ["lua", "4th"]:
        _variant(interp)
