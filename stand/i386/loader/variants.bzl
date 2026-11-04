# SPDX-License-Identifier: BSD-2-Clause
"""One native BIOS loader construction model for all supported interpreters."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load(":entry.bzl", "PROFILES")
load("//tools/build/bazel:bsd_architecture_headers.bzl", "bsd_architecture_headers")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_objects")
load("//tools/build/bazel:bsd_firmware_link.bzl", "bsd_firmware_link")
load("//tools/build/bazel:bsd_loader_generated.bzl", "bsd_loader_version", "bsd_loader_help")
load("//tools/build/bazel:bsd_boot_image.bzl", "bsd_boot_strip_client", "bsd_btx_image")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")
load("//stand/liblua:config.bzl", "loader_lua_paths")
load(":inspection.bzl", "inspection_policy")

def _variant(interpreter):
    profile = PROFILES[interpreter]
    prefix = "" if interpreter == "lua" else interpreter + "_"
    program = "loader_" + interpreter
    flags = {"//tools/build/bazel/config:" + key: "true" for key in ["loader_geli", "loader_disk", "loader_net", "loader_md", "loader_zfs", "loader_bios_textonly"]}
    if interpreter == "lua":
        flags["//tools/build/bazel/config:loader_lua"] = "true"
    elif interpreter == "4th":
        flags["//tools/build/bazel/config:forth"] = "true"
    native.config_setting(name = prefix + "entry_profile", flag_values = flags)
    compatible = ["@platforms//os:freebsd", "@platforms//cpu:x86_32"] + select({
        ":" + prefix + "entry_profile": [], "//conditions:default": ["@platforms//:incompatible"]}) + select({
        "//tools/build/bazel/config:veriexec_enabled": ["@platforms//:incompatible"], "//conditions:default": []})
    bsd_architecture_headers(name = prefix + "architecture_headers", headers = profile["views"])
    deps = [":" + prefix + "architecture_headers" if dep == ":architecture_headers" else dep for dep in profile["deps"]]
    for name, source, cflags in profile["rows"]:
        cc_library(name = "entry_" + prefix + name, srcs = [source],
            copts = profile["flags"] + cflags,
            deps = deps + ([":lua_paths"] if name == "interp_lua" else []),
            features = ["-opt", "-bsd_debug_info", "-bsd_ssp", "-bsd_riscv_userland_abi"],
            linkstatic = True, target_compatible_with = compatible)
        bsd_component_objects(name = "entry_" + prefix + name + "_objects", group = ":entry_" + prefix + name,
            target_compatible_with = compatible)
    native.filegroup(name = prefix + "entry_objects", srcs = [":entry_" + prefix + row[0] + "_objects" for row in profile["rows"]], target_compatible_with = compatible)
    bsd_firmware_link(name = program + "_symbols", output = program + ".sym",
        objects = ["//stand/i386/btx/lib:crt0", ":" + prefix + "entry_objects"],
        archives = (["//stand/liblua32:static_archive"] if interpreter == "lua" else ["//stand/ficl32:static_archive"] if interpreter == "4th" else []) + ["//stand/i386/libi386:static_archive", "//stand/libsa32:static_archive"],
        script = "//stand/i386:boot.ldscript", object_order = profile["order"],
        linkopts = ["-static", "-Wl,--defsym,ORG=0x0", "-Wl,--gc-sections", "-Wl,-z,nostart-stop-gc", "-Wl,-z,max-page-size=0x1000", "-Wl,--no-rosegment"],
        features = ["-bsd_riscv_userland_abi"], target_compatible_with = compatible)
    bsd_boot_strip_client(name = program + "_client", src = ":" + program + "_symbols", output = program + ".bin",
        maximum = "//tools/build/bazel/config:loader_bios_max_size", target_compatible_with = compatible)
    bsd_btx_image(name = program + "_image", src = ":" + program + "_client", output = program,
        kernel = "//stand/i386/btx/btx:btx", loader = "//stand/i386/btx/btxldr:btxldr",
        entry_setting = "//tools/build/bazel/config:loader_bios_address", entry_kind = "output", output_format = "aout", target_compatible_with = compatible)
    main_install = "install_" + interpreter
    bsd_install_file(name = main_install, src = ":" + program + "_image", destination = "/boot/" + program,
        owner = "root", group = "wheel", mode = "0555", install_tags = ["package=bootloader"], target_compatible_with = compatible)
    for name, destination in [("install_default", "/boot/loader"), ("install_zfs", "/boot/zfsloader")]:
        bsd_install_link(name = prefix + name, destination = destination, target = "/boot/" + program,
            kind = "hardlink", owner = "root", group = "wheel", mode = "0555", install_tags = ["package=bootloader"], target_compatible_with = compatible)
    entries = [":" + main_install] + select({"//tools/build/bazel/config:loader_default_" + interpreter: [":" + prefix + "install_default", ":" + prefix + "install_zfs"], "//conditions:default": []})
    if interpreter == "simp":
        bsd_loader_help(name = "help_bios", srcs = ["//stand/common:help.common"], output = "loader.help.bios", target_compatible_with = compatible)
        bsd_install_file(name = "install_bios_help", src = ":help_bios", destination = "/boot/loader.help.bios", owner = "root", group = "wheel", mode = "0444", install_tags = ["package=bootloader"], target_compatible_with = compatible)
        entries += [":install_bios_help"]
    bsd_install_manifest(name = prefix + "install_manifest", entries = entries, target_compatible_with = compatible)
    bsd_install_archive(name = prefix + "install_archive", manifests = [":" + prefix + "install_manifest"],
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/"}, passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree",
        epoch_setting = "//tools/build/bazel/config:loader_source_date_epoch", python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], target_compatible_with = compatible)
    inspection_policy(name = prefix + "inspection_policy", testonly = True, default_interpreter = select({"//tools/build/bazel/config:loader_default_" + i: i for i in ["lua", "4th", "simp"]}), visibility = ["//tools/build/bazel:__pkg__"])

def bios_loaders():
    loader_lua_paths(name = "lua_paths")
    bsd_loader_version(name = "version_configured", version = "version", output = "vers.c", description = "bootstrap loader", machine = "x86",
        reproducible = select({"//tools/build/bazel/config:reproducible_build_enabled": True, "//conditions:default": False}), metadata = "//tools/build/bazel/config:loader_version_metadata")
    for interpreter in ["lua", "4th", "simp"]:
        _variant(interpreter)
