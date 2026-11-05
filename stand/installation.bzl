# SPDX-License-Identifier: BSD-2-Clause
"""Compose the selected AMD64 stand traversal from native source owners."""
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive", "bsd_install_archive_set")

def _archive(name, manifests, bindir = False):
    bsd_install_archive(name = name, manifests = manifests,
        directories = {"/boot": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=utilities"]}'} if bindir else {},
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree",
        epoch_setting = "//tools/build/bazel/config:loader_source_date_epoch",
        supplemental_mtree_setting = "//tools/build/bazel/config:boot_data_directory_policy",
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"])

def stand_installation():
    for child in ["defaults", "images", "man", "fonts", "lua", "forth"]:
        _archive("data_" + child + "_archive", ["//stand/" + child + ":install_manifest"])
    for child in ["boot1", "gptboot", "loader", "loader_4th", "loader_simp", "loader_ia32"]:
        _archive("efi_" + child + "_archive", ["//stand/efi/" + child + ":freestanding_install_manifest"], bindir = True)
    _archive("kboot_archive", ["//stand/kboot/kboot:install_manifest"], bindir = True)
    _archive("libsa_manual_archive", ["//stand/libsa:install_manifest"])
    for child in ["gptboot", "isoboot", "gptzfsboot", "loader_4th", "loader_lua", "loader_simp", "pxeldr"]:
        _archive("bios_" + child + "_archive", ["//stand/i386/" + child + ":install_manifest"], bindir = True)
    _archive("userboot_bindir_archive", [], bindir = True)
    bios = (["//stand/i386:legacy_install_archive"] + ["//stand/i386/boot2:install_archive"] + [":bios_" + child + "_archive" for child in ["gptboot", "isoboot", "loader_simp"]] +
        select({"//tools/build/bazel/config:forth_enabled": [":bios_loader_4th_archive"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:loader_lua_enabled": [":bios_loader_lua_archive"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:loader_zfs_enabled": [":bios_gptzfsboot_archive"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:loader_pxeboot_enabled": [":bios_pxeldr_archive"], "//conditions:default": []})
    )
    bsd_install_archive_set(name = "bios_installation_archives", archives = bios)
    bsd_install_archive_set(name = "efi_installation_archives", archives = [":efi_boot1_archive", ":efi_gptboot_archive", ":efi_loader_simp_archive"] +
        select({"//tools/build/bazel/config:forth_enabled": [":efi_loader_4th_archive"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:loader_lua_enabled": [":efi_loader_archive"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:stand_ia32_lua_selected": [":efi_loader_ia32_archive"], "//tools/build/bazel/config:loader_ia32_disabled": []}, no_match_error = "IA32 aggregation currently supports Lua only; disable IA32 for other default interpreters"))
    bsd_install_archive_set(name = "userboot_installation_archives", archives = select({"//tools/build/bazel/config:stand_userboot_alias_enabled": [":userboot_bindir_archive"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:forth_enabled": ["//stand/userboot/userboot_4th:install_archive"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:loader_lua_enabled": ["//stand/userboot/userboot_lua:install_archive"], "//conditions:default": []}))
    bsd_install_archive_set(name = "production_installation_archives", archives = [":data_" + child + "_archive" for child in ["defaults", "images", "man", "fonts"]] + [":libsa_manual_archive"] +
        select({"//tools/build/bazel/config:loader_lua_enabled": [":data_lua_archive"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:forth_enabled": [":data_forth_archive"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:efi_enabled": [":efi_installation_archives"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:loader_bios_enabled": [":bios_installation_archives"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:loader_userboot_enabled": [":userboot_installation_archives"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:loader_kboot_enabled": [":kboot_archive"], "//conditions:default": []}),
        target_compatible_with = ["@platforms//cpu:x86_64"], visibility = ["//visibility:public"])
    native.filegroup(name = "production_products", srcs = [":production_installation_archives"] + select({"//tools/build/bazel/config:loader_userboot_enabled": ["//stand/userboot/test:harness"], "//conditions:default": []}),
        target_compatible_with = ["@platforms//cpu:x86_64"], visibility = ["//visibility:public"])
