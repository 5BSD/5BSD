# SPDX-License-Identifier: BSD-2-Clause
"""Runtime-linker installation payload and pkgbase ownership."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

load("//libexec/rtld-elf/tests:installation.bzl", "TEST_MANIFESTS", "TEST_DIRECTORIES")

def rtld_installation():
    bsd_debug_split(name = "install_debug", src = ":rtld_binary",
        binary_name = "install/ld-elf.so.1", debug_name = "install/ld-elf.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = "install_stripped", src = ":install_debug", output = "install/stripped/ld-elf.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = "install_symbols", srcs = [":install_debug"], output_group = "debug_files")
    for name, source, path, mode, tags, flags in [
        ("binary", ":install_stripped", "/libexec/ld-elf.so.1", "0555", ["package=clibs"], "schg"),
        ("debug", ":install_symbols", "/usr/lib/debug/libexec/ld-elf.so.1.debug", "0444", ["package=clibs", "dbg"], ""),
        ("config", "libmap.conf", "/etc/libmap.conf", "0644", ["package=clibs", "config"], ""),
    ]:
        bsd_install_file(name = "install_" + name + "_file", src = source, destination = path,
            owner = "root", group = "wheel", mode = mode, flags = flags, install_tags = tags)
    bsd_install_link(name = "install_compat_link", destination = "/usr/libexec/ld-elf.so.1",
        target = "../../libexec/ld-elf.so.1", kind = "symlink", owner = "root", group = "wheel",
        mode = "0755", install_tags = ["package=clibs"])
    bsd_compress(name = "install_manual", src = "rtld.1", output = "install/rtld.1.gz",
        arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=clibs-man"],
        "//conditions:default": ["package=clibs"]})
    bsd_install_file(name = "install_manual_file", src = ":install_manual", destination = "/usr/share/man/man1/rtld.1.gz",
        owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
    for name in ["ld-elf.so.1", "ld.so"]:
        bsd_install_link(name = "install_manual_" + name, destination = "/usr/share/man/man1/" + name + ".1.gz",
            target = "/usr/share/man/man1/rtld.1.gz", kind = "hardlink", owner = "root", group = "wheel",
            mode = "0444", install_tags = man_tags)
    bsd_install_manifest(name = "install_manifest", entries = [":install_" + n for n in [
        "binary_file", "debug_file", "config_file", "compat_link", "manual_file", "manual_ld-elf.so.1", "manual_ld.so"]],
        visibility = ["//visibility:public"])
    base_directories = {
        "/etc": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=utilities"]}',
        "/usr/lib/debug/libexec": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=clibs","dbg"]}',
    }
    test_directories = dict(base_directories)
    test_directories.update(TEST_DIRECTORIES)
    base_mtree = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib"}
    test_mtree = dict(base_mtree)
    test_mtree["//etc/mtree:BSD.tests.dist"] = "/usr/tests"
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"] + select({
        "//tools/build/bazel/config:tests_enabled": TEST_MANIFESTS, "//conditions:default": []}),
        directories = select({"//tools/build/bazel/config:tests_enabled": test_directories,
            "//conditions:default": base_directories}),
        mtree_specs = select({"//tools/build/bazel/config:tests_enabled": test_mtree,
            "//conditions:default": base_mtree}),
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])
