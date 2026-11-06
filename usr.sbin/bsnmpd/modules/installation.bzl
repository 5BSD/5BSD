# SPDX-License-Identifier: BSD-2-Clause
"""Install a declared bsnmpd module, manual and definition payload."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_template.bzl", "bsd_template")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def module_installation(module, binary, manual, definitions, major = "6", mibs = {}, headers = {}):
    soname = "snmp_" + module + ".so." + major
    bsd_debug_split(name = "debug", src = binary, binary_name = "debug/" + soname, debug_name = "debug/" + soname + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = "stripped", src = ":debug", output = "stripped/" + soname,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = "symbols", srcs = [":debug"], output_group = "debug_files")
    if manual:
        bsd_template(name = "filtered_manual", template = manual, output = "manual/snmp_" + module + ".3",
            substitutions = {"@MODPATH@": "/usr/lib/", "@DEFPATH@": "/usr/share/snmp/defs/", "@MIBSPATH@": "/usr/share/snmp/mibs/"})
        bsd_compress(name = "manual", src = ":filtered_manual", output = "snmp_" + module + ".3.gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=bsnmp-man"], "//conditions:default": ["package=bsnmp-dev"]})
    files = [
        (":stripped", "/usr/lib/" + soname, ["package=bsnmp"], False),
        (":symbols", "/usr/lib/debug/usr/lib/" + soname + ".debug", ["package=bsnmp", "dbg"], False),
    ] + [(source, "/usr/share/snmp/defs/" + name, ["package=bsnmp"], False) for source, name in definitions.items()]
    files += [(source, "/usr/share/snmp/mibs/" + name, ["package=bsnmp"], False) for source, name in mibs.items()]
    files += [(source, "/usr/include/bsnmp/" + name, ["package=bsnmp", "dev"], False) for source, name in headers.items()]
    if manual:
        files.append((":manual", "/usr/share/man/man3/snmp_" + module + ".3.gz", man_tags, True))
    entries = []
    for source, destination, tags, is_manual in files:
        name = "file_" + destination.replace("/", "_")
        bsd_install_file(manual = is_manual, name = name, src = source, destination = destination, owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + name)
    bsd_install_link(name = "module_link", destination = "/usr/lib/snmp_" + module + ".so", target = soname,
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=bsnmp"])
    bsd_install_manifest(name = "install_manifest", entries = entries + [":module_link"])
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"],
        directories = {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsnmp","dbg"]}' for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/lib"]} | {"/usr/share/snmp/defs": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsnmp"]}'} | ({"/usr/share/snmp/mibs": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=bsnmp"]}'} if mibs else {}),
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib", "//etc/mtree:BSD.include.dist": "/usr/include"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])
