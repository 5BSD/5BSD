# SPDX-License-Identifier: BSD-2-Clause
"""Install source-owned script/data payloads without ELF debug postprocessing."""
load(":bsd_install.bzl", "bsd_compress", "bsd_install_directory", "bsd_install_file", "bsd_install_manifest")
load(":bsd_install_archive.bzl", "bsd_install_archive")

def script_installation(name, scripts, manuals, package, files = {}):
    entries = []
    directories = {}
    for index, (source, destination) in enumerate(scripts.items()):
        item = name + "_script_" + str(index)
        bsd_install_file(name = item, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0555", install_tags = ["package=" + package])
        entries.append(":" + item)
        directories[destination.rsplit("/", 1)[0]] = True
    for index, (source, destination) in enumerate(files.items()):
        item = name + "_data_" + str(index)
        bsd_install_file(name = item, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=" + package])
        entries.append(":" + item)
        directories[destination.rsplit("/", 1)[0]] = True
    for index, directory in enumerate(directories):
        item = name + "_directory_" + str(index)
        bsd_install_directory(name = item, destination = directory,
            owner = "root", group = "wheel", mode = "0755", install_tags = ["package=" + package])
        entries.append(":" + item)
    for index, manual in enumerate(manuals):
        item = name + "_manual_" + str(index)
        bsd_compress(name = item, src = manual, output = name + "/" + manual + ".gz",
            arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
            redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        bsd_install_file(name = item + "_file", src = ":" + item,
            destination = "/usr/share/man/man" + manual.rsplit(".", 1)[1] + "/" + manual + ".gz",
            owner = "root", group = "wheel", mode = "0444", install_tags = select({
                "//tools/build/bazel/config:split_manpages_enabled": ["package=" + package + "-man"],
                "//conditions:default": ["package=" + package],
            }))
        entries.append(":" + item + "_file")
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])

def script_install_archive(name, manifest = ":install_manifest", **kwargs):
    bsd_install_archive(name = name, manifests = [manifest],
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = ["//visibility:public"], **kwargs)
