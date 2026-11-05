# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned public header groups using standard typed installation records."""
load(":bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")
load(":bsd_install_archive.bzl", "bsd_install_archive")

def public_header_installation(name, files, directory, create_directory = False, directory_tags = [], enabled = "//tools/build/bazel/config:includes_enabled", package = "clibs", directory_follows_selection = False):
    if directory.startswith("/") or (directory and any([p in ["", ".", ".."] for p in directory.split("/")])):
        fail("public header directory must be a normalized relative path")
    prefix = "/usr/include" + ("/" + directory if directory else "")
    if create_directory and not directory:
        fail("the common include root belongs to source mtree policy")
    entries = []
    for index, (source, filename) in enumerate(files.items()):
        if not filename or filename in [".", ".."] or "/" in filename:
            fail("public header filename must be a basename")
        item = name + "_header_" + str(index)
        bsd_install_file(name = item, src = source,
            destination = prefix + "/" + filename,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=" + package, "dev"])
        entries.append(":" + item)
    bsd_install_manifest(name = name + "_manifest", entries = entries if enabled == None else select({
        enabled: entries, "//conditions:default": [],
    }), visibility = ["//include:__pkg__"])
    # Companion architecture Makefiles create their directory in beforeinstall,
    # independently of the includes option. Ordinary groups rely on mtree.
    directories = {"/usr/include/" + directory: json.encode(dict(
        owner = "root", group = "wheel", mode = "0755", tags = directory_tags))} if create_directory else {}
    if directory_follows_selection:
        if enabled == None:
            fail("selected directory requires an explicit condition")
        directories = select({enabled: directories, "//conditions:default": {}})
    bsd_install_archive(name = name + "_archive", manifests = [":" + name + "_manifest"], directories = directories,
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.include.dist": "/usr/include"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = ["//visibility:public"])
