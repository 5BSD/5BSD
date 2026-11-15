# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned filesystem test installation; execution belongs to VM qualification."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_script_wrapper")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")

def filesystem_test_suite(directory, files = {}, scripts = {}, atf_shell = {}, interfaces = {}, metadata = {}, subdirectories = [], child_archives = [], extra_manifests = [], symlinks = {}, debug = False, data_subdirectories = [], kyuafile = True):
    """Install explicit payloads, preserving ATF/TAP/plain and helper distinctions.

    scripts maps installed relative names to declared source/generated bodies;
    atf_shell marks scripts requiring the maintained atf-sh interpreter wrapper.
    No Make query or filesystem discovery supplies a Bazel action graph.
    """
    entries = []
    for relative, source in files.items():
        name = "_install_data_" + relative
        bsd_install_file(name = name, src = source, destination = directory + "/" + relative,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":" + name)
    for relative, source in scripts.items():
        if relative in atf_shell:
            wrapper = "_wrapped_" + relative
            bsd_script_wrapper(name = wrapper, body = source, interpreter = "/usr/libexec/atf-sh",
                cat = "@bsd_sdk//toolchain:cat", cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"],
                redirect = "@bsd_sdk//toolchain:stdout_redirect")
            source = ":" + wrapper
        name = "_install_script_" + relative
        bsd_install_file(name = name, src = source, destination = directory + "/" + relative,
            owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
        entries.append(":" + name)
    for relative, target in symlinks.items():
        name = "_install_link_" + relative
        bsd_install_link(name = name, destination = directory + "/" + relative, target = target,
            kind = "symlink", owner = "root", group = "wheel", mode = "0777", install_tags = ["package=tests"])
        entries.append(":" + name)
    if kyuafile:
        bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = sorted(interfaces), interfaces = interfaces,
            metadata = {p: json.encode(v) for p, v in metadata.items()}, subdirectories = subdirectories)
        bsd_install_file(name = "kyuafile_install", src = ":kyuafile", destination = directory + "/Kyuafile",
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":kyuafile_install")
    bsd_install_manifest(name = "install_manifest", entries = entries, manifests = extra_manifests)
    bsd_test_install_archive(name = "install_archive", directory = directory, manifests = [":install_manifest"],
        debug = debug, data_subdirectories = data_subdirectories,
        visibility = ["//tests/sys/fs:__subpackages__", "//tests/sys/geom:__subpackages__", "//tests/sys/pjdfstest:__subpackages__"])
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"] + child_archives,
        visibility = ["//tests:__pkg__", "//tests/sys/fs:__subpackages__", "//tests/sys/geom:__subpackages__", "//tests/sys/pjdfstest:__subpackages__"])
