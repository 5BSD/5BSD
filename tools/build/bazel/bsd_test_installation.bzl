# SPDX-License-Identifier: BSD-2-Clause
"""Installation archives for declared BSD test programs and fixtures."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_debug_directories")

def bsd_tap_installation(name, directory, programs, fixtures = [], metadata = {}):
    """Declare a complete TAP suite contribution without executing its programs.

    programs maps installed basenames to source labels. Fixtures keep their
    source basenames; use separate package-owned rules for transformed data.
    Runtime execution is a separate test target or installed-system check.
    """
    # TAP rules without a source transformation install identical bytes.
    # The archive owns the installed name/mode; no host copy tool is required.
    entries = []
    for program, source in programs.items():
        if not program or "/" in program or program in [".", "..", "Kyuafile"]:
            fail("TAP program names must be distinct installed basenames")
        entry = name + "_program_" + program
        bsd_install_file(name = entry, src = source, destination = directory + "/" + program,
            owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
        entries.append(":" + entry)
    for index, source in enumerate(fixtures):
        basename = source.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
        entry = name + "_fixture_" + str(index)
        bsd_install_file(name = entry, src = source, destination = directory + "/" + basename,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":" + entry)
    bsd_kyuafile(name = name + "_kyuafile", output = name + "/Kyuafile", suite = "FreeBSD",
        names = sorted(programs.keys()), interfaces = {p: "tap" for p in programs},
        metadata = {p: json.encode(fields) for p, fields in metadata.items()})
    bsd_install_file(name = name + "_kyuafile_entry", src = ":" + name + "_kyuafile",
        destination = directory + "/Kyuafile", owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
    entries.append(":" + name + "_kyuafile_entry")
    bsd_install_manifest(name = name + "_manifest", entries = entries, visibility = ["//visibility:public"])
    bsd_test_install_archive(name = name + "_archive", directory = directory, manifests = [":" + name + "_manifest"])

def bsd_test_install_archive(name, directory, manifests, debug = False, visibility = ["//usr.bin:__subpackages__"], package = "tests", data_subdirectories = []):
    """Archive a suite with package-owned data and split-debug directories.

    Data subdirectories are canonical suite-relative paths declared by the owner.
    """
    directories = {directory: json.encode({"owner": "root", "group": "wheel", "mode": "0755", "tags": ["package=" + package]})}
    for subdirectory in data_subdirectories:
        if any([part in ["", ".", ".."] for part in subdirectory.split("/")]):
            fail("data subdirectories must be canonical suite-relative paths")
        path = directory + "/" + subdirectory
        if path in directories:
            fail("duplicate suite data subdirectory: " + subdirectory)
        directories[path] = directories[directory]
    mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.tests.dist": "/usr/tests"}
    if debug:
        directories.update(utility_debug_directories(package, directory))
        mtree_specs["//etc/mtree:BSD.debug.dist"] = "/usr/lib"
    bsd_install_archive(name = name, manifests = manifests,
        directories = directories,
        mtree_specs = mtree_specs,
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = visibility)


def bsd_library_installation_archives(name, production_name, test_name,
                                    production_manifests, test_manifests,
                                    production_directories, test_directories,
                                    visibility, **kwargs):
    """Keep original library/test package claims in separate native archives.

    Duplicate paths with distinct package tags belong to different archives.
    The complete parent selects tests; the production output name and provider
    remain available to individual package consumers. Feature-dependent test
    manifests and directory policies stay declared by the owning BUILD file.
    """
    bsd_install_archive(name = production_name, manifests = production_manifests,
        directories = production_directories, visibility = visibility, **kwargs)
    bsd_install_archive(name = test_name, manifests = test_manifests,
        directories = test_directories, **kwargs)
    bsd_install_archive_set(name = name, archives = [":" + production_name] + select({
        "//tools/build/bazel/config:tests_enabled": [":" + test_name],
        "//conditions:default": [],
    }), visibility = visibility)
