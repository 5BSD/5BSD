# SPDX-License-Identifier: BSD-2-Clause
"""Installation of unchanged TAP shell programs and their declared fixtures."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

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

def bsd_test_install_archive(name, directory, manifests):
    """Archive a declared installed suite using the shared base test policy."""
    bsd_install_archive(name = name, manifests = manifests,
        directories = {directory: json.encode({"owner": "root", "group": "wheel", "mode": "0755", "tags": ["package=tests"]})},
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.tests.dist": "/usr/tests"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        visibility = ["//usr.bin:__subpackages__"])
