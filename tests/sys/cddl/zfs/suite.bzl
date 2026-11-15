# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned installation of the selected ZFS ATF hierarchy."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_script_wrapper")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")

def zfs_test_suite(files = [], generated = {}, tests = {}, raw_scripts = {}, subdirectories = [], child_archives = [], extra_manifests = [], debug = False, kyuafile = True):
    """Declare payloads/registrations; destructive test execution is separate.

    File membership and children are explicit BUILD inputs. No filesystem walk
    or Make invocation supplies the production graph. The interpreter argument
    preserves bsd.test.mk's ksh93 ATF protocol and prerequisite metadata.
    """
    directory = "/usr/" + native.package_name()
    entries = []
    for name in files:
        target = "data_" + name
        bsd_install_file(name = target, src = generated.get(name, name), destination = directory + "/" + name,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":" + target)
    for name, source in raw_scripts.items():
        target = "script_" + name
        bsd_install_file(name = target, src = source, destination = directory + "/" + name,
            owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
        entries.append(":" + target)
    for program in tests:
        bsd_script_wrapper(name = program, body = program + ".sh",
            interpreter = "/usr/libexec/atf-sh -s/usr/local/bin/ksh93",
            cat = "@bsd_sdk//toolchain:cat", cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"],
            redirect = "@bsd_sdk//toolchain:stdout_redirect")
        target = program + "_install"
        bsd_install_file(name = target, src = ":" + program, destination = directory + "/" + program,
            owner = "root", group = "wheel", mode = "0555", install_tags = ["package=tests"])
        entries.append(":" + target)
    if kyuafile:
        bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = sorted(tests),
            interfaces = {p: "atf" for p in tests}, subdirectories = subdirectories,
            metadata = {p: json.encode(fields) for p, fields in tests.items()})
        bsd_install_file(name = "kyuafile_install", src = ":kyuafile", destination = directory + "/Kyuafile",
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":kyuafile_install")
    bsd_install_manifest(name = "suite_install_manifest", entries = entries, manifests = extra_manifests)
    bsd_test_install_archive(name = "install_archive", directory = directory,
        manifests = [":suite_install_manifest"], debug = debug,
        visibility = ["//tests/sys/cddl:__subpackages__"])
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"] + child_archives,
        visibility = ["//tests:__pkg__", "//tests/sys/cddl:__subpackages__"])
