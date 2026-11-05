# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned csu test installation and Kyua registration."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")
CSU_TEST_ROOT = "/usr/tests/lib/csu"

def csu_test_installation():
    modes = ["dynamic", "dynamiclib", "dynamicpie", "errno", "static"]
    entries = []
    binaries = [(mode + "/" + program, ":" + mode + "_" + program, "0555", True)
                for mode in modes if mode != "errno"
                for program in ["cxx_constructors", "fini_test", "init_test"]]
    errno = [("errno_test", "dynamic_plain"), ("errno_static_test", "static_plain"),
             ("errno_thr_test", "dynamic_threaded"), ("errno_thr_static_test", "static_threaded")]
    binaries += [("errno/" + name, ":errno_" + variant + "_program", "0555", not variant.startswith("static")) for name, variant in errno]
    binaries.append(("dynamiclib/libh_csu.so", ":h_csu", "0444", True))
    for index, (path, source, mode, separate_debug) in enumerate(binaries):
        name = "installed_binary_" + str(index)
        # bsd.prog.mk suppresses separate debug files for explicit LDFLAGS=-static
        # (the two errno variants), unlike NO_SHARED used by the static ATF suite.
        payload = source
        if separate_debug:
            bsd_debug_split(name = name, src = source,
                binary_name = "installed/" + path, debug_name = "installed/" + path + ".debug",
                objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
            native.filegroup(name = name + "_debug", srcs = [":" + name], output_group = "debug_files")
            payload = ":" + name
        bsd_strip_binary(name = name + "_strip", src = payload, output = "stripped/" + path,
            strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
        files = [("payload", ":" + name + "_strip", CSU_TEST_ROOT + "/" + path, mode, ["package=tests"])]
        if separate_debug:
            files.append(("symbols", ":" + name + "_debug", "/usr/lib/debug" + CSU_TEST_ROOT + "/" + path + ".debug", "0444", ["package=tests", "dbg"]))
        for suffix, target, destination, permissions, tags in files:
            item = name + "_" + suffix
            bsd_install_file(name = item, src = target, destination = destination,
                owner = "root", group = "wheel", mode = permissions, install_tags = tags)
            entries.append(":" + item)
    for mode in [""] + modes:
        name = "kyua_" + (mode or "root")
        names = sorted([n for n, _ in errno]) if mode == "errno" else (["cxx_constructors", "fini_test", "init_test"] if mode else [])
        bsd_kyuafile(name = name, output = name + "/Kyuafile", suite = "FreeBSD", names = names,
            interfaces = {n: "plain" if mode == "errno" else "atf" for n in names},
            subdirectories = [] if mode else modes)
        bsd_install_file(name = name + "_install", src = ":" + name,
            destination = CSU_TEST_ROOT + ("/" + mode if mode else "") + "/Kyuafile",
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":" + name + "_install")
    bsd_install_manifest(name = "install_manifest", entries = entries, visibility = ["//visibility:public"])
    directories = {path: json.encode(dict(owner = "root", group = "wheel", mode = "0755", tags = ["package=tests", "dbg"]))
        for path in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/lib", "/usr/lib/debug" + CSU_TEST_ROOT] + ["/usr/lib/debug" + CSU_TEST_ROOT + "/" + mode for mode in modes]}
    # Each original test owner contributes its installed suite directory, even
    # when the common tests mtree also creates it. Preserve package ownership.
    directories.update({CSU_TEST_ROOT + ("/" + mode if mode else ""): json.encode(
        dict(owner = "root", group = "wheel", mode = "0755", tags = ["package=tests"]))
        for mode in [""] + modes})
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"], directories = directories,
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib", "//etc/mtree:BSD.tests.dist": "/usr/tests"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])
