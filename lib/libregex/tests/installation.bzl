# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_script_wrapper", "bsd_debug_split", "bsd_strip_binary")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")
_INPUTS = ["anchor", "backref", "basic", "bracket", "c_comments", "complex", "error", "meta", "nospec", "paren", "regress", "repet_bounded", "repet_multi", "repet_ordinary", "startend", "subexp", "subtle", "word_bound", "zero"]
_ATT = ["basic", "categorization", "forcedassoc", "leftassoc", "nullsubexpr", "repetition", "rightassoc"]
def test_installation(name):
    root = "/usr/tests/lib/libregex/"
    files = [("//tests:README", "README", "0444", False)]
    files += [("//contrib/netbsd-tests/lib/libc/regex:data/" + n + ".in", "data/" + n + ".in", "0444", False) for n in _INPUTS]
    files += [("//contrib/netbsd-tests/lib/libc/regex:data/att/" + n + ".dat", "data/" + n + ".dat", "0444", False) for n in _ATT]
    files.append(("gnuext.in", "data/gnuext.in", "0444", False))
    for n, body in [("regex_test", "//contrib/netbsd-tests/lib/libc/regex:t_regex.sh"), ("libregex_test", "libregex_test.sh")]:
        bsd_script_wrapper(name = n, body = body, interpreter = "/usr/libexec/atf-sh",
            cat = "@bsd_sdk//toolchain:cat", cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"], redirect = "@bsd_sdk//toolchain:stdout_redirect")
        files.append((":" + n, n, "0555", False))
    bsd_kyuafile(name = "installed_kyuafile", suite = "FreeBSD",
        names = ["exhaust_test", "libregex_test", "regex_att_test", "regex_test"],
        interfaces = {n: "atf" for n in ["exhaust_test", "libregex_test", "regex_att_test", "regex_test"]})
    files.append((":installed_kyuafile", "Kyuafile", "0444", False))
    for n, source in [("h_regex", ":h_regex"), ("exhaust_test", ":exhaust_installed"), ("regex_att_test", ":regex_att_test")]:
        bsd_debug_split(name = n + "_debug", src = source, binary_name = "installed/" + n, debug_name = "installed/" + n + ".debug",
            objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
        bsd_strip_binary(name = n + "_strip", src = ":" + n + "_debug", output = "stripped/" + n,
            strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
        native.filegroup(name = n + "_symbols", srcs = [":" + n + "_debug"], output_group = "debug_files")
        files += [(":" + n + "_strip", n, "0555", False), (":" + n + "_symbols", n + ".debug", "0444", True)]
    entries = []
    for i, (source, dest, mode, debug) in enumerate(files):
        target = name + "_" + str(i)
        bsd_install_file(name = target, src = source, destination = ("/usr/lib/debug" if debug else "") + root + dest,
            owner = "root", group = "wheel", mode = mode, install_tags = ["package=tests"] + (["dbg"] if debug else []))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
    directories = {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=tests","dbg"]}' for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/tests", "/usr/lib/debug/usr/tests/lib", "/usr/lib/debug/usr/tests/lib/libregex"]}
    for d in [root[:-1], root + "data"]:
        directories[d] = '{"owner":"root","group":"wheel","mode":"0755","tags":["package=tests"]}'
    bsd_install_archive(name = "install_archive", manifests = [":" + name], directories = directories,
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib", "//etc/mtree:BSD.tests.dist": "/usr/tests"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])
