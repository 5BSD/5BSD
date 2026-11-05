# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_compare_test.bzl", "bsd_filter_fixture")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def text_locales(category, locales, aliases):
    if category not in ["LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME"]:
        fail("unsupported text locale category: " + category)
    entries = []
    directories = {"/usr/share": json.encode(dict(owner = "root", group = "wheel", mode = "0755", tags = ["package=utilities"]))}
    for locale in locales:
        bsd_filter_fixture(name = locale, src = locale + ".src", output = locale + ".out",
            visibility = ["//visibility:public"],
            tool = "//usr.bin/grep:grep", arguments = ["-v", "-E", "^(#$|#[ ])"],
            redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime_libraries = ["@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7", "//lib/libregex:regex_shared"])
        bsd_install_file(name = "install_" + locale, src = ":" + locale,
            destination = "/usr/share/locale/" + locale + "/" + category,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=locales"])
        entries.append(":install_" + locale)
        directories["/usr/share/locale/" + locale] = json.encode(dict(owner = "root", group = "wheel", mode = "0755", tags = ["package=locales"]))
    for source, alias in aliases:
        bsd_install_link(name = "alias_" + alias, destination = "/usr/share/locale/" + alias + "/" + category,
            target = "../" + source + "/" + category, kind = "symlink",
            owner = "root", group = "wheel", mode = "0755", install_tags = ["package=locales"])
        entries.append(":alias_" + alias)
        directories["/usr/share/locale/" + alias] = json.encode(dict(owner = "root", group = "wheel", mode = "0755", tags = ["package=locales"]))
    bsd_install_manifest(name = "install_manifest", entries = select({"//tools/build/bazel/config:locales_enabled": entries, "//conditions:default": []}))
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"], visibility = ["//share:__pkg__"],
        directories = select({"//tools/build/bazel/config:locales_enabled": directories, "//conditions:default": {}}),
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr"},
        passwd = "//etc:master.passwd", group = "//etc:group", epoch = 0,
        mtree = "@bsd_sdk//toolchain:extra_mtree", python = "@bsd_sdk//toolchain:extra_python",
        python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"])
