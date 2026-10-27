# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_locale.bzl", "bsd_message_catalog")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")
# C.msg is a translator template, not an installed catalog.
LOCALES = [
    'be_BY.UTF-8',
    'ca_ES.ISO8859-1',
    'de_DE.ISO8859-1',
    'el_GR.ISO8859-7',
    'es_ES.ISO8859-1',
    'fi_FI.ISO8859-1',
    'fr_FR.ISO8859-1',
    'gl_ES.ISO8859-1',
    'hu_HU.ISO8859-2',
    'it_IT.ISO8859-15',
    'ja_JP.UTF-8',
    'ja_JP.eucJP',
    'ko_KR.UTF-8',
    'ko_KR.eucKR',
    'mn_MN.UTF-8',
    'nl_NL.ISO8859-1',
    'no_NO.ISO8859-1',
    'pl_PL.ISO8859-2',
    'pt_BR.ISO8859-1',
    'ru_RU.KOI8-R',
    'ru_RU.UTF-8',
    'sk_SK.ISO8859-2',
    'sv_SE.ISO8859-1',
    'uk_UA.UTF-8',
    'zh_CN.GB18030',
    'zh_CN.GB2312',
    'zh_CN.UTF-8',
]

def libc_catalogs():
    entries, directories = [], {}
    for locale in LOCALES:
        bsd_message_catalog(name = locale, src = locale + ".msg", gencat = "//usr.bin/gencat:gencat")
        bsd_install_file(name = "install_" + locale, src = ":" + locale,
            destination = "/usr/share/nls/" + locale + "/libc.cat",
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=locales"])
        entries.append(":install_" + locale)
        directories["/usr/share/nls/" + locale] = json.encode(dict(owner = "root", group = "wheel", mode = "0755", tags = ["package=utilities"]))
    native.filegroup(name = "catalogs", srcs = [":" + locale for locale in LOCALES], visibility = ["//visibility:public"])
    bsd_install_manifest(name = "install_manifest", entries = select({"//tools/build/bazel/config:nls_enabled": entries, "//conditions:default": []}))
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"],
        directories = select({"//tools/build/bazel/config:nls_enabled": directories, "//conditions:default": {}}),
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr"},
        passwd = "//etc:master.passwd", group = "//etc:group", epoch = 0,
        mtree = "@bsd_sdk//toolchain:extra_mtree", python = "@bsd_sdk//toolchain:extra_python",
        python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"])
