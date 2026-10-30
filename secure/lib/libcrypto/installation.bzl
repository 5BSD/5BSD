# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_link", "bsd_install_manifest")
load("//crypto/openssl:install_headers.bzl", "INSTALL_HEADERS")
load(":installation_data.bzl", "MANUALS", "MANUAL_LINKS")
load(":install_helpers.bzl", "openssl_file", "openssl_binary_entries", "openssl_manual_entries")
def crypto_installation(name):
    entries = openssl_binary_entries(name, ":crypto_shared", "/lib/libcrypto.so.35")
    entries += [openssl_file(name + "_archive", ":static_archive", "/usr/lib/libcrypto.a", ["package=openssl", "dev"]),
        openssl_file(name + "_pkgconfig", "//crypto/openssl:exporters/libcrypto.pc", "/usr/libdata/pkgconfig/libcrypto.pc", ["package=openssl", "dev"])]
    for header, source in INSTALL_HEADERS:
        entries.append(openssl_file(name + "_header_" + header, source, "/usr/include/openssl/" + header, ["package=openssl", "dev"]))
    bsd_install_link(name = name + "_symlink", destination = "/usr/lib/libcrypto.so", target = "../../lib/libcrypto.so.35",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=openssl", "dev"])
    entries += [":" + name + "_symlink"] + openssl_manual_entries(name, MANUALS, MANUAL_LINKS, development = True)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
