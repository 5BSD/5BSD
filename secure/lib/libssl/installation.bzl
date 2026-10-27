# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_link", "bsd_install_manifest")
load("//secure/lib/libcrypto:install_helpers.bzl", "openssl_file", "openssl_binary_entries")
def ssl_installation(name):
    entries = openssl_binary_entries(name, ":ssl_shared", "/usr/lib/libssl.so.35")
    entries.append(openssl_file(name + "_archive", ":static_archive", "/usr/lib/libssl.a", ["package=openssl", "dev"]))
    for pc in ["libssl.pc", "openssl.pc"]:
        entries.append(openssl_file(name + "_" + pc, "//crypto/openssl:exporters/" + pc, "/usr/libdata/pkgconfig/" + pc, ["package=openssl", "dev"]))
    bsd_install_link(name = name + "_symlink", destination = "/usr/lib/libssl.so", target = "libssl.so.35",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=openssl", "dev"])
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_symlink"], visibility = ["//visibility:public"])
