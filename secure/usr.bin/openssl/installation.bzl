# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_manifest")
load("//secure/lib/libcrypto:install_helpers.bzl", "openssl_file", "openssl_binary_entries", "openssl_manual_entries")
load(":installation_data.bzl", "MANUALS", "MANUAL_LINKS")
def openssl_installation(name):
    entries = openssl_binary_entries(name, ":openssl", "/usr/bin/openssl", program = True)
    entries.append(openssl_file(name + "_configuration", "//crypto/openssl:apps/openssl.cnf", "/etc/ssl/openssl.cnf", ["package=openssl", "config"], "0644"))
    entries += openssl_manual_entries(name, [(m, s) for m, s in MANUALS if m != "openssl-fips.7"], MANUAL_LINKS)
    fips = [openssl_file(name + "_fips_configuration", "openssl-fips.cnf", "/etc/ssl/openssl-fips.cnf", ["package=openssl", "config"], "0644")]
    fips += openssl_manual_entries(name + "_fips", [(m, s) for m, s in MANUALS if m == "openssl-fips.7"], [])
    bsd_install_manifest(name = name, entries = entries + select({
        "//tools/build/bazel/config:openssl_fips_enabled": fips, "//conditions:default": [],
    }), visibility = ["//visibility:public"])
