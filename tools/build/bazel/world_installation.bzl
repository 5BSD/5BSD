# SPDX-License-Identifier: BSD-2-Clause
"""Compose maintained native world roots; rescue/sys/stand/tests remain open."""
load(":bsd_install_archive.bzl", "bsd_install_archive_set")
load(":bsd_man_database.bzl", "bsd_man_database")
load(":bsd_install.bzl", "bsd_install_manifest")
load(":bsd_script_installation.bzl", "script_install_archive")

def world_contributions():
    bsd_install_archive_set(name = "world_contributions", archives = [
        "//lib:production_installation_archives", "//libexec:installation_archives",
        "//bin:installation_archives", "//sbin:installation_archives",
        "//include:installation_archives", "//usr.bin:production_installation_archives",
        "//usr.sbin:production_installation_archives", "//share:production_installation_archives",
        "//etc:pre_database_installation_archives",
    ] + select({"//tools/build/bazel/config:cddl_enabled": ["//cddl:production_installation_archives"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:crypt_enabled": ["//secure:production_installation_archives"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:world_kerberos_mit": ["//krb5:production_installation_archives"],
                "//tools/build/bazel/config:world_kerberos_disabled": []},
            no_match_error = "The selected Heimdal world root has no native aggregate; select MIT Kerberos or disable Kerberos"),
        visibility = ["//visibility:public"])
    for name, root in [("main", "/usr/share/man"), ("openssl", "/usr/share/openssl/man")]:
        bsd_man_database(name = "world_" + name + "_manual_database", archives = [":world_contributions"],
            root = root, visibility = ["//visibility:public"])
    bsd_install_manifest(name = "world_manual_databases_manifest", manifests =
        select({"//tools/build/bazel/config:world_manual_database_enabled": [":world_main_manual_database"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:world_openssl_database_enabled": [":world_openssl_manual_database"], "//conditions:default": []}))
    script_install_archive(name = "world_manual_databases_archive", manifest = ":world_manual_databases_manifest")
    bsd_install_archive_set(name = "finalized_world_contributions", archives = [":world_contributions", ":world_manual_databases_archive"],
        visibility = ["//visibility:public"])

    # Make also constructs internal library variants that are not installed.
    native.filegroup(name = "world_contribution_products", srcs = [
        ":finalized_world_contributions", "//lib:production_libraries", "//usr.sbin:production_programs",
    ] + select({"//tools/build/bazel/config:cddl_enabled": ["//cddl:production_products"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:crypt_enabled": ["//secure:production_products"], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:world_kerberos_mit": ["//krb5:production_products"],
                "//tools/build/bazel/config:world_kerberos_disabled": []}),
        visibility = ["//visibility:public"])
