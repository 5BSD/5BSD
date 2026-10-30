# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")

def ssh_program(name, srcs, deps = [], dynamic_deps = [], bindir = "/usr/bin", man_section = "1", binary_mode = "0555", sk_client = True, aliases = [], extra_entries = [], extra_directories = {}, target_compatible_with = []):
    cc_binary(name = name, srcs = srcs + (["//crypto/openssh:ssh-sk-client.c"] if sk_client else []),
        deps = ["//secure/lib/libssh:ssh"] + deps,
        dynamic_deps = ["//secure/lib/libssh:ssh_shared"] + dynamic_deps,
        additional_compiler_inputs = ["//secure/lib/libssh:ssh_build_config"],
        copts = ["-fPIE", "-include", "$(location //secure/lib/libssh:ssh_build_config)"],
        local_defines = ["OPENSSL_API_COMPAT=0x10100000L"] + select({"//tools/build/bazel/config:ldns_enabled": ["HAVE_LDNS=1"], "//conditions:default": []}) + select({"//tools/build/bazel/config:tcp_wrappers_enabled": ["LIBWRAP=1"], "//conditions:default": []}),
        linkopts = ["-pie"], target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + target_compatible_with, visibility = ["//visibility:public"])
    utility_installation(name = "install_manifest", program = name,
        manual = "//crypto/openssh:" + name + "." + man_section, package = "ssh", bindir = bindir, man_section = man_section, binary_mode = binary_mode, aliases = aliases, extra_entries = extra_entries)
    directories = {d: json.encode({"owner": "root", "group": "wheel", "mode": "0755", "tags": ["package=ssh", "dbg"]}) for d in ["/usr/lib/debug/usr", "/usr/lib/debug" + bindir]}
    directories.update(extra_directories)
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"],
        directories = directories,
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.include.dist": "/usr/include", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", mtree = "@bsd_sdk//toolchain:extra_mtree", epoch = 0,
        python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"])
