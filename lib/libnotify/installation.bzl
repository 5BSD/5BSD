# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

MANUAL_ALIASES = ['notify_client_open', 'notify_subscribe', 'notify_unsubscribe', 'notify_publish', 'notify_next', 'notify_state_watch', 'notify_timer_add', 'notify_timer_cancel', 'notify_stats', 'notify_list_subscriptions', 'notify_list_timers', 'notify_client_close']

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":notify_shared",
        binary_name = name + "/libnotify.so.1", debug_name = name + "/libnotify.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libnotify.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [(h, "/usr/include/" + h, ["package=libnotify", "dev"]) for h in ["notify_server.h", "notify_watch.h", "notify_pressure.h"]] + [
        ("notify.h", "/usr/include/notify.h", ["package=libnotify", "dev"]),
        ("notify_protocol.h", "/usr/include/notify_protocol.h", ["package=libnotify", "dev"]),

        (":static_archive", "/usr/lib/libnotify.a", ["package=libnotify", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libnotify.so.1", ["package=libnotify"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libnotify.so.1.debug", ["package=libnotify", "dbg"]),
    ]
    bsd_compress(name = name + "_manual", src = "libnotify.3",
        output = name + "/libnotify.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/libnotify.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libnotify-man"], "//conditions:default": ["package=libnotify-dev"]})))
    bsd_compress(name = name + "_watch_manual", src = "notify_watch.3",
        output = name + "/notify_watch.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip",
        redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_watch_manual", "/usr/share/man/man3/notify_watch.3.gz",
        select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libnotify-man"], "//conditions:default": ["package=libnotify-dev"]})))
    files.append(("notify.fidl", "/usr/share/fidl/notify.fidl", ["package=libnotify-dev"]))
    files += [("//contrib/fuchsia:" + n, "/usr/share/licenses/libnotify/fuchsia/" + n, ["package=libnotify"]) for n in ["LICENSE", "PATENTS"]]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libnotify.so", target = "libnotify.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libnotify", "dev"])
    for alias in MANUAL_ALIASES:
        target = name + "_manual_" + alias
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + alias + ".3.gz",
            target = "/usr/share/man/man3/libnotify.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libnotify-man"], "//conditions:default": ["package=libnotify-dev"]}))
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
