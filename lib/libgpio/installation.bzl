# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":gpio_shared",
        binary_name = name + "/libgpio.so.0", debug_name = name + "/libgpio.so.0.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libgpio.so.0",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libgpio.a", ["package=utilities", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libgpio.so.0", ["package=utilities"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libgpio.so.0.debug", ["package=utilities", "dbg"]),
    ]
    files.append(("libgpio.h", "/usr/include/libgpio.h", ["package=utilities", "dev"]))
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=utilities-man"], "//conditions:default": ["package=utilities-dev"]})
    bsd_compress(name = name + "_manual", src = "gpio.3", output = name + "/gpio.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/gpio.3.gz", man_tags))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libgpio.so", target = "libgpio.so.0",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities", "dev"])
    for manual in ['gpio_open', 'gpio_open_device', 'gpio_close', 'gpio_pin_list', 'gpio_pin_config', 'gpio_pin_set_flags', 'gpio_pin_set_name', 'gpio_pin_get', 'gpio_pin_set', 'gpio_pin_low', 'gpio_pin_high', 'gpio_pin_input', 'gpio_pin_output', 'gpio_pin_opendrain', 'gpio_pin_pushpull', 'gpio_pin_tristate', 'gpio_pin_pullup', 'gpio_pin_pulldown', 'gpio_pin_invin', 'gpio_pin_invout', 'gpio_pin_pulsate', 'gpio_configure_events', 'gpio_fileno']:
        alias = name + "_manual_" + manual
        bsd_install_link(name = alias, destination = "/usr/share/man/man3/" + manual + ".3.gz",
            target = "/usr/share/man/man3/gpio.3.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + alias)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
