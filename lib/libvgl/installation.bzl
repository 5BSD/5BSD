# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")



def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":vgl_shared",
        binary_name = name + "/libvgl.so.6", debug_name = name + "/libvgl.so.6.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libvgl.so.6",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libvgl.a", ["package=libvgl", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libvgl.so.6", ["package=libvgl"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libvgl.so.6.debug", ["package=libvgl", "dbg"]),
    ]
    files.append(("vgl.h", "/usr/include/vgl.h", ["package=libvgl", "dev"]))
    man_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=libvgl-man"], "//conditions:default": ["package=libvgl-dev"]})
    bsd_compress(name = name + "_manual", src = "vgl.3", output = name + "/vgl.3.gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    files.append((":" + name + "_manual", "/usr/share/man/man3/vgl.3.gz", man_tags))
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libvgl.so", target = "libvgl.so.6",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=libvgl", "dev"])
    for manual in ['VGLBitmapAllocateBits', 'VGLBitmapCopy', 'VGLBitmapCreate', 'VGLBitmapDestroy', 'VGLBitmapPutChar', 'VGLBitmapString', 'VGLBlankDisplay', 'VGLBox', 'VGLCheckSwitch', 'VGLClear', 'VGLEllipse', 'VGLEnd', 'VGLFilledBox', 'VGLFilledEllipse', 'VGLGetXY', 'VGLInit', 'VGLLine', 'VGLKeyboardInit', 'VGLKeyboardEnd', 'VGLKeyboardGetCh', 'VGLMouseInit', 'VGLMouseMode', 'VGLMouseSetImage', 'VGLMouseSetStdImage', 'VGLMouseStatus', 'VGLPanScreen', 'VGLSetBorder', 'VGLSetPalette', 'VGLSetPaletteIndex', 'VGLSetVScreenSize', 'VGLSetXY', 'VGLTextSetFontFile']:
        alias = name + "_manual_" + manual
        bsd_install_link(name = alias, destination = "/usr/share/man/man3/" + manual + ".3.gz",
            target = "/usr/share/man/man3/vgl.3.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + alias)
    bsd_install_manifest(name = name, entries = entries + [":" + name + "_link"], visibility = ["//visibility:public"])
