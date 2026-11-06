# SPDX-License-Identifier: BSD-2-Clause
"""GEOM plugin installation using the frontend's configured class directory."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("//tools/build/bazel:bsd_install.bzl", "BsdInstallManifestInfo", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

def _manifest(ctx):
    directory = ctx.attr.directory[BuildSettingInfo].value
    if not directory.startswith("/") or any([p in ["", ".", ".."] for p in directory[1:].split("/")]) or any([c < " " for c in directory.elems()]):
        fail("GEOM class directory must be a normalized absolute directory")
    filename = "geom_" + ctx.attr.cls + ".so"
    records = []
    files = [
        (ctx.file.binary, directory + "/" + filename, ["package=geom"]),
        (ctx.file.debug, "/usr/lib/debug" + directory + "/" + filename + ".debug", ["package=geom", "dbg"]),
    ]
    if ctx.attr.man_enabled[BuildSettingInfo].value:
        files.append((ctx.file.manual, "/usr/share/man/man8/g" + ctx.attr.cls + ".8.gz", ["package=geom-man"] if ctx.attr.split_manpages[BuildSettingInfo].value else ["package=geom"]))
    for source, destination, tags in files:
        records.append(dict(source = source.path, destination = destination, owner = "root", group = "wheel", mode = "0444", tags = tags, type = "file", flags = ""))
    prefix = "/usr/lib/debug"
    for part in directory[1:].split("/"):
        prefix += "/" + part
        records.append(dict(destination = prefix, owner = "root", group = "wheel", mode = "0755", tags = ["package=geom", "dbg"], type = "dir"))
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(output, json.encode(dict(format = 1, files = records)) + "\n")
    payload = depset([source for source, _, _ in files])
    return [DefaultInfo(files = depset([output], transitive = [payload])), BsdInstallManifestInfo(manifest = output, payload = payload, records = records)]

_plugin_manifest = rule(implementation = _manifest, attrs = {
    "directory": attr.label(mandatory = True), "split_manpages": attr.label(mandatory = True),
    "cls": attr.string(mandatory = True),
    "man_enabled": attr.label(default = Label("//tools/build/bazel/config:man"), providers = [BuildSettingInfo]),
    "binary": attr.label(allow_single_file = True, mandatory = True),
    "debug": attr.label(allow_single_file = True, mandatory = True),
    "manual": attr.label(allow_single_file = True, mandatory = True),
})

def plugin_installation(name, cls, binary):
    filename = "geom_" + cls + ".so"
    bsd_debug_split(name = name + "_debug", src = binary,
        binary_name = name + "/" + filename, debug_name = name + "/" + filename + ".debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    bsd_strip_binary(name = name + "_strip", src = ":" + name + "_debug", output = name + "/stripped/" + filename,
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    bsd_compress(name = name + "_man", src = "g" + cls + ".8", output = name + "/g" + cls + ".8.gz", arguments = ["-cn"],
        compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    _plugin_manifest(name = name, cls = cls, binary = ":" + name + "_strip", debug = ":" + name + "_symbols", manual = ":" + name + "_man",
        directory = "//tools/build/bazel/config:geom_class_dir", split_manpages = "//tools/build/bazel/config:split_manpages")
