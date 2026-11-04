# SPDX-License-Identifier: BSD-2-Clause
"""Native EFI bootstrap programs with configured ABI and ordered link inputs."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load(":profiles.bzl", "efi_bootstrap_profiles")
load("//tools/build/bazel:bsd_python_test.bzl", "bsd_host_artifact_test")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_objects")
load("//tools/build/bazel:bsd_architecture_headers.bzl", "bsd_architecture_headers")
load("//tools/build/bazel:bsd_firmware_link.bzl", "bsd_firmware_link")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split")
load("//tools/build/bazel:bsd_efi_image.bzl", "bsd_efi_image")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_compress")
_CPU = {"amd64": "@platforms//cpu:x86_64", "aarch64": "@platforms//cpu:aarch64", "riscv64": "@platforms//cpu:riscv64"}


def _select(values, default):
    choices = {_CPU[arch]: value for arch, value in values.items()}
    choices["//conditions:default"] = default
    return select(choices)


def efi_bootstrap(program):
    profiles = efi_bootstrap_profiles(program)
    native.config_setting(name = "selected_profile", flag_values = {
        "//tools/build/bazel/config:loader_geli": "true",
        "//tools/build/bazel/config:loader_disk": "true",
        "//tools/build/bazel/config:loader_zfs": "true",
        "//tools/build/bazel/config:loader_efi_secureboot": "true",
        "//tools/build/bazel/config:loader_veriexec_vectx": "false",
        "//tools/build/bazel/config:loader_veriexec_pass_manifest": "false",
    })
    compatible = ["@platforms//os:freebsd"] + _select({arch: [] for arch in profiles}, ["@platforms//:incompatible"]) + select({
        ":selected_profile": [], "//conditions:default": ["@platforms//:incompatible"],
    })
    bsd_architecture_headers(name = "architecture_headers",
        headers = _select({arch: profile["architecture_headers"] for arch, profile in profiles.items()}, {}))
    indexed = {arch: {row[0]: row for row in profile["rows"]} for arch, profile in profiles.items()}
    names = depset([row[0] for profile in profiles.values() for row in profile["rows"]]).to_list()
    for name in names:
        supported = compatible + _select({arch: [] if name in rows else ["@platforms//:incompatible"] for arch, rows in indexed.items()}, ["@platforms//:incompatible"])
        cc_library(name = "entry_" + name,
            srcs = _select({arch: [rows[name][1]] if name in rows else [] for arch, rows in indexed.items()}, []),
            copts = _select({arch: profiles[arch]["flags"] + rows[name][2] if name in rows else [] for arch, rows in indexed.items()}, []),
            deps = _select({arch: profile["deps"] for arch, profile in profiles.items()}, []),
            features = ["-opt", "-bsd_ssp", "-bsd_riscv_userland_abi"], linkstatic = True,
            target_compatible_with = supported)
        bsd_component_objects(name = "entry_" + name + "_objects", group = ":entry_" + name,
            target_compatible_with = supported)
    native.filegroup(name = "entry_objects",
        srcs = _select({arch: [":entry_" + row[0] + "_objects" for row in profile["rows"]] for arch, profile in profiles.items()}, []),
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    bsd_firmware_link(name = "full", objects = [":entry_objects"], output = program + ".sym.full",
        script = _select({arch: profile["script"] for arch, profile in profiles.items()}, None),
        object_order = _select({arch: profile["order"] for arch, profile in profiles.items()}, []),
        archives = ["//stand/efi/libefi:static_archive", "//stand/efi/libsaefi:static_archive"],
        linkopts = _select({arch: profile["linkopts"] for arch, profile in profiles.items()}, []),
        features = ["-bsd_riscv_userland_abi"], target_compatible_with = compatible,
        visibility = ["//visibility:public"])
    bsd_debug_split(name = "symbols", src = ":full", binary_name = program + ".sym",
        debug_name = program + ".sym.debug", objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy",
        objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs", target_compatible_with = compatible,
        visibility = ["//visibility:public"])
    native.filegroup(name = "debug", srcs = [":symbols"], output_group = "debug_files",
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    bsd_efi_image(name = "image", src = ":symbols", output = program + ".efi",
        output_format = _select({arch: profile["image_format"] for arch, profile in profiles.items()}, ""),
        source_date_epoch_setting = "//tools/build/bazel/config:loader_source_date_epoch",
        sections = [".peheader", ".text", ".sdata", ".data", ".dynamic", ".dynsym", ".rel.dyn",
            ".rela.dyn", ".reloc", ".eh_frame"], objcopy_runtime = ["//usr.bin/elfcopy:execution_runtime"],
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    bsd_install_file(name = "install_image", src = ":image", destination = "/boot/" + program + ".efi",
        owner = "root", group = "wheel", mode = "0555", install_tags = ["package=bootloader"],
        target_compatible_with = compatible)
    entries = [":install_image"]
    if program == "gptboot":
        manual = program + ".efi.8"
        bsd_compress(name = "manual", src = manual, output = manual + ".gz", arguments = ["-cn"],
            compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
            runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"], target_compatible_with = compatible)
        compressed = "//tools/build/bazel/config:mancompress_enabled"
        destination = "/usr/share/man/man8/" + manual
        bsd_install_file(name = "install_manual",
            src = select({compressed: ":manual", "//conditions:default": manual}),
            destination = select({compressed: destination + ".gz", "//conditions:default": destination}),
            owner = "root", group = "wheel", mode = "0444",
            install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=bootloader-man"],
                "//conditions:default": ["package=bootloader"]}), target_compatible_with = compatible)
        entries += select({"//tools/build/bazel/config:man_enabled": [":install_manual"], "//conditions:default": []})
    bsd_install_manifest(name = "install_manifest", entries = entries,
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    native.filegroup(name = "install_metadata", srcs = [":install_manifest"], output_group = "manifest")
    test_args = ["--program", program, "--arch"] + _select({arch: [arch] for arch in profiles}, [])
    for name, target in [("full", "full"), ("symbols", "symbols"), ("debug", "debug"),
                         ("image", "image"), ("manifest", "install_metadata")]:
        test_args += ["--" + name, "$(rlocationpath :" + target + ")"]
    test_args += ["--manual"] + (select({"//tools/build/bazel/config:man_enabled": ["yes"],
        "//conditions:default": ["no"]}) if program == "gptboot" else ["no"])
    for name, setting in [("compressed", "mancompress_enabled"), ("split", "split_manpages_enabled")]:
        test_args += ["--" + name] + select({"//tools/build/bazel/config:" + setting: ["yes"], "//conditions:default": ["no"]})
    bsd_host_artifact_test(name = "artifact_test", src = "//stand/efi/boot1:artifact_test.py",
        data = [":full", ":symbols", ":debug", ":image", ":install_metadata"], args = test_args,
        size = "small", target_compatible_with = compatible, visibility = ["//visibility:public"])
