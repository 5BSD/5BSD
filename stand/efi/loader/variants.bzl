# SPDX-License-Identifier: BSD-2-Clause
"""Selected EFI interpreter variants using one source-owned entry inventory."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load(":entry.bzl", "efi_loader_amd64_cflags", "efi_loader_amd64_sources", "efi_loader_amd64_object_order")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_objects")
load("//tools/build/bazel:bsd_architecture_headers.bzl", "bsd_architecture_headers")
load("//tools/build/bazel:bsd_firmware_link.bzl", "bsd_firmware_link")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split")
load("//tools/build/bazel:bsd_efi_image.bzl", "bsd_efi_image")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")
_DEPS = {'4th': ['//:efi_loader_4th_headers', '//contrib/bzip2:efi_loader_4th_headers', '//contrib/pnglite:efi_loader_4th_headers', '//include:efi_loader_4th_headers', '//lib/libsecureboot:efi_loader_4th_headers', '//stand/common:efi_loader_4th_headers', '//stand/efi/include:efi_loader_4th_headers', '//stand/efi/loader:efi_loader_4th_headers', '//stand/ficl:efi_loader_4th_headers', '//stand/i386:efi_loader_4th_headers', '//stand/libsa:efi_loader_4th_headers', '//stand/libsa/zfs:efi_loader_4th_headers', '//sys/cddl/boot:efi_loader_4th_headers', '//sys/cddl/contrib/opensolaris/common/lz4:efi_loader_4th_headers', '//sys/contrib/dev/acpica/include:efi_loader_4th_headers', '//sys/contrib/edk2/Include:efi_loader_4th_headers', '//sys/contrib/openzfs:efi_loader_4th_headers', '//sys/contrib/xz-embedded:efi_loader_4th_headers', '//sys/contrib/zlib:efi_loader_4th_headers', '//sys/contrib/zstd:efi_loader_4th_headers', '//sys/crypto:efi_loader_4th_headers', '//sys/crypto/sha2:efi_loader_4th_headers', '//sys/dev/ic:efi_loader_4th_headers', '//sys/dev/pci:efi_loader_4th_headers', '//sys/dev/random:efi_loader_4th_headers', '//sys/fs/cd9660:efi_loader_4th_headers', '//sys/geom:efi_loader_4th_headers', '//sys/geom/eli:efi_loader_4th_headers', '//sys/net:efi_loader_4th_headers', '//sys/netinet:efi_loader_4th_headers', '//sys/netinet6:efi_loader_4th_headers', '//sys/opencrypto:efi_loader_4th_headers', '//sys/sys:efi_loader_4th_headers', '//sys/teken:efi_loader_4th_headers', '//sys/ufs/ufs:efi_loader_4th_headers', '//sys/vm:efi_loader_4th_headers', ':architecture_headers', '//stand/libsa:standalone_headers'], 'simp': ['//:efi_loader_simp_headers', '//contrib/bzip2:efi_loader_simp_headers', '//contrib/pnglite:efi_loader_simp_headers', '//include:efi_loader_simp_headers', '//lib/libsecureboot:efi_loader_simp_headers', '//stand/common:efi_loader_simp_headers', '//stand/efi/include:efi_loader_simp_headers', '//stand/efi/loader:efi_loader_simp_headers', '//stand/i386:efi_loader_simp_headers', '//stand/libsa:efi_loader_simp_headers', '//stand/libsa/zfs:efi_loader_simp_headers', '//sys/cddl/boot:efi_loader_simp_headers', '//sys/cddl/contrib/opensolaris/common/lz4:efi_loader_simp_headers', '//sys/contrib/dev/acpica/include:efi_loader_simp_headers', '//sys/contrib/edk2/Include:efi_loader_simp_headers', '//sys/contrib/openzfs:efi_loader_simp_headers', '//sys/contrib/xz-embedded:efi_loader_simp_headers', '//sys/contrib/zlib:efi_loader_simp_headers', '//sys/contrib/zstd:efi_loader_simp_headers', '//sys/crypto:efi_loader_simp_headers', '//sys/crypto/sha2:efi_loader_simp_headers', '//sys/dev/ic:efi_loader_simp_headers', '//sys/dev/pci:efi_loader_simp_headers', '//sys/dev/random:efi_loader_simp_headers', '//sys/fs/cd9660:efi_loader_simp_headers', '//sys/geom:efi_loader_simp_headers', '//sys/geom/eli:efi_loader_simp_headers', '//sys/net:efi_loader_simp_headers', '//sys/netinet:efi_loader_simp_headers', '//sys/netinet6:efi_loader_simp_headers', '//sys/opencrypto:efi_loader_simp_headers', '//sys/sys:efi_loader_simp_headers', '//sys/teken:efi_loader_simp_headers', '//sys/ufs/ufs:efi_loader_simp_headers', '//sys/vm:efi_loader_simp_headers', ':architecture_headers', '//stand/libsa:standalone_headers']}


def efi_loader_variant(interpreter):
    if interpreter not in ["4th", "simp"]:
        fail("selected variant must be Forth or simple")
    program = "loader_" + interpreter
    native.config_setting(name = "selected_profile", flag_values = {
        "//tools/build/bazel/config:loader_geli": "true",
        "//tools/build/bazel/config:loader_disk": "true",
        "//tools/build/bazel/config:loader_net": "true",
        "//tools/build/bazel/config:loader_md": "true",
        "//tools/build/bazel/config:loader_zfs": "true",
        "//tools/build/bazel/config:loader_efi_secureboot": "true",
        "//tools/build/bazel/config:loader_veriexec_vectx": "false",
        "//tools/build/bazel/config:loader_veriexec_pass_manifest": "false",
    })
    compatible = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + select({
        ":selected_profile": [], "//conditions:default": ["@platforms//:incompatible"],
    })
    header = "efi_" + program + "_headers"
    bsd_architecture_headers(name = "architecture_headers", headers = {
        "//sys/amd64/include:" + header: "machine", "//sys/x86/include:" + header: "x86",
    })
    groups = []
    for old_name, old_source, old_flags in efi_loader_amd64_sources():
        name, source, flags = old_name, old_source, old_flags
        if name == "interp_lua":
            name = "interp_forth" if interpreter == "4th" else "interp_simple"
            source = "//stand/common:" + name + ".c"
            flags = ["-Oz", "-Qunused-arguments"]
        elif name == "vers":
            source = "//stand/efi/loader:" + ("version_forth_configured" if interpreter == "4th" else "version_configured")
        elif source.startswith(":"):
            source = "//stand/efi/loader" + source
        elif not source.startswith("//"):
            source = "//stand/efi/loader:" + source
        cc_library(name = "entry_" + name, srcs = [source],
            copts = efi_loader_amd64_cflags(interpreter, native.package_name()) + flags,
            deps = _DEPS[interpreter], features = ["-opt", "-bsd_ssp", "-bsd_riscv_userland_abi"],
            linkstatic = True, target_compatible_with = compatible)
        bsd_component_objects(name = "entry_" + name + "_objects", group = ":entry_" + name,
            target_compatible_with = compatible)
        groups.append(":entry_" + name + "_objects")
    native.filegroup(name = "entry_objects", srcs = groups, target_compatible_with = compatible,
        visibility = ["//visibility:public"])
    archives = (["//stand/efi/ficlefi:static_archive"] if interpreter == "4th" else []) + [
        "//stand/efi/libefi:static_archive", "//stand/efi/libsaefi:static_archive"]
    bsd_firmware_link(name = "full", objects = [":entry_objects"], object_order = efi_loader_amd64_object_order(interpreter),
        output = program + ".sym.full", script = "//stand/efi/loader:arch/amd64/amd64.ldscript",
        archives = archives, linkopts = ["-Wl,-znocombreloc", "-Wl,-Bsymbolic,-znotext", "-pie"],
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    bsd_debug_split(name = "symbols", src = ":full", binary_name = program + ".sym",
        debug_name = program + ".sym.debug", objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy",
        objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs", target_compatible_with = compatible,
        visibility = ["//visibility:public"])
    native.filegroup(name = "debug", srcs = [":symbols"], output_group = "debug_files",
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    bsd_efi_image(name = "image", src = ":symbols", output = program + ".efi",
        output_format = "efi-app-x86_64", source_date_epoch_setting = "//tools/build/bazel/config:loader_source_date_epoch",
        sections = [".peheader", ".text", ".sdata", ".data", ".dynamic", ".dynsym", ".rel.dyn",
            ".rela.dyn", ".reloc", ".eh_frame", "set_Xcommand_set", "set_X" + interpreter + "_compile_set"],
        objcopy_runtime = ["//usr.bin/elfcopy:execution_runtime"], target_compatible_with = compatible,
        visibility = ["//visibility:public"])
    bsd_install_file(name = "install_image", src = ":image", destination = "/boot/" + program + ".efi",
        owner = "root", group = "wheel", mode = "0555", install_tags = ["package=bootloader"],
        target_compatible_with = compatible)
    entries = [":install_image"]
    # Forth's maintained Makefile sets INSTALL_LOADER_HELP_FILE=no.
    if interpreter == "simp":
        bsd_install_file(name = "install_help", src = "//stand/efi/loader:help_common",
            destination = "/boot/loader.help.efi", owner = "root", group = "wheel", mode = "0444",
            install_tags = ["package=bootloader"], target_compatible_with = compatible)
        entries.append(":install_help")
    bsd_install_manifest(name = "install_manifest", entries = entries,
        target_compatible_with = compatible, visibility = ["//visibility:public"])
