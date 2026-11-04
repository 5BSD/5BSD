# SPDX-License-Identifier: BSD-2-Clause
"""Selected EFI interpreter variants using one source-owned entry inventory."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load(":cross_profiles.bzl", "cross_loader_profiles")
load("//tools/build/bazel:bsd_python_test.bzl", "bsd_host_artifact_test")
load(":entry.bzl", "efi_loader_amd64_cflags", "efi_loader_amd64_sources", "efi_loader_amd64_object_order")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_objects")
load("//tools/build/bazel:bsd_architecture_headers.bzl", "bsd_architecture_headers")
load("//tools/build/bazel:bsd_firmware_link.bzl", "bsd_firmware_link")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split")
load("//tools/build/bazel:bsd_efi_image.bzl", "bsd_efi_image")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest")
_DEPS = {'4th': ['//stand:efi_loader_4th_headers', '//contrib/bzip2:efi_loader_4th_headers', '//contrib/pnglite:efi_loader_4th_headers', '//include:efi_loader_4th_headers', '//lib/libsecureboot:efi_loader_4th_headers', '//stand/common:efi_loader_4th_headers', '//stand/efi/include:efi_loader_4th_headers', '//stand/efi/loader:efi_loader_4th_headers', '//stand/ficl:efi_loader_4th_headers', '//stand/i386:efi_loader_4th_headers', '//stand/libsa:efi_loader_4th_headers', '//stand/libsa/zfs:efi_loader_4th_headers', '//sys/cddl/boot:efi_loader_4th_headers', '//sys/cddl/contrib/opensolaris/common/lz4:efi_loader_4th_headers', '//sys/contrib/dev/acpica/include:efi_loader_4th_headers', '//sys/contrib/edk2/Include:efi_loader_4th_headers', '//sys/contrib/openzfs:efi_loader_4th_headers', '//sys/contrib/xz-embedded:efi_loader_4th_headers', '//sys/contrib/zlib:efi_loader_4th_headers', '//sys/contrib/zstd:efi_loader_4th_headers', '//sys/crypto:efi_loader_4th_headers', '//sys/crypto/sha2:efi_loader_4th_headers', '//sys/dev/ic:efi_loader_4th_headers', '//sys/dev/pci:efi_loader_4th_headers', '//sys/dev/random:efi_loader_4th_headers', '//sys/fs/cd9660:efi_loader_4th_headers', '//sys/geom:efi_loader_4th_headers', '//sys/geom/eli:efi_loader_4th_headers', '//sys/net:efi_loader_4th_headers', '//sys/netinet:efi_loader_4th_headers', '//sys/netinet6:efi_loader_4th_headers', '//sys/opencrypto:efi_loader_4th_headers', '//sys/sys:efi_loader_4th_headers', '//sys/teken:efi_loader_4th_headers', '//sys/ufs/ufs:efi_loader_4th_headers', '//sys/vm:efi_loader_4th_headers', ':architecture_headers', '//stand/libsa:standalone_headers'], 'simp': ['//stand:efi_loader_simp_headers', '//contrib/bzip2:efi_loader_simp_headers', '//contrib/pnglite:efi_loader_simp_headers', '//include:efi_loader_simp_headers', '//lib/libsecureboot:efi_loader_simp_headers', '//stand/common:efi_loader_simp_headers', '//stand/efi/include:efi_loader_simp_headers', '//stand/efi/loader:efi_loader_simp_headers', '//stand/i386:efi_loader_simp_headers', '//stand/libsa:efi_loader_simp_headers', '//stand/libsa/zfs:efi_loader_simp_headers', '//sys/cddl/boot:efi_loader_simp_headers', '//sys/cddl/contrib/opensolaris/common/lz4:efi_loader_simp_headers', '//sys/contrib/dev/acpica/include:efi_loader_simp_headers', '//sys/contrib/edk2/Include:efi_loader_simp_headers', '//sys/contrib/openzfs:efi_loader_simp_headers', '//sys/contrib/xz-embedded:efi_loader_simp_headers', '//sys/contrib/zlib:efi_loader_simp_headers', '//sys/contrib/zstd:efi_loader_simp_headers', '//sys/crypto:efi_loader_simp_headers', '//sys/crypto/sha2:efi_loader_simp_headers', '//sys/dev/ic:efi_loader_simp_headers', '//sys/dev/pci:efi_loader_simp_headers', '//sys/dev/random:efi_loader_simp_headers', '//sys/fs/cd9660:efi_loader_simp_headers', '//sys/geom:efi_loader_simp_headers', '//sys/geom/eli:efi_loader_simp_headers', '//sys/net:efi_loader_simp_headers', '//sys/netinet:efi_loader_simp_headers', '//sys/netinet6:efi_loader_simp_headers', '//sys/opencrypto:efi_loader_simp_headers', '//sys/sys:efi_loader_simp_headers', '//sys/teken:efi_loader_simp_headers', '//sys/ufs/ufs:efi_loader_simp_headers', '//sys/vm:efi_loader_simp_headers', ':architecture_headers', '//stand/libsa:standalone_headers']}


_CPU = {"amd64": "@platforms//cpu:x86_64", "aarch64": "@platforms//cpu:aarch64", "riscv64": "@platforms//cpu:riscv64"}


def _select(values, default):
    choices = {_CPU[arch]: value for arch, value in values.items()}
    choices["//conditions:default"] = default
    return select(choices)


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
    cpus = {"amd64": "@platforms//cpu:x86_64", "aarch64": "@platforms//cpu:aarch64", "riscv64": "@platforms//cpu:riscv64"}
    def_select = {cpu: [] for cpu in cpus.values()}
    def_select["//conditions:default"] = ["@platforms//:incompatible"]
    compatible = ["@platforms//os:freebsd"] + select(def_select) + select({
        ":selected_profile": [], "//conditions:default": ["@platforms//:incompatible"],
    })
    header = "efi_" + program + "_headers"
    rows = []
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
        rows.append((name, source, flags))
    profiles = {"amd64": dict(rows = rows, flags = efi_loader_amd64_cflags(interpreter, native.package_name()),
        deps = _DEPS[interpreter], architecture_headers = {
            "//sys/amd64/include:" + header: "machine", "//sys/x86/include:" + header: "x86"},
        order = efi_loader_amd64_object_order(interpreter), script = "//stand/efi/loader:arch/amd64/amd64.ldscript",
        archives = (["//stand/efi/ficlefi:static_archive"] if interpreter == "4th" else []) + [
            "//stand/efi/libefi:static_archive", "//stand/efi/libsaefi:static_archive"],
        linkopts = ["-Wl,-znocombreloc", "-Wl,-Bsymbolic,-znotext", "-pie"],
        image_format = "efi-app-x86_64", help = "//stand/efi/loader:help_common")}
    profiles.update(cross_loader_profiles(interpreter, native.package_name()))
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
    bsd_firmware_link(name = "full", objects = [":entry_objects"],
        object_order = _select({arch: profile["order"] for arch, profile in profiles.items()}, []),
        output = program + ".sym.full", script = _select({arch: profile["script"] for arch, profile in profiles.items()}, None),
        archives = _select({arch: profile["archives"] for arch, profile in profiles.items()}, []),
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
        output_format = _select({arch: profile["image_format"] for arch, profile in profiles.items()}, ""), source_date_epoch_setting = "//tools/build/bazel/config:loader_source_date_epoch",
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
        bsd_install_file(name = "install_help", src = _select({arch: profile["help"] for arch, profile in profiles.items()}, None),
            destination = "/boot/loader.help.efi", owner = "root", group = "wheel", mode = "0444",
            install_tags = ["package=bootloader"], target_compatible_with = compatible)
        entries.append(":install_help")
    bsd_install_manifest(name = "install_manifest", entries = entries,
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    native.filegroup(name = "install_metadata", srcs = [":install_manifest"], output_group = "manifest")
    test_data = [":full", ":symbols", ":debug", ":image", ":install_metadata"]
    test_args = ["--program", program, "--arch"] + _select({arch: [arch] for arch in profiles}, [])
    for name in ["full", "symbols", "debug", "image"]:
        test_args += ["--" + name, "$(rlocationpath :" + name + ")"]
    test_args += ["--manifest", "$(rlocationpath :install_metadata)", "--manual", "no", "--compressed", "yes", "--split", "no"]
    if interpreter == "simp":
        native.filegroup(name = "help_data", srcs = _select({arch: [profile["help"]] for arch, profile in profiles.items()}, []))
        test_data.append(":help_data")
        test_args += ["--help-data", "$(rlocationpath :help_data)"]
    bsd_host_artifact_test(name = "artifact_test", src = "//stand/efi/boot1:artifact_test.py",
        data = test_data, args = test_args, size = "small", target_compatible_with = compatible,
        visibility = ["//visibility:public"])
