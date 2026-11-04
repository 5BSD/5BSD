# SPDX-License-Identifier: BSD-2-Clause
# Source-owned common AMD64 EFI entry model and selected Lua construction.
# Foreign/profile dispatch and runtime qualification remain separate gates.
load("@rules_cc//cc:defs.bzl", "cc_library")
load(":cross_profiles.bzl", "cross_lua_profiles")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_objects")
load("//tools/build/bazel:bsd_architecture_headers.bzl", "bsd_architecture_headers")
load("//stand/liblua:config.bzl", "loader_lua_paths")
load("//tools/build/bazel:bsd_firmware_link.bzl", "bsd_firmware_link")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split")
load("//tools/build/bazel:bsd_efi_image.bzl", "bsd_efi_image")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")
load("//tools/build/bazel:bsd_pkg_layout.bzl", "bsd_pkg_layout")

# Source-owned entry facts shared by the selected AMD64 interpreters.
# Interpreter include/verification options come from stand/{lua,ficl}.mk.
_ENTRY_BEFORE_CPU = ['-O2', '-pipe', '-fno-common', '-Wformat', '-fshort-wchar', '-mno-red-zone', '-nostdinc', '-Istand/libsa', '-D_STANDALONE', '-Isys', '-Ddouble=jagged-little-pill', '-Dfloat=floaty-mcfloatface', '-ffunction-sections', '-fdata-sections', '-DLOADER_GELI_SUPPORT', '-Istand/libsa/geli', '-DLOADER_DISK_SUPPORT', '-DLOADER_NET_SUPPORT', '-DLOADER_MD_SUPPORT', '-ffreestanding', '-mno-mmx', '-mno-sse', '-mno-avx', '-mno-avx2', '-msoft-float']
_ENTRY_AFTER_CPU = ['-mno-relax', '-DLOADER_VERIEXEC', '-Ilib/libsecureboot/h', '-Istand/efi/acpica/include', '-Istand/efi/loader', '-Istand/libsa/zfs', '-Isys/contrib/openzfs/include', '-Isys/contrib/openzfs/include/os/freebsd/zfs', '-DEFI_ZFS_BOOT']
_ENTRY_AFTER_EFI_INCLUDES = ['-Isys/contrib/edk2/Include', '-Isys/contrib/dev/acpica/include', '-Istand/i386/libi386', '-DEFI', '-DEFI_SECUREBOOT', '-DLOADER_VERITY_SUPPORT', '-Istand/common']
_ENTRY_AFTER_INTERPRETER = ['-DLOADER_MSDOS_SUPPORT', '-DLOADER_UFS_SUPPORT', '-DLOADER_BZIP2_SUPPORT', '-DLOADER_XZ_SUPPORT', '-DLOADER_GPT_SUPPORT', '-DLOADER_MBR_SUPPORT', '-DLOADER_ZFS_SUPPORT', '-Istand/libsa/zfs', '-Isys/cddl/boot/zfs', '-Isys/cddl/contrib/opensolaris/uts/common', '\'-DHELP_FILENAME="loader.help.efi"\'', '-g', '-gz=zlib', '-std=gnu17', '-Wno-format-zero-length', '-Wsystem-headers', '-Werror', '-Wno-pointer-sign', '-Wdate-time', '-Wno-empty-body', '-Wno-string-plus-int', '-Wno-unused-const-variable', '-Wno-error=unused-but-set-parameter', '-Wno-error=cast-function-type-mismatch', '-Wno-tautological-compare', '-Wno-unused-value', '-Wno-parentheses-equality', '-Wno-unused-function', '-Wno-enum-conversion', '-Wno-unused-local-typedef', '-Wno-address-of-packed-member', '-Wno-switch', '-Wno-switch-enum', '-Wno-knr-promoted-parameter', '-Wno-parentheses']
_INTERPRETER_FLAGS = {
    "lua": ["-Icontrib/lua/src", "-Istand/common", "-Istand/liblua"],
    "4th": ["-fPIC", "-Istand/ficl", "-Istand/ficl/amd64", "-Istand/common",
        "-DBF_DICTSIZE=30000", "-DLOADER_VERIEXEC", "-Ilib/libsecureboot/h"],
    "simp": [],
}
_X86_COMMON_ENTRY_SOURCES = [
    ('8x16', ':console_font', ['-Oz', '-Qunused-arguments']),
    ('acpi_detect', '//stand:efi/acpica/acpi_detect.c', ['-Oz', '-Qunused-arguments']),
    ('autoload', 'autoload.c', ['-Oz', '-Qunused-arguments']),
    ('bcache', '//stand/common:bcache.c', ['-Oz', '-Qunused-arguments']),
    ('boot', '//stand/common:boot.c', ['-Oz', '-Qunused-arguments']),
    ('bootinfo', 'bootinfo.c', ['-Oz', '-Qunused-arguments', '-Isys/teken', '-Icontrib/pnglite']),
    ('comconsole', '//stand/i386/libi386:comconsole.c', ['-Oz', '-Qunused-arguments']),
    ('commands', '//stand/common:commands.c', ['-Oz', '-Qunused-arguments']),
    ('conf', 'conf.c', ['-Oz', '-Qunused-arguments']),
    ('console', '//stand/common:console.c', ['-Oz', '-Qunused-arguments']),
    ('copy', 'copy.c', ['-Oz', '-Qunused-arguments']),
    ('decompress', 'decompress.c', ['-Oz', '-Qunused-arguments', '-DHAVE_MEMCPY', '-Isys/contrib/zlib', '-Wno-deprecated-non-prototype', '-Icontrib/bzip2', '-DBZ_NO_STDIO', '-DBZ_NO_COMPRESS', '-Isys/contrib/zstd/lib', '-DXZ_USE_CRC64', '-Isys/contrib/xz-embedded/freebsd', '-Isys/contrib/xz-embedded/linux/include/linux']),
    ('dev_net', '//stand/common:dev_net.c', ['-Oz', '-Qunused-arguments']),
    ('devopen', '//stand/common:devopen.c', ['-Oz', '-Qunused-arguments']),
    ('disk', '//stand/common:disk.c', ['-Oz', '-Qunused-arguments']),
    ('efi_main', 'efi_main.c', ['-Oz', '-Qunused-arguments']),
    ('framebuffer', 'framebuffer.c', ['-Oz', '-Qunused-arguments', '-Isys/teken', '-Icontrib/pnglite']),
    ('g_verity_transition', '//sys/geom:verity/g_verity_transition.c', ['-Oz', '-Qunused-arguments']),
    ('g_verity_verify', '//sys/geom:verity/g_verity_verify.c', ['-Oz', '-Qunused-arguments']),
    ('gfx_fb', '//stand/common:gfx_fb.c', ['-Oz', '-Qunused-arguments', '-Isys/teken', '-Isys/cddl/contrib/opensolaris/common/lz4', '-Icontrib/pnglite', '-DHAVE_MEMCPY', '-Isys/contrib/zlib', '-Wno-deprecated-non-prototype']),
    ('interp', '//stand/common:interp.c', ['-Oz', '-Qunused-arguments']),
    ('interp_backslash', '//stand/common:interp_backslash.c', ['-Oz', '-Qunused-arguments']),
    ('interp_lua', '//stand/common:interp_lua.c', ['-Oz', '-Qunused-arguments', '-Ilibexec/flua/lfs']),
    ('interp_parse', '//stand/common:interp_parse.c', ['-Oz', '-Qunused-arguments']),
    ('load_elf32', '//stand/common:load_elf32.c', ['-Oz', '-Qunused-arguments']),
    ('load_elf32_obj', '//stand/common:load_elf32_obj.c', ['-Oz', '-Qunused-arguments']),
    ('load_elf64', '//stand/common:load_elf64.c', ['-Oz', '-Qunused-arguments']),
    ('load_elf64_obj', '//stand/common:load_elf64_obj.c', ['-Oz', '-Qunused-arguments']),
    ('ls', '//stand/common:ls.c', ['-Oz', '-Qunused-arguments']),
    ('main', 'main.c', ['-Wno-format', '-Oz', '-Qunused-arguments', '-Isys/teken', '-Icontrib/pnglite']),
    ('md', '//stand/common:md.c', ['-Oz', '-Qunused-arguments']),
    ('memdisk', 'memdisk.c', ['-Wno-format', '-Oz', '-Qunused-arguments']),
    ('misc', '//stand/common:misc.c', ['-Oz', '-Qunused-arguments']),
    ('modinfo', '//stand/common:modinfo.c', ['-Oz', '-Qunused-arguments']),
    ('module', '//stand/common:module.c', ['-Oz', '-Qunused-arguments', '-Isys/teken', '-Icontrib/pnglite']),
    ('nullconsole', '//stand/i386/libi386:nullconsole.c', ['-Oz', '-Qunused-arguments']),
    ('nvstore', '//stand/common:nvstore.c', ['-Oz', '-Qunused-arguments']),
    ('part', '//stand/common:part.c', ['-Oz', '-Qunused-arguments', '-DHAVE_MEMCPY', '-Isys/contrib/zlib', '-Wno-deprecated-non-prototype']),
    ('pnglite', '//contrib/pnglite:pnglite.c', ['-Oz', '-Qunused-arguments', '-Icontrib/pnglite', '-DHAVE_MEMCPY', '-Isys/contrib/zlib']),
    ('reloc_elf32', '//stand/common:reloc_elf32.c', ['-Oz', '-Qunused-arguments']),
    ('reloc_elf64', '//stand/common:reloc_elf64.c', ['-Oz', '-Qunused-arguments']),
    ('self_reloc', '//stand/common:self_reloc.c', ['-Oz', '-Qunused-arguments']),
    ('spinconsole', '//stand/i386/libi386:spinconsole.c', ['-Oz', '-Qunused-arguments']),
    ('tslog', '//stand/common:tslog.c', ['-Oz', '-Qunused-arguments']),
    ('vdisk', '//stand/common:vdisk.c', ['-Oz', '-Qunused-arguments']),
    ('verified_root', '//stand/common:verified_root.c', ['-Oz', '-Qunused-arguments']),
    ('verity_attach', '//stand/common:verity_attach.c', ['-Oz', '-Qunused-arguments']),
    ('verity_commands', '//stand/common:verity_commands.c', ['-Oz', '-Qunused-arguments']),
    ('verity_read', '//stand/libsa:verity_read.c', ['-Oz', '-Qunused-arguments']),
    ('veritydev', '//stand/common:veritydev.c', ['-Oz', '-Qunused-arguments']),
    ('vers', ':version_configured', ['-Oz', '-Qunused-arguments']),
    ('zfs_cmd', '//stand/common:zfs_cmd.c', ['-Oz', '-Qunused-arguments']),
]
_X86_ARCH_ENTRY_SOURCES = {
    "amd64": [
        ('amd64_tramp', 'arch/amd64/amd64_tramp.S', ['-Oz', '-Qunused-arguments']),
        ('start', 'arch/amd64/start.S', ['-Oz', '-Qunused-arguments']),
        ('elf64_freebsd', 'arch/amd64/elf64_freebsd.c', ['-Oz', '-Qunused-arguments']),
        ('trap', 'arch/amd64/trap.c', ['-Oz', '-Qunused-arguments']),
        ('multiboot2', 'arch/amd64/multiboot2.c', ['-Oz', '-Qunused-arguments']),
        ('exc', 'arch/amd64/exc.S', ['-Oz', '-Qunused-arguments']),
    ],
    "i386": [
        ('amd64_tramp', 'arch/i386/amd64_tramp.S', ['-Oz', '-Qunused-arguments']),
        ('start', 'arch/i386/start.S', ['-Oz', '-Qunused-arguments']),
        ('setup', 'arch/i386/setup.c', ['-Oz', '-Qunused-arguments']),
        ('elf64_freebsd', 'arch/i386/elf64_freebsd.c', ['-Oz', '-Qunused-arguments']),
    ],
}

def _efi_loader_x86_cflags(architecture, interpreter, package):
    if architecture not in _X86_ARCH_ENTRY_SOURCES or interpreter not in _INTERPRETER_FLAGS:
        fail("unsupported EFI architecture/interpreter")
    if architecture == "i386" and interpreter != "lua":
        fail("IA32 entry construction currently qualifies the Lua interpreter")
    cpu = ["-fPIC", "-mno-red-zone"] if architecture == "amd64" else ["-m32", "-march=i386"]
    firmware_alignment = [] if architecture == "amd64" else ["-malign-double"]
    pic = ["-fPIC"] if architecture == "amd64" else []
    return _ENTRY_BEFORE_CPU + firmware_alignment + cpu + _ENTRY_AFTER_CPU + pic + ["-Wall"] + [
        "-I" + package, "-I" + package + "/arch/" + architecture,
        "-Istand/efi/include", "-Istand/efi/include/" + architecture,
    ] + _ENTRY_AFTER_EFI_INCLUDES + _INTERPRETER_FLAGS[interpreter] + _ENTRY_AFTER_INTERPRETER

def efi_loader_amd64_cflags(interpreter, package):
    return _efi_loader_x86_cflags("amd64", interpreter, package)

_X86_BEFORE_ARCH_ORDER = ['autoload.o', 'bootinfo.o', 'conf.o', 'copy.o', 'decompress.o', 'efi_main.o', 'framebuffer.o', 'main.o', 'memdisk.o', 'self_reloc.o', 'vers.o', 'gfx_fb.o', '8x16.o', 'acpi_detect.o']
_X86_AFTER_ARCH_ORDER = ['nullconsole.o', 'comconsole.o', 'spinconsole.o', 'veritydev.o', 'verity_attach.o', 'verity_read.o', 'g_verity_verify.o', 'g_verity_transition.o', 'verity_commands.o', 'boot.o', 'commands.o', 'console.o', 'devopen.o', 'interp.o', 'interp_backslash.o', 'interp_parse.o', 'ls.o', 'misc.o', 'modinfo.o', 'module.o', 'nvstore.o', 'pnglite.o', 'tslog.o', 'verified_root.o', 'load_elf32.o', 'load_elf32_obj.o', 'reloc_elf32.o', 'load_elf64.o', 'load_elf64_obj.o', 'reloc_elf64.o', 'disk.o', 'part.o', 'vdisk.o', 'dev_net.o', 'bcache.o', 'md.o', 'interp_lua.o', 'zfs_cmd.o']

def efi_loader_amd64_object_order(interpreter):
    selected = {"lua": "interp_lua.o", "4th": "interp_forth.o", "simp": "interp_simple.o"}
    if interpreter not in selected:
        fail("unsupported EFI interpreter")
    return _efi_loader_x86_object_order("amd64", interpreter)

def _efi_loader_x86_object_order(architecture, interpreter):
    selected = {"lua": "interp_lua.o", "4th": "interp_forth.o", "simp": "interp_simple.o"}
    order = _X86_BEFORE_ARCH_ORDER + [row[0] + ".o" for row in _X86_ARCH_ENTRY_SOURCES[architecture]] + _X86_AFTER_ARCH_ORDER
    return [selected[interpreter] if name == "interp_lua.o" else name for name in order]

def efi_loader_amd64_sources():
    return _X86_COMMON_ENTRY_SOURCES + _X86_ARCH_ENTRY_SOURCES["amd64"]

# This inventory is complete for the selected Make profile. Unsupported profiles
# are incompatible instead of silently retaining a different source selection.
_CPU = {"i386": "@platforms//cpu:x86_32", "amd64": "@platforms//cpu:x86_64", "aarch64": "@platforms//cpu:aarch64", "riscv64": "@platforms//cpu:riscv64"}

def _cpu_select(values, default):
    choices = {_CPU[arch]: value for arch, value in values.items()}
    choices["//conditions:default"] = default
    return select(choices)

def _ia32_lua_profile(base):
    # Explicit architecture rows keep future AMD64-only inputs out of DO32.
    return dict(rows = _X86_COMMON_ENTRY_SOURCES + _X86_ARCH_ENTRY_SOURCES["i386"],
        order = _efi_loader_x86_object_order("i386", "lua"),
        flags = _efi_loader_x86_cflags("i386", "lua", native.package_name()),
        deps = base["deps"],
        architecture_headers = {"//sys/i386/include:efi_loader_entry_headers": "machine", "//sys/x86/include:efi_loader_ia32_headers": "x86"},
        script = "arch/i386/i386.ldscript",
        archives = ["//stand/efi/liblua32efi:static_archive", "//stand/efi/libefi32:static_archive", "//stand/efi/libsa32efi:static_archive"],
        linkopts = ["-Wl,-Bsymbolic,-znotext", "-pie"], image_format = "efi-app-ia32")

def efi_loader_entry():
    native.config_setting(name = "entry_profile", flag_values = {
        "//tools/build/bazel/config:loader_geli": "true",
        "//tools/build/bazel/config:loader_disk": "true",
        "//tools/build/bazel/config:loader_net": "true",
        "//tools/build/bazel/config:loader_md": "true",
        "//tools/build/bazel/config:loader_zfs": "true",
        "//tools/build/bazel/config:loader_efi_secureboot": "true",
        "//tools/build/bazel/config:loader_veriexec_vectx": "false",
        "//tools/build/bazel/config:loader_veriexec_pass_manifest": "false",
    })
    compatible = ["@platforms//os:freebsd"] + _cpu_select({arch: [] for arch in _CPU}, ["@platforms//:incompatible"]) + select({
        ":entry_profile": [], "//conditions:default": ["@platforms//:incompatible"],
    })
    profiles = {"amd64": dict(flags = efi_loader_amd64_cflags("lua", native.package_name()),
        rows = efi_loader_amd64_sources(), deps = ['//stand:efi_loader_entry_headers', '//contrib/bzip2:efi_loader_entry_headers', '//contrib/lua/src:efi_loader_entry_headers', '//contrib/pnglite:efi_loader_entry_headers', '//include:efi_loader_entry_headers', '//lib/libsecureboot:efi_loader_entry_headers', '//libexec/flua/lfs:efi_loader_entry_headers', '//stand/common:efi_loader_entry_headers', '//stand/efi/include:efi_loader_entry_headers', '//stand/efi/loader:efi_loader_entry_headers', '//stand/i386:efi_loader_entry_headers', '//stand/liblua:efi_loader_entry_headers', '//stand/libsa:efi_loader_entry_headers', '//stand/libsa/zfs:efi_loader_entry_headers', '//sys/cddl/boot:efi_loader_entry_headers', '//sys/cddl/contrib/opensolaris/common/lz4:efi_loader_entry_headers', '//sys/contrib/dev/acpica/include:efi_loader_entry_headers', '//sys/contrib/edk2/Include:efi_loader_entry_headers', '//sys/contrib/openzfs:efi_loader_entry_headers', '//sys/contrib/xz-embedded:efi_loader_entry_headers', '//sys/contrib/zlib:efi_loader_entry_headers', '//sys/contrib/zstd:efi_loader_entry_headers', '//sys/crypto:efi_loader_entry_headers', '//sys/crypto/sha2:efi_loader_entry_headers', '//sys/dev/ic:efi_loader_entry_headers', '//sys/dev/pci:efi_loader_entry_headers', '//sys/dev/random:efi_loader_entry_headers', '//sys/fs/cd9660:efi_loader_entry_headers', '//sys/geom:efi_loader_entry_headers', '//sys/geom/eli:efi_loader_entry_headers', '//sys/net:efi_loader_entry_headers', '//sys/netinet:efi_loader_entry_headers', '//sys/netinet6:efi_loader_entry_headers', '//sys/opencrypto:efi_loader_entry_headers', '//sys/sys:efi_loader_entry_headers', '//sys/teken:efi_loader_entry_headers', '//sys/ufs/ufs:efi_loader_entry_headers', '//sys/vm:efi_loader_entry_headers', ':entry_architecture_headers', '//stand/libsa:standalone_headers'],
        architecture_headers = {"//sys/amd64/include:efi_loader_entry_headers": "machine", "//sys/x86/include:efi_loader_entry_headers": "x86"},
        order = efi_loader_amd64_object_order("lua"), script = "arch/amd64/amd64.ldscript",
        archives = ["//stand/efi/libluaefi:static_archive", "//stand/efi/libefi:static_archive", "//stand/efi/libsaefi:static_archive"],
        linkopts = ["-Wl,-znocombreloc", "-Wl,-Bsymbolic,-znotext", "-pie"], image_format = "efi-app-x86_64", help = ":help_common")}
    profiles["i386"] = _ia32_lua_profile(profiles["amd64"])
    profiles.update(cross_lua_profiles())
    native_width = compatible + _cpu_select({arch: ["@platforms//:incompatible"] if arch == "i386" else [] for arch in profiles}, ["@platforms//:incompatible"])
    bsd_architecture_headers(name = "entry_architecture_headers",
        headers = _cpu_select({arch: profile["architecture_headers"] for arch, profile in profiles.items()}, {}))
    loader_lua_paths(name = "entry_lua_paths")
    indexed = {arch: {row[0]: row for row in profile["rows"]} for arch, profile in profiles.items()}
    names = depset([row[0] for profile in profiles.values() for row in profile["rows"]]).to_list()
    for name in names:
        supported = compatible + _cpu_select({arch: [] if name in rows else ["@platforms//:incompatible"] for arch, rows in indexed.items()}, ["@platforms//:incompatible"])
        cc_library(name = "entry_" + name,
            srcs = _cpu_select({arch: [rows[name][1]] if name in rows else [] for arch, rows in indexed.items()}, []),
            copts = _cpu_select({arch: profiles[arch]["flags"] + rows[name][2] if name in rows else [] for arch, rows in indexed.items()}, []),
            deps = _cpu_select({arch: profile["deps"] for arch, profile in profiles.items()}, []) + ([":entry_lua_paths"] if name == "interp_lua" else []),
            features = ["-opt", "-bsd_ssp", "-bsd_riscv_userland_abi"], linkstatic = True,
            target_compatible_with = supported)
        bsd_component_objects(name = "entry_" + name + "_objects", group = ":entry_" + name,
            target_compatible_with = supported)
    native.filegroup(name = "entry_objects",
        srcs = _cpu_select({arch: [":entry_" + row[0] + "_objects" for row in profile["rows"]] for arch, profile in profiles.items()}, []),
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    bsd_firmware_link(name = "loader_lua_full", objects = [":entry_objects"], output = _cpu_select({arch: ("loader_ia32" if arch == "i386" else "loader_lua") + ".sym.full" for arch in profiles}, ""),
        script = _cpu_select({arch: profile["script"] for arch, profile in profiles.items()}, None),
        archives = _cpu_select({arch: profile["archives"] for arch, profile in profiles.items()}, []),
        linkopts = _cpu_select({arch: profile["linkopts"] for arch, profile in profiles.items()}, []),
        features = ["-bsd_riscv_userland_abi"],
        object_order = _cpu_select({arch: profile["order"] for arch, profile in profiles.items()}, []),
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    bsd_debug_split(name = "loader_lua_symbols", src = ":loader_lua_full",
        binary_name = _cpu_select({arch: ("loader_ia32" if arch == "i386" else "loader_lua") + ".sym" for arch in profiles}, ""),
        debug_name = _cpu_select({arch: ("loader_ia32" if arch == "i386" else "loader_lua") + ".sym.debug" for arch in profiles}, ""),
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy",
        objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs",
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    native.filegroup(name = "loader_lua_debug", srcs = [":loader_lua_symbols"],
        output_group = "debug_files", target_compatible_with = compatible,
        visibility = ["//visibility:public"])
    bsd_efi_image(name = "loader_lua_efi", src = ":loader_lua_symbols",
        output = _cpu_select({arch: ("loader_ia32" if arch == "i386" else "loader_lua") + ".efi" for arch in profiles}, ""), output_format = _cpu_select({arch: profile["image_format"] for arch, profile in profiles.items()}, ""),
        source_date_epoch_setting = "//tools/build/bazel/config:loader_source_date_epoch",
        sections = [".peheader", ".text", ".sdata", ".data", ".dynamic", ".dynsym",
            ".rel.dyn", ".rela.dyn", ".reloc", ".eh_frame", "set_Xcommand_set",
            "set_Xlua_compile_set"],
        objcopy_runtime = ["//usr.bin/elfcopy:execution_runtime"],
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    bsd_install_file(name = "install_lua_efi", src = ":loader_lua_efi",
        destination = _cpu_select({arch: "/boot/" + ("loader_ia32" if arch == "i386" else "loader_lua") + ".efi" for arch in profiles}, ""), owner = "root", group = "wheel",
        mode = "0555", install_tags = ["package=bootloader"], target_compatible_with = compatible)
    bsd_install_file(name = "install_help", src = _cpu_select({arch: profile.get("help", ":help_common") for arch, profile in profiles.items()}, None),
        destination = "/boot/loader.help.efi", owner = "root", group = "wheel",
        mode = "0444", install_tags = ["package=bootloader"], target_compatible_with = native_width)
    bsd_install_link(name = "install_default_efi", destination = "/boot/loader.efi",
        target = "/boot/loader_lua.efi", kind = "hardlink", owner = "root", group = "wheel",
        mode = "0555", install_tags = ["package=bootloader"], target_compatible_with = native_width)
    # The aggregate stage's maintained mtree supplies directory metadata. This
    # selected Lua profile is the maintained default interpreter on these platforms.
    bsd_install_manifest(name = "install_manifest", entries = _cpu_select({arch: [":install_lua_efi"] if arch == "i386" else [":install_lua_efi", ":install_help", ":install_default_efi"] for arch in profiles}, []), target_compatible_with = compatible,
        visibility = ["//visibility:public"])
    bsd_install_archive(name = "install_archive", manifests = [":install_manifest"],
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/"},
        passwd = "//etc:master.passwd", group = "//etc:group",
        mtree = "@bsd_sdk//toolchain:extra_mtree",
        epoch_setting = "//tools/build/bazel/config:loader_source_date_epoch",
        python = "@bsd_sdk//toolchain:extra_python",
        python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"],
        target_compatible_with = compatible, visibility = ["//visibility:public"])
    # EFI Lua is one contributor to bootloader. Aggregate the other boot
    # programs before permitting complete pkgbase manifests or publication.
    bsd_pkg_layout(name = "component_package_layout", scope = "component",
        manifests = [":install_manifest"], packages = ["bootloader"],
        suffix_tags = ["dbg", "dev"], target_compatible_with = compatible,
        visibility = ["//visibility:public"])
