# SPDX-License-Identifier: BSD-2-Clause
# Source-owned EFI entry objects. Selected AMD64 Lua/secureboot profile first;
# foreign/profile dispatch and complete linking remain separate qualifications.
load("@rules_cc//cc:defs.bzl", "cc_library")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_objects")
load("//tools/build/bazel:bsd_architecture_headers.bzl", "bsd_architecture_headers")
load("//stand/liblua:config.bzl", "loader_lua_paths")

# This inventory is complete for the selected Make profile. Unsupported profiles
# are incompatible instead of silently retaining a different source selection.
def efi_loader_amd64_entry():
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
    compatible = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"] + select({
        ":entry_profile": [], "//conditions:default": ["@platforms//:incompatible"],
    })
    bsd_architecture_headers(name = "entry_architecture_headers", headers = {
        "//sys/amd64/include:efi_loader_entry_headers": "machine",
        "//sys/x86/include:efi_loader_entry_headers": "x86",
    })
    loader_lua_paths(name = "entry_lua_paths")
    deps = ['//:efi_loader_entry_headers', '//contrib/bzip2:efi_loader_entry_headers', '//contrib/lua/src:efi_loader_entry_headers', '//contrib/pnglite:efi_loader_entry_headers', '//include:efi_loader_entry_headers', '//lib/libsecureboot:efi_loader_entry_headers', '//libexec/flua/lfs:efi_loader_entry_headers', '//stand/common:efi_loader_entry_headers', '//stand/efi/include:efi_loader_entry_headers', '//stand/efi/loader:efi_loader_entry_headers', '//stand/i386:efi_loader_entry_headers', '//stand/liblua:efi_loader_entry_headers', '//stand/libsa:efi_loader_entry_headers', '//stand/libsa/zfs:efi_loader_entry_headers', '//sys/cddl/boot:efi_loader_entry_headers', '//sys/cddl/contrib/opensolaris/common/lz4:efi_loader_entry_headers', '//sys/contrib/dev/acpica/include:efi_loader_entry_headers', '//sys/contrib/edk2/Include:efi_loader_entry_headers', '//sys/contrib/openzfs:efi_loader_entry_headers', '//sys/contrib/xz-embedded:efi_loader_entry_headers', '//sys/contrib/zlib:efi_loader_entry_headers', '//sys/contrib/zstd:efi_loader_entry_headers', '//sys/crypto:efi_loader_entry_headers', '//sys/crypto/sha2:efi_loader_entry_headers', '//sys/dev/ic:efi_loader_entry_headers', '//sys/dev/pci:efi_loader_entry_headers', '//sys/dev/random:efi_loader_entry_headers', '//sys/fs/cd9660:efi_loader_entry_headers', '//sys/geom:efi_loader_entry_headers', '//sys/geom/eli:efi_loader_entry_headers', '//sys/net:efi_loader_entry_headers', '//sys/netinet:efi_loader_entry_headers', '//sys/netinet6:efi_loader_entry_headers', '//sys/opencrypto:efi_loader_entry_headers', '//sys/sys:efi_loader_entry_headers', '//sys/teken:efi_loader_entry_headers', '//sys/ufs/ufs:efi_loader_entry_headers', '//sys/vm:efi_loader_entry_headers', ':entry_architecture_headers', '//stand/libsa:standalone_headers']
    early = ['-O2', '-pipe', '-fno-common', '-Wformat', '-fshort-wchar', '-mno-red-zone', '-nostdinc', '-Istand/libsa', '-D_STANDALONE', '-Isys', '-Ddouble=jagged-little-pill', '-Dfloat=floaty-mcfloatface', '-ffunction-sections', '-fdata-sections', '-DLOADER_GELI_SUPPORT', '-Istand/libsa/geli', '-DLOADER_DISK_SUPPORT', '-DLOADER_NET_SUPPORT', '-DLOADER_MD_SUPPORT', '-ffreestanding', '-mno-mmx', '-mno-sse', '-mno-avx', '-mno-avx2', '-msoft-float', '-fPIC', '-mno-red-zone', '-mno-relax', '-DLOADER_VERIEXEC', '-Ilib/libsecureboot/h', '-Istand/efi/acpica/include', '-Istand/efi/loader', '-Istand/libsa/zfs', '-Isys/contrib/openzfs/include', '-Isys/contrib/openzfs/include/os/freebsd/zfs', '-DEFI_ZFS_BOOT', '-fPIC', '-Wall', '-Istand/efi/loader', '-Istand/efi/loader/arch/amd64', '-Istand/efi/include', '-Istand/efi/include/amd64', '-Isys/contrib/edk2/Include', '-Isys/contrib/dev/acpica/include', '-Istand/i386/libi386', '-DEFI', '-DEFI_SECUREBOOT', '-DLOADER_VERITY_SUPPORT', '-Istand/common', '-Icontrib/lua/src', '-Istand/common', '-Istand/liblua', '-DLOADER_MSDOS_SUPPORT', '-DLOADER_UFS_SUPPORT', '-DLOADER_BZIP2_SUPPORT', '-DLOADER_XZ_SUPPORT', '-DLOADER_GPT_SUPPORT', '-DLOADER_MBR_SUPPORT', '-DLOADER_ZFS_SUPPORT', '-Istand/libsa/zfs', '-Isys/cddl/boot/zfs', '-Isys/cddl/contrib/opensolaris/uts/common', '\'-DHELP_FILENAME="loader.help.efi"\'', '-g', '-gz=zlib', '-std=gnu17', '-Wno-format-zero-length', '-Wsystem-headers', '-Werror', '-Wno-pointer-sign', '-Wdate-time', '-Wno-empty-body', '-Wno-string-plus-int', '-Wno-unused-const-variable', '-Wno-error=unused-but-set-parameter', '-Wno-error=cast-function-type-mismatch', '-Wno-tautological-compare', '-Wno-unused-value', '-Wno-parentheses-equality', '-Wno-unused-function', '-Wno-enum-conversion', '-Wno-unused-local-typedef', '-Wno-address-of-packed-member', '-Wno-switch', '-Wno-switch-enum', '-Wno-knr-promoted-parameter', '-Wno-parentheses']
    late = []
    sources = [
        ('8x16', ':console_font', ['-Oz', '-Qunused-arguments']),
        ('acpi_detect', '//:stand/efi/acpica/acpi_detect.c', ['-Oz', '-Qunused-arguments']),
        ('amd64_tramp', 'arch/amd64/amd64_tramp.S', ['-Oz', '-Qunused-arguments']),
        ('autoload', 'autoload.c', ['-Oz', '-Qunused-arguments']),
        ('bcache', '//stand/common:bcache.c', ['-Oz', '-Qunused-arguments']),
        ('boot', '//stand/common:boot.c', ['-Oz', '-Qunused-arguments']),
        ('bootinfo', 'bootinfo.c', ['-Oz', '-Qunused-arguments', '-Isys/teken', '-Icontrib/pnglite']),
        ('comconsole', '//stand/i386:libi386/comconsole.c', ['-Oz', '-Qunused-arguments']),
        ('commands', '//stand/common:commands.c', ['-Oz', '-Qunused-arguments']),
        ('conf', 'conf.c', ['-Oz', '-Qunused-arguments']),
        ('console', '//stand/common:console.c', ['-Oz', '-Qunused-arguments']),
        ('copy', 'copy.c', ['-Oz', '-Qunused-arguments']),
        ('decompress', 'decompress.c', ['-Oz', '-Qunused-arguments', '-DHAVE_MEMCPY', '-Isys/contrib/zlib', '-Wno-deprecated-non-prototype', '-Icontrib/bzip2', '-DBZ_NO_STDIO', '-DBZ_NO_COMPRESS', '-Isys/contrib/zstd/lib', '-DXZ_USE_CRC64', '-Isys/contrib/xz-embedded/freebsd', '-Isys/contrib/xz-embedded/linux/include/linux']),
        ('dev_net', '//stand/common:dev_net.c', ['-Oz', '-Qunused-arguments']),
        ('devopen', '//stand/common:devopen.c', ['-Oz', '-Qunused-arguments']),
        ('disk', '//stand/common:disk.c', ['-Oz', '-Qunused-arguments']),
        ('efi_main', 'efi_main.c', ['-Oz', '-Qunused-arguments']),
        ('elf64_freebsd', 'arch/amd64/elf64_freebsd.c', ['-Oz', '-Qunused-arguments']),
        ('exc', 'arch/amd64/exc.S', ['-Oz', '-Qunused-arguments']),
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
        ('multiboot2', 'arch/amd64/multiboot2.c', ['-Oz', '-Qunused-arguments']),
        ('nullconsole', '//stand/i386:libi386/nullconsole.c', ['-Oz', '-Qunused-arguments']),
        ('nvstore', '//stand/common:nvstore.c', ['-Oz', '-Qunused-arguments']),
        ('part', '//stand/common:part.c', ['-Oz', '-Qunused-arguments', '-DHAVE_MEMCPY', '-Isys/contrib/zlib', '-Wno-deprecated-non-prototype']),
        ('pnglite', '//contrib/pnglite:pnglite.c', ['-Oz', '-Qunused-arguments', '-Icontrib/pnglite', '-DHAVE_MEMCPY', '-Isys/contrib/zlib']),
        ('reloc_elf32', '//stand/common:reloc_elf32.c', ['-Oz', '-Qunused-arguments']),
        ('reloc_elf64', '//stand/common:reloc_elf64.c', ['-Oz', '-Qunused-arguments']),
        ('self_reloc', '//stand/common:self_reloc.c', ['-Oz', '-Qunused-arguments']),
        ('spinconsole', '//stand/i386:libi386/spinconsole.c', ['-Oz', '-Qunused-arguments']),
        ('start', 'arch/amd64/start.S', ['-Oz', '-Qunused-arguments']),
        ('trap', 'arch/amd64/trap.c', ['-Oz', '-Qunused-arguments']),
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
    for name, source, flags in sources:
        cc_library(name = "entry_" + name, srcs = [source], copts = early + flags + late,
            deps = deps + ([":entry_lua_paths"] if name == "interp_lua" else []),
            features = ["-opt", "-bsd_ssp", "-bsd_riscv_userland_abi"],
            linkstatic = True, target_compatible_with = compatible)
        bsd_component_objects(name = "entry_" + name + "_objects", group = ":entry_" + name,
            target_compatible_with = compatible)
    native.filegroup(name = "entry_objects", srcs = [":entry_" + row[0] + "_objects" for row in sources],
        target_compatible_with = compatible, visibility = ["//visibility:public"])
