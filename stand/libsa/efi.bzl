# SPDX-License-Identifier: BSD-2-Clause
"""Private EFI context with explicit policy and shared standalone sources."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load("//tools/build/bazel:bsd_component_archive.bzl", "bsd_component_archive")
load(":library.bzl", "standalone_sa_arch_cflags", "standalone_sa_groups", "standalone_sa_order")

_WCHAR_CFLAGS = select({
    "@platforms//cpu:x86_64": ["-fshort-wchar"],
    "@platforms//cpu:aarch64": ["-fshort-wchar"],
    "//conditions:default": [],
})
_EFI_MACHINE_CFLAGS = select({
    "@platforms//cpu:x86_64": ["-Istand/efi/include/amd64"],
    "@platforms//cpu:aarch64": ["-Istand/efi/include/arm64"],
    "@platforms//cpu:riscv64": ["-Istand/efi/include/riscv"],
    "//conditions:default": [],
})
_EARLY = ["-O2", "-pipe", "-fno-common", "-Wformat"] + _WCHAR_CFLAGS + ["-nostdinc"]
# brf.c also consumes the BearSSL tool interface. Keep its options in the same
# position as the common Make recipe, with no second copy of the common flags.
_CFLAGS_BEFORE_TOOLS = ['-Istand/libsa',
 '-D_STANDALONE',
 '-Isys',
 '-Ddouble=jagged-little-pill',
 '-Dfloat=floaty-mcfloatface',
 '-DLOADER_GELI_SUPPORT',
 '-Istand/libsa/geli',
 '-DLOADER_DISK_SUPPORT',
 '-ffreestanding',
 '-DLOADER_VERIEXEC',
 '-Ilib/libsecureboot/h',
 '-Icontrib/bearssl/inc',
 '-Wno-deprecated-non-prototype',
 '-Icontrib/bearssl/src',
 '-Ilib/libsecureboot/h']
_CFLAGS_BEFORE_MACHINE = ['-DVE_PCR_SUPPORT', '-Isys/contrib/edk2/Include', '-Istand/efi/include']
_CFLAGS_AFTER_MACHINE = ['-g',
 '-gz=zlib',
 '-std=gnu17',
 '-Wno-format-zero-length',
 '-Wsystem-headers',
 '-Werror',
 '-Wno-pointer-sign',
 '-Wdate-time',
 '-Wno-empty-body',
 '-Wno-string-plus-int',
 '-Wno-unused-const-variable',
 '-Wno-error=unused-but-set-parameter',
 '-Wno-error=cast-function-type-mismatch',
 '-Wno-tautological-compare',
 '-Wno-unused-value',
 '-Wno-parentheses-equality',
 '-Wno-unused-function',
 '-Wno-enum-conversion',
 '-Wno-unused-local-typedef',
 '-Wno-address-of-packed-member',
 '-Wno-switch',
 '-Wno-switch-enum',
 '-Wno-knr-promoted-parameter',
 '-Wno-parentheses',
 '-Qunused-arguments',
 '-include',
 'secureboot_config.h']

def _efi_cflags(tool_flags = []):
    return _CFLAGS_BEFORE_TOOLS + tool_flags + _CFLAGS_BEFORE_MACHINE + _EFI_MACHINE_CFLAGS + _CFLAGS_AFTER_MACHINE

_EXTRA = [
    struct(name = "ccopy", sources = ["//contrib/bearssl:standalone_sa_efi_ccopy_sources", "//lib/libsecureboot:standalone_sa_efi_ccopy_sources"], tool_flags = []),
    struct(name = "brf", sources = ["//lib/libsecureboot:standalone_sa_efi_brf_sources"], tool_flags = ["-DNO_STDIO", "-Icontrib/bearssl/tools"]),
]
_EXTRA_ORDER = ['ccopy.o',
 'dec32be.o',
 'dec64be.o',
 'enc32be.o',
 'enc64be.o',
 'pemdec.o',
 'ec_all_m31.o',
 'ec_c25519_m31.o',
 'ec_c25519_m62.o',
 'ec_c25519_m64.o',
 'ec_default.o',
 'ec_p256_m31.o',
 'ec_p256_m62.o',
 'ec_p256_m64.o',
 'ec_prime_i31.o',
 'ec_pubkey.o',
 'ec_secp256r1.o',
 'ec_secp384r1.o',
 'ec_secp521r1.o',
 'ecdsa_atr.o',
 'ecdsa_default_vrfy_asn1.o',
 'ecdsa_i31_bits.o',
 'ecdsa_i31_vrfy_asn1.o',
 'ecdsa_i31_vrfy_raw.o',
 'multihash.o',
 'sha1.o',
 'sha2big.o',
 'sha2small.o',
 'i31_add.o',
 'i31_bitlen.o',
 'i31_decmod.o',
 'i31_decode.o',
 'i31_encode.o',
 'i31_fmont.o',
 'i31_iszero.o',
 'i31_moddiv.o',
 'i31_modpow.o',
 'i31_modpow2.o',
 'i31_montmul.o',
 'i31_muladd.o',
 'i31_ninv31.o',
 'i31_rshift.o',
 'i31_sub.o',
 'i31_tmont.o',
 'i32_div32.o',
 'i62_modpow2.o',
 'rsa_default_pkcs1_vrfy.o',
 'rsa_i31_pkcs1_vrfy.o',
 'rsa_i31_pub.o',
 'rsa_i62_pkcs1_vrfy.o',
 'rsa_i62_pub.o',
 'rsa_pkcs1_sig_unpad.o',
 'asn1enc.o',
 'x509_decoder.o',
 'x509_minimal.o',
 'errors.o',
 'readfile.o',
 'brf.o',
 'vesigned.o',
 'x509_tbs.o',
 'vets.o',
 'xmem.o',
 'vector.o',
 'vectx.o',
 'veopen.o',
 'vepcr.o',
 'verify_file.o',
 'efi_variables.o',
 'efi_init.o']

def efi_sa_library(name, deps, compatible):
    groups = standalone_sa_groups(deps = deps, compatible = compatible,
        prefix = "efi_sa_", early_cflags = _EARLY, cflags = _efi_cflags())
    for group in _EXTRA:
        target = "efi_sa_extra_" + group.name
        cc_library(name = target, srcs = group.sources, copts = _EARLY + _efi_cflags(group.tool_flags) + standalone_sa_arch_cflags(),
            deps = deps, features = ["-opt", "-bsd_ssp", "-bsd_riscv_userland_abi"], linkstatic = True,
            target_compatible_with = compatible)
        groups.append(":" + target)
    bsd_component_archive(name = name, groups = groups,
        object_order = standalone_sa_order(before_zfs = _EXTRA_ORDER),
        target_compatible_with = compatible, visibility = ["//visibility:public"])
