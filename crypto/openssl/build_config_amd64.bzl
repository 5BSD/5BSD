# SPDX-License-Identifier: BSD-2-Clause
"""Selected amd64 OpenSSL build defaults shared by crypto, SSL and CLI."""
AMD64_DEFINES = [
    "L_ENDIAN", "OPENSSL_CPUID_OBJ", "OPENSSL_IA32_SSE2",
    "OPENSSL_BN_ASM_MONT", "OPENSSL_BN_ASM_MONT5", "OPENSSL_BN_ASM_GF2m",
    "SHA1_ASM", "SHA256_ASM", "SHA512_ASM", "KECCAK1600_ASM", "RC4_ASM",
    "MD5_ASM", "AES_ASM", "BSAES_ASM", "VPAES_ASM", "WHIRLPOOL_ASM",
    "GHASH_ASM", "CMLL_ASM", "ECP_NISTZ256_ASM", "X25519_ASM",
    "PADLOCK_ASM", "POLY1305_ASM", "NDEBUG",
    'OPENSSLDIR=\\"/etc/ssl\\"', 'ENGINESDIR=\\"/usr/lib/engines-3\\"',
    'MODULESDIR=\\"/usr/lib/ossl-modules\\"',
]
