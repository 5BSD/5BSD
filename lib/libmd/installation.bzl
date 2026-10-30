# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned default libmd installation inventory; no Make queries at build time.

Test installation belongs to the tests package and is declared separately.
"""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")

HEADERS = {'md4.h': 'md4.h', 'md5.h': 'md5.h', 'ripemd.h': 'ripemd.h', 'sha.h': 'sha.h', 'sha224.h': '//sys/crypto/sha2:sha224.h', 'sha256.h': '//sys/crypto/sha2:sha256.h', 'sha384.h': '//sys/crypto/sha2:sha384.h', 'sha512.h': '//sys/crypto/sha2:sha512.h', 'sha512t.h': '//sys/crypto/sha2:sha512t.h', 'skein.h': '//sys/crypto/skein:skein.h', 'skein_port.h': '//sys/crypto/skein:skein_port.h', 'skein_freebsd.h': '//sys/crypto/skein:skein_freebsd.h', 'skein_iv.h': '//sys/crypto/skein:skein_iv.h'}
MANUALS = ['md4.3', 'md5.3', 'ripemd.3', 'sha.3', 'sha256.3', 'sha512.3', 'skein.3']
MANUAL_LINKS = [
    ('md4.3', 'MD4Init.3'),
    ('md4.3', 'MD4Update.3'),
    ('md4.3', 'MD4Final.3'),
    ('md4.3', 'MD4End.3'),
    ('md4.3', 'MD4File.3'),
    ('md4.3', 'MD4FileChunk.3'),
    ('md4.3', 'MD4Data.3'),
    ('md5.3', 'MD5Init.3'),
    ('md5.3', 'MD5Update.3'),
    ('md5.3', 'MD5Final.3'),
    ('md5.3', 'MD5End.3'),
    ('md5.3', 'MD5File.3'),
    ('md5.3', 'MD5FileChunk.3'),
    ('md5.3', 'MD5Data.3'),
    ('ripemd.3', 'RIPEMD160_Init.3'),
    ('ripemd.3', 'RIPEMD160_Update.3'),
    ('ripemd.3', 'RIPEMD160_Final.3'),
    ('ripemd.3', 'RIPEMD160_Data.3'),
    ('ripemd.3', 'RIPEMD160_End.3'),
    ('ripemd.3', 'RIPEMD160_File.3'),
    ('ripemd.3', 'RIPEMD160_FileChunk.3'),
    ('sha.3', 'SHA_Init.3'),
    ('sha.3', 'SHA_Update.3'),
    ('sha.3', 'SHA_Final.3'),
    ('sha.3', 'SHA_End.3'),
    ('sha.3', 'SHA_File.3'),
    ('sha.3', 'SHA_FileChunk.3'),
    ('sha.3', 'SHA_Data.3'),
    ('sha.3', 'SHA1_Init.3'),
    ('sha.3', 'SHA1_Update.3'),
    ('sha.3', 'SHA1_Final.3'),
    ('sha.3', 'SHA1_End.3'),
    ('sha.3', 'SHA1_File.3'),
    ('sha.3', 'SHA1_FileChunk.3'),
    ('sha.3', 'SHA1_Data.3'),
    ('sha256.3', 'SHA224_Init.3'),
    ('sha256.3', 'SHA224_Update.3'),
    ('sha256.3', 'SHA224_Final.3'),
    ('sha256.3', 'SHA224_End.3'),
    ('sha256.3', 'SHA224_File.3'),
    ('sha256.3', 'SHA224_FileChunk.3'),
    ('sha256.3', 'SHA224_Data.3'),
    ('sha256.3', 'SHA256_Init.3'),
    ('sha256.3', 'SHA256_Update.3'),
    ('sha256.3', 'SHA256_Final.3'),
    ('sha256.3', 'SHA256_End.3'),
    ('sha256.3', 'SHA256_File.3'),
    ('sha256.3', 'SHA256_FileChunk.3'),
    ('sha256.3', 'SHA256_Data.3'),
    ('sha512.3', 'SHA384_Init.3'),
    ('sha512.3', 'SHA384_Update.3'),
    ('sha512.3', 'SHA384_Final.3'),
    ('sha512.3', 'SHA384_End.3'),
    ('sha512.3', 'SHA384_File.3'),
    ('sha512.3', 'SHA384_FileChunk.3'),
    ('sha512.3', 'SHA384_Data.3'),
    ('sha512.3', 'sha384.3'),
    ('sha512.3', 'SHA512_Init.3'),
    ('sha512.3', 'SHA512_Update.3'),
    ('sha512.3', 'SHA512_Final.3'),
    ('sha512.3', 'SHA512_End.3'),
    ('sha512.3', 'SHA512_File.3'),
    ('sha512.3', 'SHA512_FileChunk.3'),
    ('sha512.3', 'SHA512_Data.3'),
    ('sha512.3', 'SHA512_224_Init.3'),
    ('sha512.3', 'SHA512_224_Update.3'),
    ('sha512.3', 'SHA512_224_Final.3'),
    ('sha512.3', 'SHA512_224_End.3'),
    ('sha512.3', 'SHA512_224_File.3'),
    ('sha512.3', 'SHA512_224_FileChunk.3'),
    ('sha512.3', 'SHA512_224_Data.3'),
    ('sha512.3', 'SHA512_256_Init.3'),
    ('sha512.3', 'SHA512_256_Update.3'),
    ('sha512.3', 'SHA512_256_Final.3'),
    ('sha512.3', 'SHA512_256_End.3'),
    ('sha512.3', 'SHA512_256_File.3'),
    ('sha512.3', 'SHA512_256_FileChunk.3'),
    ('sha512.3', 'SHA512_256_Data.3'),
    ('skein.3', 'SKEIN256_Init.3'),
    ('skein.3', 'SKEIN256_Update.3'),
    ('skein.3', 'SKEIN256_Final.3'),
    ('skein.3', 'SKEIN256_End.3'),
    ('skein.3', 'SKEIN256_File.3'),
    ('skein.3', 'SKEIN256_FileChunk.3'),
    ('skein.3', 'SKEIN256_Data.3'),
    ('skein.3', 'skein256.3'),
    ('skein.3', 'SKEIN512_Init.3'),
    ('skein.3', 'SKEIN512_Update.3'),
    ('skein.3', 'SKEIN512_Final.3'),
    ('skein.3', 'SKEIN512_End.3'),
    ('skein.3', 'SKEIN512_File.3'),
    ('skein.3', 'SKEIN512_FileChunk.3'),
    ('skein.3', 'SKEIN512_Data.3'),
    ('skein.3', 'skein512.3'),
    ('skein.3', 'SKEIN1024_Init.3'),
    ('skein.3', 'SKEIN1024_Update.3'),
    ('skein.3', 'SKEIN1024_Final.3'),
    ('skein.3', 'SKEIN1024_End.3'),
    ('skein.3', 'SKEIN1024_File.3'),
    ('skein.3', 'SKEIN1024_FileChunk.3'),
    ('skein.3', 'SKEIN1024_Data.3'),
    ('skein.3', 'skein1024.3'),
]

def libmd_installation(name):
    entries = []
    native.filegroup(name = name + "_debug_artifact", srcs = [":md_debug"], output_group = "debug_files")
    files = [
        ("archive", ":md", "/usr/lib/libmd.a", ["dev", "package=runtime"]),
        ("shared", ":md_install", "/lib/libmd.so.7", ["package=runtime"]),
        ("debug", ":" + name + "_debug_artifact", "/usr/lib/debug/lib/libmd.so.7.debug", ["dbg", "package=runtime"]),
    ]
    for header, source in HEADERS.items():
        files.append(("header_" + header, source, "/usr/include/" + header, ["dev", "package=runtime"]))
    man_tags = select({
        "//tools/build/bazel/config:split_manpages_enabled": ["package=runtime-man"],
        "//conditions:default": ["package=runtime-dev"],
    })
    for manual in MANUALS:
        files.append(("manual_" + manual, ":" + manual.removesuffix(".3") + "_manual_gzip", "/usr/share/man/man3/" + manual + ".gz", man_tags))
    for suffix, source, destination, tags in files:
        target = name + "_" + suffix
        bsd_install_file(name = target, src = source, destination = destination,
                         owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    target = name + "_shared_link"
    bsd_install_link(name = target, destination = "/usr/lib/libmd.so", target = "../../lib/libmd.so.7",
                     kind = "symlink", owner = "root", group = "wheel", mode = "0755",
                     install_tags = ["dev", "package=runtime"])
    entries.append(":" + target)
    for source, destination in MANUAL_LINKS:
        target = name + "_alias_" + destination
        bsd_install_link(name = target, destination = "/usr/share/man/man3/" + destination + ".gz",
                         target = "/usr/share/man/man3/" + source + ".gz", kind = "hardlink",
                         owner = "root", group = "wheel", mode = "0444", install_tags = man_tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
