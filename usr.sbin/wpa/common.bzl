# SPDX-License-Identifier: BSD-2-Clause
"""Maintained WPA Makefile.inc/Makefile.crypto configuration, owned by source."""
load("@bazel_skylib//lib:selects.bzl", "selects")
OPENSSL = "//tools/build/bazel/config:openssl_enabled"
EAPOL = "//tools/build/bazel/config:wpa_supplicant_eapol_enabled"
INET6 = "//tools/build/bazel/config:inet6_enabled"
PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]

_BASE = [
    "-DCONFIG_DRIVER_BSD", "-DCONFIG_DRIVER_WIRED", "-DCONFIG_DRIVER_RADIUS_ACL",
    "-DCONFIG_CTRL_IFACE", "-DCONFIG_CTRL_IFACE_UNIX", "-DCONFIG_IEEE80211AC",
    "-DCONFIG_IEEE80211AX", "-DCONFIG_IEEE80211BE", "-DCONFIG_IEEE80211N",
    "-DCONFIG_IEEE80211R", "-DCONFIG_IEEE80211W",
    '-DTLS_DEFAULT_CIPHERS=\\"DEFAULT:!EXP:!LOW\\"',
    "-DCONFIG_DEBUG_SYSLOG", "-DCONFIG_DEBUG_FILE", "-DPKCS12_FUNCS", "-DCONFIG_GAS",
    "-DCONFIG_PEERKEY", "-DCONFIG_PRIVSEP", "-DCONFIG_SMARTCARD", "-DCONFIG_TDLS",
    "-DCONFIG_TERMINATE_ONLASTIF", "-DCONFIG_TLS=openssl", "-DCONFIG_MATCH_IFACE",
    "-DCONFIG_PTKSA_CACHE", "-DEAP_SERVER", "-DEAP_SERVER_GTC", "-DEAP_SERVER_IDENTITY",
    "-DEAP_SERVER_MD5", "-DEAP_SERVER_MSCHAPV2", "-DEAP_SERVER_PEAP", "-DEAP_SERVER_TLS",
    "-DEAP_SERVER_TTLS", "-DEAP_SERVER_WSC", "-DEAP_TLS_FUNCS", "-DCONFIG_WNM",
    "-DCONFIG_MBO", "-DCONFIG_RSN_PREAUTH", "-DCONFIG_WEP", "-DCONFIG_LIBWPA",
    "-DCONFIG_SAE", "-DNEED_AP_MLME", "-Wno-incompatible-function-pointer-types",
    "-Wno-undefined-internal",
]
_EAPOL = ["-DCONFIG_HS20", "-DEAP_GTC", "-DEAP_LEAP", "-DEAP_MD5", "-DEAP_MSCHAPv2",
    "-DEAP_OTP", "-DEAP_PEAP", "-DEAP_PSK", "-DEAP_TLS", "-DEAP_TTLS", "-DEAP_WSC",
    "-DIEEE8021X_EAPOL", "-DCONFIG_INTERWORKING", "-DCONFIG_WPS", "-DCONFIG_WPS2",
    "-DCONFIG_WPS_UPNP", "-DCONFIG_WPS_OOB"]
# Exact WARNS=0 Clang policy. In particular, Make does not enable -Werror here.
_WARNINGS = ["-Wno-format-zero-length", "-Wno-pointer-sign", "-Wdate-time", "-Wno-empty-body",
    "-Wno-string-plus-int", "-Wno-unused-const-variable", "-Wno-error=unused-but-set-parameter",
    "-Wno-error=cast-function-type-mismatch", "-Wno-tautological-compare", "-Wno-unused-value",
    "-Wno-parentheses-equality", "-Wno-unused-function", "-Wno-enum-conversion",
    "-Wno-unused-local-typedef", "-Wno-address-of-packed-member", "-Wno-switch",
    "-Wno-switch-enum", "-Wno-knr-promoted-parameter", "-Wno-parentheses"]

def inc_flags():
    return _BASE + select({EAPOL: _EAPOL, "//conditions:default": []}) + select({
        OPENSSL: ["-DCONFIG_PASN"], "//conditions:default": [],
    })

def crypto_flags():
    return select({OPENSSL: ["-DCONFIG_SHA256", "-DCONFIG_ECC", "-DEAP_TLS_OPENSSL"],
        "//conditions:default": ["-DCONFIG_CRYPTO_INTERNAL", "-DCONFIG_INTERNAL_LIBTOMMATH",
            "-DCONFIG_TLS_INTERNAL_CLIENT", "-DCONFIG_SHA256", "-DCONFIG_SHA384", "-DCONFIG_SHA512"],
    }) + ["-DALL_DH_GROUPS"]

def compiler_flags():
    return ["-pipe", "-fno-common", "-std=gnu17"] + _WARNINGS + ["-Qunused-arguments"]

def crypto_sources():
    prefix = select({OPENSSL: ["//contrib/wpa:src/crypto/aes-siv.c", "//contrib/wpa:src/crypto/crypto_openssl.c", "//contrib/wpa:src/crypto/random.c", "//contrib/wpa:src/crypto/sha1-prf.c",
        "//contrib/wpa:src/crypto/sha256-kdf.c", "//contrib/wpa:src/crypto/sha256-prf.c", "//contrib/wpa:src/crypto/sha256-tlsprf.c", "//contrib/wpa:src/crypto/sha384-prf.c", "//contrib/wpa:src/crypto/sha384-tlsprf.c",
        "//contrib/wpa:src/crypto/sha512.c", "//contrib/wpa:src/crypto/tls_openssl.c", "//contrib/wpa:src/crypto/tls_openssl_ocsp.c"],
        "//conditions:default": ["//contrib/wpa:src/crypto/crypto_internal.c", "//contrib/wpa:src/crypto/random.c", "//contrib/wpa:src/crypto/crypto_internal-cipher.c",
            "//contrib/wpa:src/crypto/crypto_internal-modexp.c", "//contrib/wpa:src/crypto/crypto_internal-rsa.c", "//contrib/wpa:src/crypto/tls_internal.c", "//contrib/wpa:src/crypto/aes-unwrap.c",
            "//contrib/wpa:src/crypto/aes-wrap.c", "//contrib/wpa:src/crypto/aes-internal.c", "//contrib/wpa:src/crypto/aes-internal-dec.c", "//contrib/wpa:src/crypto/aes-internal-enc.c", "//contrib/wpa:src/crypto/aes-cbc.c"],
    })
    # AES-SIV in the OpenSSL archive needs CTR even without EAPOL/EAX.
    # Keep its original position and exactly one member when both are enabled.
    eapol = select({EAPOL: ["//contrib/wpa:src/crypto/aes-eax.c"], "//conditions:default": []}) + selects.with_or({
        (OPENSSL, EAPOL): ["//contrib/wpa:src/crypto/aes-ctr.c"],
        "//conditions:default": [],
    }) + select({EAPOL: ["//contrib/wpa:src/crypto/aes-encblock.c"], "//conditions:default": []})
    hashes = select({OPENSSL: [], "//conditions:default": ["//contrib/wpa:src/crypto/des-internal.c", "//contrib/wpa:src/crypto/md4-internal.c",
        "//contrib/wpa:src/crypto/md5.c", "//contrib/wpa:src/crypto/md5-internal.c", "//contrib/wpa:src/crypto/rc4.c", "//contrib/wpa:src/crypto/sha1-internal.c", "//contrib/wpa:src/crypto/sha1-pbkdf2.c", "//contrib/wpa:src/crypto/sha1.c",
        "//contrib/wpa:src/crypto/sha1-prf.c", "//contrib/wpa:src/crypto/sha256.c", "//contrib/wpa:src/crypto/sha256-internal.c", "//contrib/wpa:src/crypto/sha256-prf.c", "//contrib/wpa:src/crypto/sha384.c",
        "//contrib/wpa:src/crypto/sha384-internal.c", "//contrib/wpa:src/crypto/sha384-prf.c", "//contrib/wpa:src/crypto/sha384-tlsprf.c", "//contrib/wpa:src/crypto/sha512.c",
        "//contrib/wpa:src/crypto/sha512-internal.c", "//contrib/wpa:src/crypto/sha512-prf.c"],
    })
    # Preserve Make's archive member order, including the conditional DH5 entry.
    tail = ["//contrib/wpa:src/crypto/sha1-tlsprf.c"] + select({OPENSSL: [], "//conditions:default": ["//contrib/wpa:src/crypto/dh_group5.c"]}) + ["//contrib/wpa:src/crypto/dh_groups.c", "//contrib/wpa:src/crypto/ms_funcs.c"]
    return prefix + eapol + ["//contrib/wpa:src/crypto/aes-omac1.c"] + hashes + tail
