# SPDX-License-Identifier: BSD-2-Clause
"""Shared source-owned NTP compilation policy from the maintained port."""
PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
OPENSSL = "//tools/build/bazel/config:openssl_enabled"

def common_defines():
    return ["SYS_FREEBSD", "PARSE", "HAVE_CONFIG_H"] + select({
        OPENSSL: ["OPENSSL", "AUTOKEY", "USE_OPENSSL_CRYPTO_RAND"],
        "//conditions:default": [],
    })

def common_headers():
    return ["//usr.sbin/ntp:config_headers", "//contrib/ntp:headers",
        "//contrib/ntp:isc_headers", "//contrib/ntp:isc_unix_headers",
        "//contrib/ntp:isc_pthread_headers", "//contrib/ntp:opts_headers"]
