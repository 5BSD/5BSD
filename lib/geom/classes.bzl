# SPDX-License-Identifier: BSD-2-Clause
"""Native GEOM class inventory, corresponding to Makefile.classes."""

GEOM_CLASSES = ["label", "mirror", "multipath", "nop", "part", "raid", "zoned"]
GEOM_OPENSSL_CLASSES = ["eli"]

def geom_class_labels(pattern):
    """Select class labels and aliases with the same OpenSSL configuration."""
    return [pattern.format(cls = cls) for cls in GEOM_CLASSES] + select({
        "//tools/build/bazel/config:openssl_enabled": [pattern.format(cls = cls) for cls in GEOM_OPENSSL_CLASSES],
        "//conditions:default": [],
    })
