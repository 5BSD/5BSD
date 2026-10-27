# SPDX-License-Identifier: BSD-2-Clause
"""Typed Kyua properties shared by installed suites and Bazel test adapters."""
def kyua_metadata_fields(encoded, reserved = []):
    metadata = json.decode(encoded)
    if type(metadata) != "dict":
        fail("Kyua metadata must be a JSON object")
    fields = []
    for key, value in metadata.items():
        if not key or key == "name" or key in reserved or key[0] not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_" or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789" for c in key.elems()]):
            fail("invalid or reserved Kyua metadata key: " + key)
        if type(value) not in ["string", "int", "bool"]:
            fail("Kyua metadata values must be strings, integers or booleans")
        fields.append(key + "=" + json.encode(value))
    return fields
