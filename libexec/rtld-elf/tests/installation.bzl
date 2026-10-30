# SPDX-License-Identifier: BSD-2-Clause
"""Shared source-owned rtld test installation inventory."""
TEST_PROGRAMS = ["dlopen_hash_test", "dlopen_test", "ld_library_pathfds",
    "ld_preload_fds", "parse_integer_test", "set_var_test", "signature_verify_test"]
TEST_MANIFESTS = ["//libexec/rtld-elf/tests:install_" + program for program in TEST_PROGRAMS] + [
    "//libexec/rtld-elf/tests:install_metadata",
    "//libexec/rtld-elf/tests/target:install_manifest",
    "//libexec/rtld-elf/tests/libpythagoras:install_manifest",
] + ["//libexec/rtld-elf/tests/rtld_deepbind:install_" + name
    for name in ["val", "val2", "deep", "program", "metadata"]]
TEST_DIRECTORIES = {path: json.encode({"owner": "root", "group": "wheel", "mode": "0755",
    "tags": ["package=tests"] + (["dbg"] if path.startswith("/usr/lib/debug/") else [])})
    for path in ["/usr/tests/libexec/rtld-elf", "/usr/lib/debug/usr", "/usr/lib/debug/usr/tests",
        "/usr/lib/debug/usr/tests/libexec", "/usr/lib/debug/usr/tests/libexec/rtld-elf",
        "/usr/tests/libexec/rtld-elf/rtld_deepbind",
        "/usr/lib/debug/usr/tests/libexec/rtld-elf/rtld_deepbind"]}
