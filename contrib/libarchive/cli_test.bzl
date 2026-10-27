# SPDX-License-Identifier: BSD-2-Clause
"""Run upstream CLI suites with declared executables, fixtures and native DSOs.

The suites still call host shell utilities and optional external compressors.
Callers mark tests local and noncacheable until those runtimes are modeled.
"""
def _test(ctx):
    prefix = ctx.label.name + ".runtime/"
    links = {prefix + "harness": ctx.executable.harness, prefix + "program": ctx.executable.program}
    for file in ctx.files.references:
        key = prefix + "references/" + file.basename
        if key in links:
            fail("duplicate reference basename: " + file.basename)
        links[key] = file
    for target, soname in ctx.attr.libraries.items():
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1 or "/" in soname or not soname:
            fail("one shared artifact and a basename required for " + str(target.label))
        key = prefix + "lib/" + soname
        if key in links:
            fail("duplicate runtime SONAME: " + soname)
        links[key] = files[0]
    runner = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(runner, """#!/bin/sh
set -eu
root="$TEST_SRCDIR/$TEST_WORKSPACE/%s"
exec /usr/bin/env -i PATH=/bin:/usr/bin:/usr/local/bin LC_ALL=C TMPDIR="$TEST_TMPDIR" LD_LIBRARY_PATH="$root/lib" "$root/harness" -p "$root/program" -r "$root/references" -v
""" % prefix, is_executable = True)
    targets = [ctx.attr.harness, ctx.attr.program] + ctx.attr.libraries.keys()
    runfiles = ctx.runfiles(symlinks = links).merge_all([target[DefaultInfo].default_runfiles for target in targets])
    return [DefaultInfo(executable = runner, runfiles = runfiles)]
archive_cli_test = rule(implementation = _test, test = True, attrs = {
    "harness": attr.label(executable = True, cfg = "target", mandatory = True),
    "program": attr.label(executable = True, cfg = "target", mandatory = True),
    "references": attr.label_list(allow_files = True, mandatory = True),
    "libraries": attr.label_keyed_string_dict(allow_files = True, mandatory = True),
})

def archive_cli_suite(name, harness, program, references):
    libraries = {
        "//lib/libarchive:archive_shared": "libarchive.so.7",
        "//lib/libz:z_shared": "libz.so.6",
        "//lib/libbz2:bz2_shared": "libbz2.so.4",
        "//lib/liblzma:lzma_shared": "liblzma.so.5",
        "//lib/libexpat:bsdxml_shared": "libbsdxml.so.4",
        "//lib/libzstd:zstd_shared": "libprivatezstd.so.5",
        "//lib/libmd:md_shared": "libmd.so.7",
    }
    archive_cli_test(name = name, harness = harness, program = program, references = references,
        libraries = select({"//tools/build/bazel/config:openssl_enabled": dict(libraries, **{"//secure/lib/libcrypto:crypto_shared": "libcrypto.so.35"}), "//conditions:default": libraries}),
        tags = ["local", "no-cache"], size = "medium")
