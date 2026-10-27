# SPDX-License-Identifier: BSD-2-Clause
"""Upstream file fixtures with explicit database and runtime dependencies."""

def _fixture(ctx):
    links = {"test-program/file": ctx.file.program,
             "test-data/expected": ctx.file.expected,
             "test-data/argument-0": ctx.file.fixture,
             "test-adapter/compare": ctx.executable.compare}
    magic_env = {}
    for i, magic in enumerate(ctx.files.magic):
        leaf = str(i) + "/" + magic.basename
        links["test-magic/" + leaf] = magic
        magic_env["FILE_MAGIC_" + str(i)] = leaf
    if ctx.file.flags:
        links["test-data/flags"] = ctx.file.flags
    for library in ctx.files.runtime_lib:
        key = "test-runtime/lib/" + library.basename
        if key in links:
            fail("duplicate runtime library: " + key)
        links[key] = library
    ctx.actions.symlink(output = ctx.outputs.executable, target_file = ctx.executable.runner, is_executable = True)
    runfiles = ctx.runfiles(files = [ctx.executable.runner], symlinks = links)
    runfiles = runfiles.merge_all([t[DefaultInfo].default_runfiles for t in
        [ctx.attr.runner, ctx.attr.compare, ctx.attr.program] + ctx.attr.runtime_lib])
    return [DefaultInfo(executable = ctx.outputs.executable, runfiles = runfiles),
        RunEnvironmentInfo(environment = dict(magic_env, **{
            "BSD_COMPARE_PROGRAM": "file", "BSD_COMPARE_EXIT": "0",
            "BSD_COMPARE_STDERR": "0", "BSD_COMPARE_STDIN": "0",
            "BSD_COMPARE_FILE_ARGC": "1", "FILE_MAGIC_COUNT": str(len(ctx.files.magic)),
            "FILE_HAS_FLAGS": "1" if ctx.file.flags else "0",
        }))]

file_fixture_test = rule(implementation = _fixture, test = True, attrs = {
    "program": attr.label(allow_single_file = True, mandatory = True),
    "fixture": attr.label(allow_single_file = True, mandatory = True),
    "expected": attr.label(allow_single_file = True, mandatory = True),
    "flags": attr.label(allow_single_file = True),
    "magic": attr.label_list(allow_files = True, mandatory = True),
    "runtime_lib": attr.label_list(allow_files = True),
    "runner": attr.label(executable = True, cfg = "exec", mandatory = True),
    "compare": attr.label(executable = True, cfg = "exec", mandatory = True),
})
