# SPDX-License-Identifier: BSD-2-Clause
"""Apply original crunchide to a private combined object with its original name.

The input is an already linked ET_REL object. Its declared program basename is
passed from an owned output directory, preserving crunchide's filename-derived
symbol names. A transparent .o alias makes the result a normal C/C++ link input.
"""
_NAME_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"

def _impl(ctx):
    name = ctx.attr.program_name
    if not name or name in [".", ".."] or name.startswith("-") or any([c not in _NAME_CHARS for c in name.elems()]):
        fail("crunchide program name must be a canonical basename")
    keep = ctx.attr.keep_symbols
    if any([not symbol for symbol in keep]) or len(depset(keep).to_list()) != len(keep):
        fail("crunchide keep symbols must be nonempty and unique")
    source = ctx.file.input_object
    directory = ctx.label.name + ".generated/"
    original = ctx.actions.declare_file(directory + name + ".lo")
    alias = ctx.actions.declare_file(directory + name + ".o")
    runtime = []
    basenames = [original.basename, alias.basename]
    for library in ctx.files.libraries:
        if library.basename in basenames:
            fail("duplicate crunchide runtime basename: " + library.basename)
        basenames.append(library.basename)
        link = ctx.actions.declare_file(directory + library.basename)
        ctx.actions.symlink(output = link, target_file = library)
        runtime.append(link)
    args = ctx.actions.args()
    args.add_all(["--copy", source.path, original.path, "--", ctx.executable.cwd_runner.path,
                  original.dirname, ctx.executable.tool.path])
    for symbol in keep:
        args.add_all(["-k", symbol])
    args.add(original.basename)
    ctx.actions.run(executable = ctx.attr.copy_runner[DefaultInfo].files_to_run,
        arguments = [args], inputs = [source] + runtime + ctx.files.libraries,
        tools = [ctx.attr.cwd_runner[DefaultInfo].files_to_run, ctx.attr.tool[DefaultInfo].files_to_run],
        outputs = [original], env = {"LC_ALL": "C", "PATH": "", "LD_LIBRARY_PATH": ".",
                                     "DTRACE_DOF_INIT_DISABLE": "1"},
        use_default_shell_env = False, mnemonic = "BSDCrunchide")
    ctx.actions.symlink(output = alias, target_file = original)
    return [DefaultInfo(files = depset([alias])),
            OutputGroupInfo(original_name = depset([original]), execution_tool = depset([ctx.executable.tool]))]

bsd_crunchide = rule(implementation = _impl, attrs = {
    "input_object": attr.label(allow_single_file = [".o", ".lo"], mandatory = True),
    "program_name": attr.string(mandatory = True),
    "keep_symbols": attr.string_list(mandatory = True, doc = "Explicit keep list; an empty list deliberately hides all definitions."),
    "tool": attr.label(executable = True, cfg = "exec", default = "//usr.sbin/crunch/crunchide:crunchide"),
    "copy_runner": attr.label(executable = True, cfg = "exec", default = "//tools/build/bazel:dtrace_copy_runner"),
    "cwd_runner": attr.label(executable = True, cfg = "exec", default = "//tools/build/bazel:cwd_exec"),
    "libraries": attr.label_list(allow_files = True, cfg = "exec", default = [
        "@bsd_sdk//toolchain:sysroot/lib/libc.so.7",
        "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7",
    ]),
})
