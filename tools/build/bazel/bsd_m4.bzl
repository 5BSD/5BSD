# SPDX-License-Identifier: BSD-2-Clause
"""m4 source generation with explicit includes and execution-tool inputs."""
def _generate(ctx):
    out = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all([out.path, ctx.executable.m4.path, "-D", "SRCDIR=" + ctx.file.src.dirname])
    args.add_all(ctx.attr.flags)
    for root, variable in ctx.attr.directory_defines.items():
        files = root[DefaultInfo].files.to_list()
        if len(files) != 1 or files[0].is_directory:
            fail("directory define requires one source anchor file")
        if not variable or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in variable.elems()]):
            fail("m4 directory define requires an identifier")
        args.add("-D" + variable + "=" + files[0].dirname + "/")
    args.add_all(ctx.files.prefixes)
    args.add(ctx.file.src)
    ctx.actions.run(executable = ctx.executable.redirect, arguments = [args],
        inputs = [ctx.file.src] + ctx.files.includes + ctx.files.prefixes + ctx.files.directory_defines,
        tools = [ctx.attr.m4[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [out], env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "BsdM4")
    return [DefaultInfo(files = depset([out]))]
bsd_m4 = rule(implementation = _generate, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "includes": attr.label_list(allow_files = True),
    "flags": attr.string_list(),
    "prefixes": attr.label_list(allow_files = True, doc = "Ordered m4 input files before the primary source."),
    "directory_defines": attr.label_keyed_string_dict(allow_files = True, doc = "Source anchor file to m4 directory variable name."),
    "output": attr.string(mandatory = True),
    "m4": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
