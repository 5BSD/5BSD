# SPDX-License-Identifier: BSD-2-Clause
"""Compile declared magic fragments using the native execution-platform tool."""
def _database(ctx):
    source = ctx.actions.declare_file(ctx.label.name + "/magic")
    database = ctx.actions.declare_file(ctx.label.name + "/magic.mgc")
    fragments = sorted(ctx.files.fragments, key = _source_path)
    if not fragments:
        fail("magic database requires declared fragments")
    args = ctx.actions.args()
    args.add_all([source.path, ctx.executable.cat.path])
    args.add_all(fragments)
    ctx.actions.run(executable = ctx.executable.redirect, arguments = [args],
        inputs = fragments + ctx.files.cat_runtime,
        tools = [ctx.attr.cat[DefaultInfo].files_to_run], outputs = [source],
        env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "MagicConcatenate")
    ctx.actions.run(executable = ctx.executable.cwd_exec,
        arguments = [database.dirname, ctx.executable.compiler.path, source.basename],
        inputs = [source], tools = [ctx.attr.compiler[DefaultInfo].files_to_run],
        outputs = [database], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "MagicCompile")
    return [DefaultInfo(files = depset([source, database])),
            OutputGroupInfo(source = depset([source]), database = depset([database]))]

def _source_path(file):
    return file.short_path

magic_database = rule(implementation = _database, attrs = {
    "fragments": attr.label_list(allow_files = True, mandatory = True),
    "compiler": attr.label(executable = True, cfg = "exec", mandatory = True),
    "cat": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "cat_runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    "cwd_exec": attr.label(executable = True, cfg = "exec", mandatory = True),
})
