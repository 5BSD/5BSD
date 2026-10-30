# SPDX-License-Identifier: BSD-2-Clause
"""Expand roff .so includes from an explicitly declared include namespace."""
def _expand(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    includes = []
    directory = None
    for target, relative in ctx.attr.includes.items():
        if relative.startswith("/") or any([p in ["", ".", ".."] for p in relative.split("/")]):
            fail("include paths must be normalized relative paths")
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1:
            fail("each include label must name one file")
        link = ctx.actions.declare_file(ctx.label.name + ".includes/" + relative)
        ctx.actions.symlink(output = link, target_file = files[0])
        includes.append(link)
        directory = link.path[:-(len(relative) + 1)]
    args = [output.path, ctx.executable.soelim.path]
    if includes:
        args += ["-I", directory]
    args.append(ctx.file.src.path)
    ctx.actions.run(executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = args, inputs = [ctx.file.src] + includes + ctx.files.runtime,
        tools = [ctx.attr.soelim[DefaultInfo].files_to_run], outputs = [output],
        env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "BSDSoelim")
    return [DefaultInfo(files = depset([output]))]
bsd_soelim = rule(implementation = _expand, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "includes": attr.label_keyed_string_dict(allow_files = True),
    "output": attr.string(mandatory = True),
    "soelim": attr.label(executable = True, cfg = "exec", mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
