# SPDX-License-Identifier: BSD-2-Clause
"""Generate character mapper indexes from explicit policy and source fragments."""
def _indexes(ctx):
    request = ctx.actions.declare_file(ctx.label.name + ".json")
    directory = ctx.actions.declare_file("mapper.dir")
    pivot = ctx.actions.declare_file("charset.pivot")
    ctx.actions.write(request, json.encode({
        "families": json.decode(ctx.attr.families),
        "sources": {file.short_path[len(ctx.label.package) + 1:]: file.path for file in ctx.files.srcs},
    }))
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", ctx.file.script.path, request.path, directory.path, pivot.path],
        inputs = [request, ctx.file.script, ctx.file.python_home] + ctx.files.srcs,
        tools = ctx.files.runtime, outputs = [directory, pivot],
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "CitrusMapperIndex")
    return [DefaultInfo(files = depset([directory, pivot])),
            OutputGroupInfo(directory = depset([directory]), pivot = depset([pivot]))]

citrus_mapper_index = rule(implementation = _indexes, attrs = {
    "families": attr.string(mandatory = True),
    "srcs": attr.label_list(allow_files = True, mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "python": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
