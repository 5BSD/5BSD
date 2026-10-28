# SPDX-License-Identifier: BSD-2-Clause
"""Build encoding indexes from owned layout metadata and declared alias files."""
def _index(ctx):
    layout = ctx.actions.declare_file(ctx.label.name + ".layout")
    directory = ctx.actions.declare_file("esdb.dir")
    aliases = ctx.actions.declare_file("esdb.alias")
    rows = []
    for row in ctx.attr.layout:
        fields = row.split("\t")
        if fields[0] == "E":
            fields[-1] = ctx.files.aliases[int(fields[-1])].path
        rows.append("\t".join(fields))
    ctx.actions.write(layout, "\n".join(rows) + "\n")
    ctx.actions.run(executable = ctx.executable.awk,
        arguments = ["-v", "layout=" + layout.path, "-v", "directory=" + directory.path,
            "-v", "aliases=" + aliases.path, "-f", ctx.file.script.path] +
            [f.path for f in ctx.files.aliases] + [layout.path],
        inputs = ctx.files.aliases + [layout, ctx.file.script], outputs = [directory, aliases],
        env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "CitrusIndex")
    return [DefaultInfo(files = depset([directory, aliases])),
            OutputGroupInfo(directory = depset([directory]), aliases = depset([aliases]))]

citrus_index = rule(implementation = _index, attrs = {
    "layout": attr.string_list(mandatory = True),
    "aliases": attr.label_list(allow_files = True, mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "awk": attr.label(executable = True, cfg = "exec", mandatory = True),
})
