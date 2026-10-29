# SPDX-License-Identifier: BSD-2-Clause
"""Declared native SNMP daemon tree and OID generation."""
def _generate(ctx):
    tree = ctx.actions.declare_file(ctx.label.name + "/" + ctx.attr.prefix + "tree.c")
    header = ctx.actions.declare_file(ctx.label.name + "/" + ctx.attr.prefix + "tree.h")
    oid = ctx.actions.declare_file(ctx.label.name + "/" + ctx.attr.prefix + "oid.h")
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file.driver.path, "--generator", ctx.executable.generator.path,
                  "--source", ctx.file.source.path, "--output-dir", tree.dirname])
    args.add("--prefix", ctx.attr.prefix)
    if ctx.attr.local_includes:
        args.add("--local-includes")
    for file in ctx.files.includes:
        args.add("--include", file)
    for symbol in ctx.attr.symbols:
        args.add("--symbol", symbol)
    ctx.actions.run(executable = ctx.executable.python, arguments = [args],
        inputs = [ctx.file.driver, ctx.file.source] + ctx.files.includes,
        tools = [ctx.attr.generator[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [tree, header, oid], mnemonic = "BsdSnmpTree",
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"})
    return [DefaultInfo(files = depset([tree, header, oid])),
            OutputGroupInfo(source = depset([tree]), headers = depset([header, oid]))]

snmp_tree = rule(implementation = _generate, attrs = {
    "prefix": attr.string(),
    "local_includes": attr.bool(default = True),
    "source": attr.label(mandatory = True, allow_single_file = True),
    "includes": attr.label_list(allow_files = True),
    "symbols": attr.string_list(mandatory = True),
    "generator": attr.label(mandatory = True, executable = True, cfg = "exec"),
    "driver": attr.label(mandatory = True, allow_single_file = True, cfg = "exec"),
    "python": attr.label(mandatory = True, executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(mandatory = True, allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
