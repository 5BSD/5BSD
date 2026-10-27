# SPDX-License-Identifier: BSD-2-Clause
"""Native FIDL schema compilation with explicit execution tools and inputs."""

BSDFidlIrInfo = provider(doc = "Compiled FIDL IR and its ordered schema inputs.", fields = ["ir", "schemas"])

def _compile(ctx):
    if not ctx.files.schemas:
        fail("FIDL requires ordered schemas, dependencies first")
    flags = ctx.attr.flags
    explicit_available = any([flag == "--available" or flag.startswith("--available=") for flag in flags])
    if ctx.attr.available and not explicit_available:
        flags = ["--available", ctx.attr.available] + flags
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    args = ctx.actions.args()
    args.add_all(["--json", output.path])
    args.add_all(flags)
    for schema in ctx.files.schemas:
        args.add("--files")
        args.add(schema)
    environment = {"LC_ALL": "C"}
    if ctx.files.runtime_libraries:
        environment["LD_LIBRARY_PATH"] = ":".join(depset([f.dirname for f in ctx.files.runtime_libraries]).to_list())
    ctx.actions.run(
        executable = ctx.attr.compiler[DefaultInfo].files_to_run,
        arguments = [args], inputs = ctx.files.schemas,
        tools = ctx.files.runtime + ctx.files.runtime_libraries, outputs = [output],
        env = environment, use_default_shell_env = False,
        mnemonic = "BSDFidlCompile",
    )
    return [DefaultInfo(files = depset([output])),
            BSDFidlIrInfo(ir = output, schemas = ctx.files.schemas)]

bsd_fidl_ir = rule(
    implementation = _compile,
    attrs = {
        "schemas": attr.label_list(allow_files = [".fidl"], mandatory = True),
        "available": attr.string(),
        "flags": attr.string_list(),
        "compiler": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
        "runtime_libraries": attr.label_list(allow_files = True, cfg = "exec"),
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    },
)

BSDFidlBindingsInfo = provider(doc = "Declared generated binding sources and headers.", fields = ["sources", "headers", "include_root"])

def _bindings(ctx):
    paths = ctx.attr.sources + ctx.attr.headers
    if not ctx.attr.sources or not ctx.attr.headers or len(paths) != len(depset(paths).to_list()):
        fail("unique generated source and header paths required")
    for path in paths:
        if path.startswith("/") or ".." in path.split("/"):
            fail("generated outputs must stay under their binding root")
    if not ctx.files.templates:
        fail("explicit FIDL templates required")
    template_roots = depset([f.dirname for f in ctx.files.templates]).to_list()
    if len(template_roots) != 1:
        fail("FIDL templates must share a declared directory")
    outputs = [ctx.actions.declare_file(ctx.label.name + "/" + path) for path in paths]
    root = outputs[0].path[:-len(paths[0])].rstrip("/")
    args = ctx.actions.args()
    args.add("-S")
    args.add(ctx.file.generator)
    args.add_all(["--ir", ctx.attr.ir[BSDFidlIrInfo].ir.path, "--out", root,
                  "--templates", template_roots[0]])
    for path in paths:
        args.add_all(["--expected-output", path])
    ctx.actions.run(
        executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [ctx.attr.ir[BSDFidlIrInfo].ir, ctx.file.generator, ctx.file.python_home] + ctx.files.modules + ctx.files.templates,
        tools = ctx.files.runtime, outputs = outputs,
        env = {"LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONNOUSERSITE": "1", "PYTHONHOME": ctx.file.python_home.dirname},
        use_default_shell_env = False, mnemonic = "BSDFidlBindings",
    )
    sources = outputs[:len(ctx.attr.sources)]
    headers = outputs[len(ctx.attr.sources):]
    return [DefaultInfo(files = depset(outputs)),
            BSDFidlBindingsInfo(sources = sources, headers = headers, include_root = root),
            OutputGroupInfo(sources = depset(sources), headers = depset(headers))]

bsd_fidl_bindings = rule(
    implementation = _bindings,
    attrs = {
        "ir": attr.label(providers = [BSDFidlIrInfo], mandatory = True),
        "generator": attr.label(allow_single_file = [".py"], mandatory = True),
        "modules": attr.label_list(allow_files = [".py"]),
        "templates": attr.label_list(allow_files = True, mandatory = True),
        "sources": attr.string_list(mandatory = True),
        "headers": attr.string_list(mandatory = True),
        "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
        "python": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    },
)
