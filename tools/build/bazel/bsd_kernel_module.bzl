# SPDX-License-Identifier: BSD-2-Clause
"""Declared relocatable module linking and maintained export-policy actions.

The caller supplies the architecture linker script/emulation and selected SDK
linker closure. Shared-object module formats and PREFIX_SYMS remain separate.
"""

def _link(ctx):
    if not ctx.files.objects:
        fail("module link requires ordered object inputs")
    if len(depset(ctx.files.objects).to_list()) != len(ctx.files.objects):
        fail("duplicate module object inputs")
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all(["-m", ctx.attr.emulation, "-warn-common", "--build-id=sha1", "-T", ctx.file.script.path, "-r", "-o", output.path])
    args.add_all(ctx.files.objects)
    args.use_param_file("@%s", use_always = True)
    ctx.actions.run(executable = ctx.attr.linker[DefaultInfo].files_to_run,
        arguments = [args], inputs = ctx.files.objects + [ctx.file.script],
        tools = ctx.files.linker_inputs, outputs = [output], env = {"LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "BSDModuleLink")
    return [DefaultInfo(files = depset([output]))]

bsd_module_link = rule(implementation = _link, attrs = {
    "objects": attr.label_list(allow_files = True, mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "emulation": attr.string(mandatory = True),
    "output": attr.string(mandatory = True),
    "linker": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "linker_inputs": attr.label_list(allow_files = True, cfg = "exec"),
})

def _exports(ctx):
    if ctx.attr.exports and ctx.file.exports_file:
        fail("supply an export list or an export file, not both")
    listing = ctx.actions.declare_file(ctx.label.name + ".symbols")
    options = ctx.actions.declare_file(ctx.label.name + ".options")
    output = ctx.actions.declare_file(ctx.attr.output)
    exports = ctx.file.exports_file
    if not exports:
        exports = ctx.actions.declare_file(ctx.label.name + ".exports")
        ctx.actions.write(exports, "".join([symbol + "\n" for symbol in ctx.attr.exports]))
    ctx.actions.run(executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = [listing.path, ctx.executable.nm.path, "-g", ctx.file.src.path],
        inputs = [ctx.file.src], tools = [ctx.attr.nm[DefaultInfo].files_to_run] + ctx.files.tool_inputs,
        outputs = [listing], env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "BSDModuleSymbols")
    ctx.actions.run(executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = [options.path, ctx.executable.awk.path, "-v", "modname=" + ctx.file.src.basename,
            "-f", ctx.file.policy.path, listing.path, exports.path],
        inputs = [ctx.file.policy, listing, exports],
        tools = [ctx.attr.awk[DefaultInfo].files_to_run] + ctx.files.libraries,
        outputs = [options], env = {"LC_ALL": "C", "LD_LIBRARY_PATH": ":".join(depset([f.dirname for f in ctx.files.libraries]).to_list())},
        use_default_shell_env = False, mnemonic = "BSDModuleExportPolicy")
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", ctx.file._runner.path, ctx.executable.objcopy.path,
            options.path, ctx.file.src.path, output.path],
        inputs = [ctx.file._runner, ctx.file.python_home, options, ctx.file.src] + ctx.files.runtime,
        tools = [ctx.attr.objcopy[DefaultInfo].files_to_run] + ctx.files.tool_inputs,
        outputs = [output], env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1"},
        use_default_shell_env = False, mnemonic = "BSDModuleExports")
    return [DefaultInfo(files = depset([output])), OutputGroupInfo(symbol_listing = depset([listing]), export_options = depset([options]))]

bsd_module_exports = rule(implementation = _exports, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "exports": attr.string_list(),
    "exports_file": attr.label(allow_single_file = True, doc = "Preprocessed list: one symbol per line, without comments."),
    "output": attr.string(mandatory = True),
    "policy": attr.label(allow_single_file = True, default = "//sys/conf:kmod_syms.awk"),
    "nm": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "objcopy": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "awk": attr.label(executable = True, cfg = "exec", default = "//usr.bin/awk:awk"),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    "tool_inputs": attr.label_list(allow_files = True, cfg = "exec"),
    "libraries": attr.label_list(allow_files = True, cfg = "exec"),
    "python": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "_runner": attr.label(allow_single_file = True, default = "//tools/build/bazel:module_exports.py"),
})
