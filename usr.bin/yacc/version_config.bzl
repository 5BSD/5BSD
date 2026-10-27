# SPDX-License-Identifier: BSD-2-Clause
"""Bind the maintained platform configuration to the declared upstream version."""
def _config(ctx):
    output = ctx.actions.declare_file("generated/config.h")
    script = "import pathlib,re,sys; version=pathlib.Path(sys.argv[2]).read_text().strip(); assert re.fullmatch(r'[0-9]+',version), 'invalid byacc VERSION'; pathlib.Path(sys.argv[3]).write_text(pathlib.Path(sys.argv[1]).read_text()+'\\n#define YYPATCH '+version+'\\n')"
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", "-c", script, ctx.file.config.path, ctx.file.version.path, output.path],
        inputs = [ctx.file.config, ctx.file.version, ctx.file.python_home], tools = ctx.files.runtime,
        outputs = [output], env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "ByaccVersionConfig")
    return [DefaultInfo(files = depset([output]))]
version_config = rule(implementation = _config, attrs = {
    "config": attr.label(allow_single_file = True, mandatory = True),
    "version": attr.label(allow_single_file = True, mandatory = True),
    "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "python_home": attr.label(cfg = "exec", allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(cfg = "exec", allow_files = True),
})
