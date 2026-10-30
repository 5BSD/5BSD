# SPDX-License-Identifier: BSD-2-Clause
"""Run the maintained bc string generator with its original relative input names."""
def _quote(value):
    return "'" + value.replace("'", "'\\''") + "'"

def _generate(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    tools = []
    aliases = []
    names = []
    for target, name in ctx.attr.path_tools.items():
        if not name or "/" in name or name in [".", ".."] or name in names:
            fail("tool alias must be a basename")
        tool = target[DefaultInfo].files_to_run
        executable = tool.executable
        if not executable:
            files = target[DefaultInfo].files.to_list()
            if len(files) != 1:
                fail("tool alias must provide one executable file")
            executable = files[0]
        alias = ctx.actions.declare_file(ctx.label.name + ".tools/" + name)
        ctx.actions.symlink(output = alias, target_file = executable, is_executable = True)
        aliases.append(alias)
        tools.append(tool if tool.executable else executable)
        names.append(name)
    source = ctx.file.src
    if not source.path.endswith("/gen/" + source.basename):
        fail("bc generator input must retain its gen/ source layout")
    root = source.dirname[:-len("/gen")]
    if not aliases:
        fail("explicit generator tools required")
    if ctx.file.script.path != root + "/gen/strgen.sh" or ctx.file.helper.path != root + "/scripts/functions.sh":
        fail("generator and helper must share the declared source layout")
    launcher = ctx.actions.declare_file(ctx.label.name + ".launch.sh")
    ctx.actions.write(launcher,
        'root=$(pwd -P)\n' +
        'PATH="$root/"' + _quote(aliases[0].dirname) + '\nexport PATH\n' +
        'TMPDIR="$root/"' + _quote(output.dirname) + '\nexport TMPDIR\n' +
        'out="$root/"' + _quote(output.path) + '\n' +
        'shell="$root/"' + _quote(ctx.executable.shell.path) + '\n' +
        'cd "$root/"' + _quote(root) + '\n' +
        'exec "$shell" gen/strgen.sh ' + _quote("gen/" + source.basename) +
        ' "$out" 0 ' + " ".join([_quote(x) for x in ctx.attr.arguments]) + '\n')
    ctx.actions.run(executable = ctx.attr.shell[DefaultInfo].files_to_run,
        arguments = [launcher.path], inputs = [source, ctx.file.script, ctx.file.helper, launcher] + aliases,
        tools = tools + ctx.files.runtime, outputs = [output],
        env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "BSDCalculatorSource")
    return [DefaultInfo(files = depset([output]))]

calculator_source = rule(implementation = _generate, attrs = {
    "src": attr.label(allow_single_file = True, mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "helper": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "arguments": attr.string_list(mandatory = True),
    "path_tools": attr.label_keyed_string_dict(cfg = "exec", allow_files = True, mandatory = True),
    "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})
