# SPDX-License-Identifier: BSD-2-Clause
"""Run maintained module audits with declared ELF fixtures and native tools.

Host /bin/sh and the SDK Python interpreter's loader remain execution dependencies;
callers keep these tests local and uncached until those are fully modeled.
"""
def _quote(value):
    return "'" + value.replace("'", "'\\''") + "'"

def _impl(ctx):
    prefix = ctx.label.name + ".runtime/"
    links = {prefix + "kldxref": ctx.executable.program, prefix + "audit.py": ctx.file.audit}
    for file in ctx.files.fixtures:
        key = prefix + "fixtures/" + file.basename
        if key in links:
            fail("duplicate fixture basename: " + file.basename)
        links[key] = file
    for file in ctx.files.libraries:
        key = prefix + "lib/" + file.basename
        if key in links:
            fail("duplicate runtime library: " + file.basename)
        links[key] = file
    runner = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(runner, "\n".join([
        "#!/bin/sh", "set -eu", 'root="$TEST_SRCDIR/$TEST_WORKSPACE"',
        'export PYTHONNOUSERSITE=1', 'unset PYTHONPATH LD_LIBRARY_PATH LD_PRELOAD',
        'export PYTHONHOME="$root/"' + _quote(ctx.file.python_home.short_path[:-len(ctx.file.python_home.basename)]),
        'exec "$root/"' + _quote(ctx.executable.python.short_path) + ' -B -s "$root/"' + _quote(ctx.file.adapter.short_path) + ' "$root/"' + _quote(prefix) + ' ' + _quote(ctx.attr.mode),
        "",
    ]), is_executable = True)
    targets = [ctx.attr.program, ctx.attr.python] + ctx.attr.runtime + ctx.attr.libraries + ctx.attr.fixtures
    runfiles = ctx.runfiles(files = [ctx.executable.python, ctx.file.python_home, ctx.file.adapter] + ctx.files.runtime, symlinks = links)
    runfiles = runfiles.merge_all([target[DefaultInfo].default_runfiles for target in targets])
    return [DefaultInfo(executable = runner, runfiles = runfiles)]

kldxref_audit_test = rule(implementation = _impl, test = True, attrs = {
    "program": attr.label(executable = True, cfg = "target", mandatory = True),
    "python": attr.label(executable = True, cfg = "exec", allow_files = True, mandatory = True),
    "python_home": attr.label(allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(allow_files = True),
    "libraries": attr.label_list(allow_files = True, mandatory = True),
    "fixtures": attr.label_list(allow_files = True, mandatory = True),
    "audit": attr.label(allow_single_file = True, mandatory = True),
    "mode": attr.string(values = ["pnp", "module-inputs", "kldxref", "module-artifacts"], mandatory = True),
    "adapter": attr.label(allow_single_file = True, default = ":kldxref_test.py"),
})
