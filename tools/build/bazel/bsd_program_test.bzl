# SPDX-License-Identifier: BSD-2-Clause
"""Run an installable self-checking program using the Bazel test protocol.

Optional runtime libraries are explicit runfiles. This adapter does not enforce
privilege, kernel or ATF metadata, or replace the program's exit status.
"""
def _program_test(ctx):
    if ctx.attr.interface == "plain" and not ctx.executable.runner:
        fail("plain reporting requires the declared program runner")
    program = ctx.attr.program[DefaultInfo]
    if ctx.attr.runtime_lib and not ctx.executable.runner:
        fail("runtime_lib requires a runner")
    executable = ctx.executable.runner or ctx.executable.program
    ctx.actions.symlink(output = ctx.outputs.executable,
        target_file = executable, is_executable = True)
    links = {}
    providers = [program.default_runfiles] + [target[DefaultInfo].default_runfiles for target in ctx.attr.data]
    if ctx.executable.runner:
        links["program-bin/" + ctx.executable.program.basename] = ctx.executable.program
        providers.append(ctx.attr.runner[DefaultInfo].default_runfiles)
    for file in ctx.files.runtime_lib:
        key = "program-runtime/lib/" + file.basename
        if key in links:
            fail("duplicate runtime library: " + key)
        links[key] = file
    providers.extend([target[DefaultInfo].default_runfiles for target in ctx.attr.runtime_lib])
    result = [DefaultInfo(executable = ctx.outputs.executable,
        runfiles = ctx.runfiles(files = [executable, ctx.executable.program] + ctx.files.data, symlinks = links).merge_all(providers))]
    if ctx.executable.runner:
        result.append(RunEnvironmentInfo(environment = {
            "BSD_TEST_PROGRAM": ctx.executable.program.basename,
            "BSD_TEST_INTERFACE": ctx.attr.interface,
            "BSD_TEST_RUNTIME": "1" if ctx.files.runtime_lib else "0",
        }))
    return result

bsd_program_test = rule(implementation = _program_test, test = True, attrs = {
    "interface": attr.string(default = "native", values = ["native", "plain"],
        doc = "Native preserves child XML; plain preserves child XML as an artifact and uses process status, matching Kyua plain semantics."),
    "program": attr.label(executable = True, cfg = "target", mandatory = True),
    "data": attr.label_list(allow_files = True, doc = "Declared test scripts and fixtures, included in runfiles."),
    "runtime_lib": attr.label_list(allow_files = True),
    "runner": attr.label(executable = True, cfg = "exec"),
})
