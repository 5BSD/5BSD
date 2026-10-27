# SPDX-License-Identifier: BSD-2-Clause
"""Declared stdout, optional stderr and exit-status tests using Bazel protocol."""
def _compare(ctx):
    if ctx.attr.expected_exit < 0 or ctx.attr.expected_exit > 255:
        fail("expected_exit must be between 0 and 255")
    links = {"test-program/" + ctx.file.program.basename: ctx.file.program,
             "test-data/expected": ctx.file.expected}
    if ctx.file.expected_stderr:
        links["test-data/expected-stderr"] = ctx.file.expected_stderr
    if ctx.file.input:
        links["test-data/input"] = ctx.file.input
    for i, file in enumerate(ctx.files.file_arguments):
        links["test-data/argument-" + str(i)] = file
    for file in ctx.files.runtime_lib:
        key = "test-runtime/lib/" + file.basename
        if key in links:
            fail("duplicate runtime library: " + key)
        links[key] = file
    for target, name in ctx.attr.working_files.items():
        if not name or any([part in ["", ".", ".."] for part in name.split("/")]) or "\\" in name:
            fail("working file path must be normalized and relative: " + name)
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1:
            fail("working file target must produce exactly one file")
        key = "test-work/" + name
        if key in links or any([other.startswith(key + "/") or key.startswith(other + "/") for other in links]):
            fail("working file path collision: " + name)
        links[key] = files[0]
    env = {"BSD_COMPARE_PROGRAM": ctx.file.program.basename,
           "BSD_COMPARE_EXIT": str(ctx.attr.expected_exit),
           "BSD_COMPARE_WORKDIR": "1" if ctx.attr.working_files else "0",
           "BSD_COMPARE_STDERR": "1" if ctx.file.expected_stderr else "0",
           "BSD_COMPARE_ARGC": str(len(ctx.attr.arguments)),
           "BSD_COMPARE_FILE_ARGC": str(len(ctx.files.file_arguments)),
           "BSD_COMPARE_STDIN": "1" if ctx.file.input else "0"}
    for i, arg in enumerate(ctx.attr.arguments):
        env["BSD_COMPARE_ARG_" + str(i)] = arg
    for name, value in ctx.attr.environment.items():
        if name.startswith("BSD_COMPARE_") or name.startswith("TEST_") or name in ["LD_LIBRARY_PATH", "LD_PRELOAD", "LC_ALL"]:
            fail("test environment cannot override runner-controlled variable: " + name)
        if not name or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" for c in name.elems()]):
            fail("invalid test environment entry")
        env[name] = value
    ctx.actions.symlink(output = ctx.outputs.executable, target_file = ctx.executable.runner, is_executable = True)
    runfiles = ctx.runfiles(files = [ctx.executable.runner], symlinks = links).merge_all(
        [target[DefaultInfo].default_runfiles for target in [ctx.attr.runner, ctx.attr.program] + ctx.attr.runtime_lib])
    return [DefaultInfo(executable = ctx.outputs.executable,
                        runfiles = runfiles),
            RunEnvironmentInfo(environment = env)]

bsd_compare_test = rule(
    implementation = _compare, test = True,
    attrs = {
        "program": attr.label(allow_single_file = True, mandatory = True),
        "input": attr.label(allow_single_file = True),
        "file_arguments": attr.label_list(allow_files = True),
        "expected": attr.label(allow_single_file = True, mandatory = True),
        "expected_exit": attr.int(default = 0),
        "expected_stderr": attr.label(allow_single_file = True),
        "arguments": attr.string_list(),
        "environment": attr.string_dict(),
        "working_files": attr.label_keyed_string_dict(allow_files = True),
        "runtime_lib": attr.label_list(allow_files = True),
        "runner": attr.label(executable = True, cfg = "exec", mandatory = True),
    },
)

def _filter(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    environment = {"LC_ALL": "C"}
    if ctx.files.runtime_libraries:
        environment["LD_LIBRARY_PATH"] = ":".join(sorted(depset([f.dirname for f in ctx.files.runtime_libraries]).to_list()))
    ctx.actions.run(
        executable = ctx.executable.redirect,
        arguments = [output.path, ctx.executable.tool.path] + ctx.attr.arguments + [ctx.file.src.path],
        inputs = [ctx.file.src], tools = [ctx.attr.tool[DefaultInfo].files_to_run] + ctx.files.runtime + ctx.files.runtime_libraries,
        outputs = [output], env = environment, use_default_shell_env = False,
        mnemonic = "BSDFilterFixture",
    )
    return [DefaultInfo(files = depset([output]))]

bsd_filter_fixture = rule(
    implementation = _filter,
    attrs = {
        "src": attr.label(allow_single_file = True, mandatory = True),
        "output": attr.string(mandatory = True),
        "tool": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
        "arguments": attr.string_list(),
        "runtime_libraries": attr.label_list(allow_files = True, cfg = "exec"),
    },
)
