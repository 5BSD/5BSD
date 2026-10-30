# SPDX-License-Identifier: BSD-2-Clause
"""Build the DTrace generator without instrumenting its own dependency graph.

The consumer applies the exec transition first. This transition changes only
instrumentation settings, preserving that execution platform and toolchain.
"""
def _bootstrap_config(settings, attr):
    return {
        "//tools/build/bazel/config:dtrace": False,
        "//tools/build/bazel/config:experimental_dtrace_section_archives": False,
    }

_bootstrap = transition(
    implementation = _bootstrap_config,
    inputs = [],
    outputs = ["//tools/build/bazel/config:dtrace", "//tools/build/bazel/config:experimental_dtrace_section_archives"],
)

def _impl(ctx):
    ctx.actions.symlink(output = ctx.outputs.executable, target_file = ctx.executable.binary, is_executable = True)
    runtime = depset(ctx.files.runtime_libraries)
    runfiles = ctx.runfiles(transitive_files = runtime).merge(ctx.attr.binary[DefaultInfo].default_runfiles)
    return [DefaultInfo(executable = ctx.outputs.executable, runfiles = runfiles),
            OutputGroupInfo(runtime_libraries = runtime)]

bsd_dtrace_bootstrap = rule(
    implementation = _impl,
    executable = True,
    cfg = _bootstrap,
    attrs = {
        "binary": attr.label(executable = True, cfg = "target", mandatory = True),
        "runtime_libraries": attr.label_list(allow_files = True),
        "_allowlist_function_transition": attr.label(default = "@bazel_tools//tools/allowlists/function_transition_allowlist"),
    },
)
