# SPDX-License-Identifier: BSD-2-Clause
"""Explicit trust-header generation; no ambient policy or certificate discovery."""

def _path(file):
    return file.short_path

def _headers(ctx):
    outputs = [ctx.actions.declare_file(ctx.label.name + "/" + name)
               for name in ["ta.h", "vse.h", "secureboot_config.h"]]
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._driver.path, "--policy", ctx.file.policy.path,
                  "--output", outputs[0].dirname])
    args.add_all(sorted(ctx.files.anchors, key = _path), before_each = "--anchor")
    args.add_all(sorted(ctx.files.verification, key = _path), before_each = "--verification")
    ctx.actions.run(
        executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [ctx.file.policy, ctx.file._driver, ctx.file.python_home] + ctx.files.anchors + ctx.files.verification,
        tools = ctx.files.runtime,
        outputs = outputs,
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "BSDSecurebootHeaders",
    )
    return [DefaultInfo(files = depset(outputs))]

bsd_secureboot_headers = rule(implementation = _headers, attrs = {
    "policy": attr.label(allow_single_file = True, mandatory = True),
    "anchors": attr.label_list(allow_files = True),
    "verification": attr.label_list(allow_files = True),
    "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "_driver": attr.label(default = Label("//tools/build/bazel:secureboot_headers.py"), allow_single_file = True),
})
