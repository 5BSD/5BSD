# SPDX-License-Identifier: BSD-2-Clause
"""Generate kernel version C with declared compiler and source identity."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")

def _impl(ctx):
    revision = ctx.attr.revision[BuildSettingInfo].value
    if not revision:
        fail("kernel_source_revision must explicitly identify the source revision or archive")
    toolchain = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
        requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    compiler = cc_common.get_tool_for_action(feature_configuration = features, action_name = ACTION_NAMES.c_compile)
    compiler_inputs = ctx.attr.compiler_inputs[DefaultInfo].files
    if compiler not in [f.path for f in compiler_inputs.to_list()]:
        fail("compiler_inputs must contain the selected C toolchain compiler")
    output = ctx.actions.declare_file(ctx.label.name + "/vers.c")
    aliases = []
    tools = [ctx.attr.shell[DefaultInfo].files_to_run]
    for name in ["awk", "sed", "cat"]:
        tool = getattr(ctx.attr, name)[DefaultInfo].files_to_run
        alias = ctx.actions.declare_file(ctx.label.name + ".tools/" + name)
        ctx.actions.symlink(output = alias, target_file = tool.executable, is_executable = True)
        aliases.append(alias)
        tools.append(tool)
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._runner.path])
    for name in ["script", "param", "copyright", "template", "identity"]:
        args.add("--" + name, getattr(ctx.file, name))
    args.add("--compiler", compiler)
    args.add("--shell", ctx.executable.shell)
    args.add("--path", aliases[0].dirname)
    args.add("--revision", revision)
    args.add("--branch", ctx.attr.branch[BuildSettingInfo].value)
    args.add("--output", output)
    args.add_all(ctx.files.libraries, before_each = "--library")
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], outputs = [output], tools = tools,
        inputs = depset([ctx.file._runner, ctx.file.python_home, ctx.file.script, ctx.file.param,
            ctx.file.copyright, ctx.file.template, ctx.file.identity] + aliases + ctx.files.runtime + ctx.files.libraries,
            transitive = [compiler_inputs]),
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "BSDKernelVersion")
    return [DefaultInfo(files = depset([output]))]

bsd_kernel_version = rule(implementation = _impl, attrs = {
    "script": attr.label(allow_single_file = True, default = "//sys/conf:newvers.sh"),
    "param": attr.label(allow_single_file = True, default = "//sys/sys:param.h"),
    "copyright": attr.label(allow_single_file = True, default = "//:COPYRIGHT"),
    "template": attr.label(allow_single_file = True, default = "//share/examples/etc:bsd-style-copyright"),
    "identity": attr.label(allow_single_file = True, mandatory = True),
    "revision": attr.label(providers = [BuildSettingInfo], default = "//tools/build/bazel/config:kernel_source_revision"),
    "branch": attr.label(providers = [BuildSettingInfo], default = "//tools/build/bazel/config:version_branch"),
    "compiler_inputs": attr.label(mandatory = True),
    "awk": attr.label(executable = True, cfg = "exec", default = "//usr.bin/awk:awk"),
    "sed": attr.label(executable = True, cfg = "exec", default = "//usr.bin/sed:sed"),
    "cat": attr.label(executable = True, cfg = "exec", default = "//bin/cat:cat"),
    "shell": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "python": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "python_home": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "libraries": attr.label_list(allow_files = True, cfg = "exec"),
    "_runner": attr.label(allow_single_file = True, default = "//tools/build/bazel:kernel_version.py"),
}, fragments = ["cpp"], toolchains = use_cc_toolchain())
