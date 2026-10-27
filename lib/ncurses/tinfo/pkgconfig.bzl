# SPDX-License-Identifier: BSD-2-Clause
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")

def _impl(ctx):
    toolchain = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
        requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    variables = cc_common.create_compile_variables(cc_toolchain = toolchain, feature_configuration = features)
    flags = cc_common.get_memory_inefficient_command_line(
        feature_configuration = features, action_name = ACTION_NAMES.c_compile, variables = variables)
    # Mirror BSD's SSP_CFLAGS metadata using the selected compiler feature's
    # actual flags, rather than assuming SSP is enabled or repeating its value.
    ssp = [flag for flag in flags if flag.startswith("-fstack-protector")]
    settings = ctx.actions.declare_file(ctx.label.name + ".settings.json")
    ctx.actions.write(settings, json.encode({
        "PREFIX": ctx.attr.prefix, "LIBDIR": ctx.attr.libdir, "INCLUDEDIR": ctx.attr.includedir,
        "ABI": str(ctx.attr.abi), "NAME": ctx.attr.module, "DESCRIPTION": ctx.attr.description,
        "REQUIRES": ctx.attr.requires,
        "LINK_FLAGS": "".join([" " + flag for flag in ssp]),
        "LIBRARIES": " ".join(["-l" + lib for lib in ctx.attr.libraries]),
    }))
    output = ctx.actions.declare_file(ctx.attr.module + ".pc")
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._generator.path])
    args.add("--template", ctx.file.template)
    args.add("--version", ctx.file.version)
    args.add("--settings", settings)
    args.add("--output", output)
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args], outputs = [output],
        inputs = [ctx.file.template, ctx.file.version, settings, ctx.file._generator, ctx.file.python_home],
        tools = ctx.files.runtime,
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False, mnemonic = "NcursesPkgConfig")
    return [DefaultInfo(files = depset([output]))]

ncurses_pkgconfig = rule(implementation = _impl, attrs = {
    "module": attr.string(mandatory = True), "abi": attr.int(mandatory = True),
    "description": attr.string(mandatory = True), "requires": attr.string(),
    "libraries": attr.string_list(mandatory = True),
    "prefix": attr.string(default = "/usr"), "libdir": attr.string(default = "/usr/lib"), "includedir": attr.string(default = "/usr/include"),
    "template": attr.label(allow_single_file = True, mandatory = True),
    "version": attr.label(allow_single_file = True, mandatory = True),
    "python": attr.label(executable = True, cfg = "exec", mandatory = True, allow_single_file = True),
    "python_home": attr.label(cfg = "exec", allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(cfg = "exec", allow_files = True),
    "_generator": attr.label(default = Label(":pkgconfig.py"), cfg = "exec", allow_single_file = True),
}, fragments = ["cpp"], toolchains = use_cc_toolchain())
