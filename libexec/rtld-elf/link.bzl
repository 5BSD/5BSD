# SPDX-License-Identifier: BSD-2-Clause
"""Freestanding rtld link with a declared map and mandatory dependency checks."""
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _impl(ctx):
    tc = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = tc,
        requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    objects = []
    for group in ctx.attr.groups:
        own = []
        for item in group[CcInfo].linking_context.linker_inputs.to_list():
            if item.owner == group.label:
                for library in item.libraries:
                    own += library.pic_objects
        if not own:
            fail("rtld group has no own PIC objects: " + str(group.label))
        objects += own
    if len(objects) != len(depset(objects).to_list()):
        fail("duplicate rtld compilation objects")
    linkmap = ctx.actions.declare_file(ctx.label.name + ".map")
    linked = cc_common.link(actions = ctx.actions, name = ctx.label.name,
        feature_configuration = features, cc_toolchain = tc, output_type = "dynamic_library",
        compilation_outputs = cc_common.create_compilation_outputs(pic_objects = depset(objects)),
        linking_contexts = [dep[CcInfo].linking_context for dep in ctx.attr.deps],
        user_link_flags = ["-nostdlib", "-Wl,-Bsymbolic,-z,defs", "-Wl,-e," + ctx.attr.entry,
            "-Wl,--version-script=" + ctx.file.version_map.path,
            "-Wl,-Map=" + linkmap.path, "-Wl,--cref"],
        additional_inputs = [ctx.file.version_map], additional_outputs = [linkmap], stamp = 0)
    raw = linked.library_to_link.dynamic_library
    checked = ctx.actions.declare_file(ctx.attr.output)
    report = ctx.actions.declare_file(ctx.label.name + ".check.json")
    ctx.actions.run(executable = ctx.executable.python,
        arguments = ["-B", ctx.file.checker.path, raw.path, linkmap.path, checked.path, report.path],
        inputs = [raw, linkmap, ctx.file.checker, ctx.file.python_home] + ctx.files.runtime,
        tools = [ctx.attr.python[DefaultInfo].files_to_run], outputs = [checked, report],
        env = {"LC_ALL": "C", "PYTHONHOME": ctx.file.python_home.dirname},
        use_default_shell_env = False, mnemonic = "BSDRtldLinkCheck")
    return [DefaultInfo(files = depset([checked, linkmap, report])),
            OutputGroupInfo(binary = depset([checked]), linkmap = depset([linkmap]))]

bsd_rtld_link = rule(implementation = _impl, attrs = {
    "groups": attr.label_list(providers = [CcInfo], mandatory = True),
    "deps": attr.label_list(providers = [CcInfo]),
    "version_map": attr.label(allow_single_file = True, mandatory = True),
    "entry": attr.string(mandatory = True), "output": attr.string(mandatory = True),
    "checker": attr.label(allow_single_file = True, default = Label(":link_check.py")),
    "python": attr.label(executable = True, allow_single_file = True, cfg = "exec", mandatory = True),
    "python_home": attr.label(allow_single_file = True, mandatory = True),
    "runtime": attr.label_list(allow_files = True),
}, toolchains = use_cc_toolchain(), fragments = ["cpp"])
