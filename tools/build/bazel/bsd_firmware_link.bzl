# SPDX-License-Identifier: BSD-2-Clause
"""Freestanding executable link using the selected native C++ toolchain.

Objects have explicit complete order; archives retain ordinary ordered extraction.
No host startup files or system libraries are inferred by this rule.
"""
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("//tools/build/bazel:bsd_object_order.bzl", "ordered_objects")

def _link(ctx):
    if not ctx.attr.object_order:
        fail("firmware link requires an explicit complete object order")
    objects = ordered_objects(ctx.files.objects, ctx.attr.object_order)
    if not objects:
        fail("firmware link requires entry objects")
    archives = []
    for target in ctx.attr.archives:
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1 or files[0].extension != "a":
            fail("each firmware archive must select one native archive")
        archives.append(files[0])
    inputs = objects + archives
    if len(inputs) != len(depset(inputs).to_list()):
        fail("duplicate firmware link inputs")
    toolchain = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
        requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    linker_inputs = []
    for archive in archives:
        library = cc_common.create_library_to_link(actions = ctx.actions,
            feature_configuration = features, cc_toolchain = toolchain,
            static_library = archive)
        linker_inputs.append(cc_common.create_linker_input(owner = ctx.label,
            libraries = depset([library])))
    # Preserve input precedence at this final boundary. No dependency DAG or
    # implicit transitive archive can reorder or expand the selected inventory.
    chain = depset(order = "topological")
    for item in reversed(linker_inputs):
        chain = depset([item], transitive = [chain], order = "topological")
    compilation = cc_common.create_compilation_outputs(objects = depset(objects),
        pic_objects = depset(objects))
    result = cc_common.link(name = ctx.attr.output, actions = ctx.actions,
        feature_configuration = features, cc_toolchain = toolchain,
        compilation_outputs = compilation,
        linking_contexts = [cc_common.create_linking_context(linker_inputs = chain)],
        user_link_flags = ["-nostdlib", "-Wl,-T," + ctx.file.script.path] + ctx.attr.linkopts,
        additional_inputs = [ctx.file.script], output_type = "executable",
        link_deps_statically = True)
    return [DefaultInfo(files = depset([result.executable]))]

bsd_firmware_link = rule(implementation = _link, attrs = {
    "objects": attr.label_list(allow_files = [".o"], mandatory = True),
    "object_order": attr.string_list(mandatory = True),
    "archives": attr.label_list(allow_files = [".a"], mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "linkopts": attr.string_list(),
}, fragments = ["cpp"], toolchains = use_cc_toolchain())
