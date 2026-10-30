# SPDX-License-Identifier: BSD-2-Clause
"""Compile program translation units using their configured Make contexts."""
load(":source_identity.bzl", "source_files")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")

def _objects(ctx):
    toolchain = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
        requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    sources = source_files(ctx.files.srcs, ctx.attr.source_keys, "program source")
    if not sources or len(sources) != len(ctx.files.srcs):
        fail("nonempty unique program sources required")
    if sorted(ctx.attr.source_order) != sorted(sources.keys()) or sorted(ctx.attr.source_flags.keys()) != sorted(sources.keys()):
        fail("program object order and flags must cover every source exactly once")
    textual = source_files(ctx.files.textual_inputs, ctx.attr.textual_keys, "textual input")
    context = cc_common.create_compilation_context(headers = depset(ctx.files.hdrs))
    contexts = [context] + [dep[CcInfo].compilation_context for dep in ctx.attr.deps]
    objects = []
    for index, path in enumerate(ctx.attr.source_order):
        source = sources[path]
        private = []
        for name in ctx.attr.source_textual_inputs.get(path, []):
            if name not in textual:
                fail("program source lacks declared textual input: " + name)
            private.append(textual[name])
        _context, compiled = cc_common.compile(
            actions = ctx.actions, feature_configuration = features,
            cc_toolchain = toolchain, srcs = [source], private_hdrs = private,
            compilation_contexts = contexts,
            user_compile_flags = [ctx.expand_make_variables("source_flags", flag, {}) for flag in ctx.attr.source_flags[path]],
            disallow_pic_outputs = not ctx.attr.position_independent,
            disallow_nopic_outputs = ctx.attr.position_independent,
            name = ctx.label.name + "_" + str(index) + "_" + source.basename.replace(".", "_"),
        )
        selected = compiled.pic_objects if ctx.attr.position_independent else compiled.objects
        if len(selected) != 1:
            fail("program translation unit must produce exactly one object: " + path)
        objects.extend(selected)
    # Link these objects directly through cc_binary.srcs. An archive here would
    # change extraction semantics, including constructor-only translation units.
    return [DefaultInfo(files = depset(objects))]

bsd_program_objects = rule(
    implementation = _objects,
    attrs = {
        "position_independent": attr.bool(default = False),
        "srcs": attr.label_list(allow_files = [".c", ".cc", ".cpp", ".cxx", ".C", ".S"], mandatory = True),
        "source_keys": attr.label_keyed_string_dict(allow_files = True),
        "textual_keys": attr.label_keyed_string_dict(allow_files = True),
        "source_order": attr.string_list(mandatory = True),
        "source_flags": attr.string_list_dict(mandatory = True),
        "hdrs": attr.label_list(allow_files = True),
        "textual_inputs": attr.label_list(allow_files = True),
        "source_textual_inputs": attr.string_list_dict(),
        "deps": attr.label_list(providers = [CcInfo]),
    },
    fragments = ["cpp"],
    toolchains = use_cc_toolchain(),
)
