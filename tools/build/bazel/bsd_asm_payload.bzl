# SPDX-License-Identifier: BSD-2-Clause
"""Compile maintained assembly with declared binary .incbin payloads."""
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")

def _assemble(ctx):
    toolchain = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
        requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    names = [f.basename for f in ctx.files.payloads]
    if len(names) != len(depset(names).to_list()):
        fail("assembly payload basenames must be unique")
    _, objects = cc_common.compile(actions = ctx.actions,
        feature_configuration = features, cc_toolchain = toolchain,
        srcs = [ctx.file.src], additional_inputs = ctx.files.payloads,
        user_compile_flags = ["-I" + d for d in depset([f.dirname for f in ctx.files.payloads]).to_list()] + ctx.attr.copts,
        disallow_pic_outputs = True, name = ctx.label.name)
    return [DefaultInfo(files = depset(objects.objects))]

bsd_asm_payload = rule(implementation = _assemble,
    attrs = {
        "src": attr.label(allow_single_file = [".s", ".S"], mandatory = True),
        "payloads": attr.label_list(allow_files = True, mandatory = True),
        "copts": attr.string_list(),
    }, fragments = ["cpp"], toolchains = use_cc_toolchain())
