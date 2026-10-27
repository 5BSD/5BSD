# SPDX-License-Identifier: BSD-2-Clause
"""A declared native linker GROUP, preserving archive rescanning semantics."""
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")


def _group(ctx):
    members = []
    transitive_runfiles = []
    for target in ctx.attr.members:
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1:
            fail("GROUP member must identify exactly one native artifact")
        member = files[0]
        if member in members:
            fail("repeated native GROUP member")
        members.append(member)
        transitive_runfiles.append(target[DefaultInfo].default_runfiles)
    if not members:
        fail("empty native GROUP")
    script = ctx.actions.declare_file(ctx.label.name + ".ifso")
    # Artifact paths are execroot-relative declared inputs, not installed paths.
    # Quote each path for the linker grammar rather than interpolating options.
    paths = []
    for member in members:
        if '"' in member.path or "\\" in member.path or "\n" in member.path:
            fail("unsupported native GROUP artifact path")
        paths.append('"' + member.path + '"')
    ctx.actions.write(script, "GROUP ( " + " ".join(paths) + " )\n")
    shared = ctx.attr.shared_member_indices
    if not shared or shared[0] != 0 or len(shared) != len(depset(shared).to_list()):
        fail("GROUP requires distinct shared member indices starting with zero")
    toolchain = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
        requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    namespace = "/".join([part for part in [ctx.label.workspace_name, ctx.label.package, ctx.label.name] if part])
    runtime = []
    basenames = []
    main = None
    for index in shared:
        if index < 0 or index >= len(members):
            fail("GROUP shared member index is out of range")
        member = members[index]
        if member.basename in basenames:
            fail("ambiguous GROUP runtime library basename")
        basenames.append(member.basename)
        # Keep group-only shared members beside the primary runtime library.
        # Their symbols are linked through the GROUP, not added a second time.
        library = cc_common.create_library_to_link(
            actions = ctx.actions, feature_configuration = features, cc_toolchain = toolchain,
            dynamic_library = member,
            dynamic_library_symlink_path = namespace + "/" + member.basename,
            interface_library = script if index == 0 else None,
            interface_library_symlink_path = namespace + "/" + script.basename if index == 0 else "",
        )
        runtime.append(library.dynamic_library)
        if index == 0:
            main = library
    linker_input = cc_common.create_linker_input(
        owner = ctx.label,
        libraries = depset([main]),
        additional_inputs = depset([script] + members + runtime),
    )
    return [
        DefaultInfo(files = depset([script]),
                    runfiles = ctx.runfiles(files = members + runtime).merge_all(transitive_runfiles)),
        CcInfo(linking_context = cc_common.create_linking_context(
            linker_inputs = depset([linker_input]))),
    ]

bsd_link_group = rule(
    implementation = _group,
    attrs = {
        "members": attr.label_list(allow_files = True, mandatory = True),
        "shared_member_indices": attr.int_list(default = [0]),
    },
    fragments = ["cpp"],
    toolchains = use_cc_toolchain(),
)
