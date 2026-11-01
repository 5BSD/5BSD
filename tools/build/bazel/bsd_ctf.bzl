# SPDX-License-Identifier: BSD-2-Clause
"""CTF conversion of a cc_library's own objects, preserving normal CcInfo deps."""
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("@rules_cc//cc/common:cc_shared_library_hint_info.bzl", "CcSharedLibraryHintInfo")

load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

def _convert(ctx):
    if ctx.attr.ctf_label and ctx.attr.ctf_label_setting:
        fail("select ctf_label or ctf_label_setting")
    source = ctx.attr.library
    regular = []
    pic = []
    dependencies = []
    flags = []
    additional = []
    alwayslink = False
    for item in source[CcInfo].linking_context.linker_inputs.to_list():
        if item.owner != source.label:
            dependencies.append(item)
        else:
            if getattr(item, "linkstamps", []):
                fail("CTF linkstamp composition is not yet supported")
            flags += item.user_link_flags
            additional += item.additional_inputs
            for lib in item.libraries:
                alwayslink = alwayslink or lib.alwayslink
                regular += lib.objects
                pic += lib.pic_objects
    if not regular and not pic:
        fail("CTF requires the selected library's own compilation objects")
    converted = {}
    if ctx.attr.enabled:
        label = ctx.attr.ctf_label_setting[BuildSettingInfo].value if ctx.attr.ctf_label_setting else ctx.attr.ctf_label
        if not label:
            fail("an explicit CTF label is required")
        runtime_dirs = depset([f.dirname for f in ctx.files.runtime]).to_list()
        for variant, objects in [("regular", regular), ("pic", pic)]:
            if len(depset(objects).to_list()) != len(objects):
                fail("duplicate CTF object inputs")
            outputs = []
            for index, obj in enumerate(objects):
                # ctfmerge sorts input paths before merging types. Put the object
                # basename before the collision discriminator so unique-basename
                # inputs retain the same ordering as ordinary Make objects.
                # The index still distinguishes equal-basename input objects.
                out = ctx.actions.declare_file(ctx.label.name + "/" + variant + "/" + obj.basename + "/" + str(index) + "/" + obj.basename)
                ctx.actions.run(executable = ctx.attr.converter[DefaultInfo].files_to_run,
                    arguments = (["-g"] if ctx.attr.preserve_debug else []) + ["-l", label, "-o", out.path, obj.path],
                    inputs = [obj], tools = ctx.files.runtime, outputs = [out],
                    env = {"LC_ALL": "C", "LD_LIBRARY_PATH": ":".join(runtime_dirs)},
                    use_default_shell_env = False, mnemonic = "BSDCtfConvert")
                outputs.append(out)
            converted[variant] = outputs
    else:
        converted = {"regular": regular, "pic": pic}
    toolchain = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
        requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    compilation = cc_common.create_compilation_outputs(objects = depset(converted["regular"]), pic_objects = depset(converted["pic"]))
    own, outputs = cc_common.create_linking_context_from_compilation_outputs(
        actions = ctx.actions, name = ctx.label.name, cc_toolchain = toolchain,
        feature_configuration = features, compilation_outputs = compilation,
        user_link_flags = flags, additional_inputs = additional, alwayslink = alwayslink, disallow_dynamic_library = True)
    context = cc_common.create_linking_context(linker_inputs = depset(transitive = [own.linker_inputs, depset(dependencies)]))
    archives = [f for f in [outputs.library_to_link.static_library, outputs.library_to_link.pic_static_library] if f != None]
    return [DefaultInfo(files = depset(archives)),
        CcInfo(compilation_context = source[CcInfo].compilation_context, linking_context = context),
        CcSharedLibraryHintInfo(attributes = ["library"], owners = [ctx.label]),
        OutputGroupInfo(regular_objects = depset(converted["regular"]), pic_objects = depset(converted["pic"]),
            regular_archive = depset([outputs.library_to_link.static_library] if outputs.library_to_link.static_library else []),
            pic_archive = depset([outputs.library_to_link.pic_static_library] if outputs.library_to_link.pic_static_library else []))]

bsd_ctf_library = rule(implementation = _convert, provides = [CcInfo, CcSharedLibraryHintInfo],
    attrs = {"library": attr.label(providers = [CcInfo], mandatory = True),
        "converter": attr.label(executable = True, cfg = "exec", mandatory = True),
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
        "enabled": attr.bool(default = True),
        "ctf_label": attr.string(),
        "ctf_label_setting": attr.label(providers = [BuildSettingInfo]),
        "preserve_debug": attr.bool(default = False)},
    toolchains = use_cc_toolchain(), fragments = ["cpp"])


def _merge(ctx):
    if ctx.attr.ctf_label and ctx.attr.ctf_label_setting:
        fail("choose either ctf_label or ctf_label_setting")
    out = ctx.actions.declare_file(ctx.attr.output)
    if not ctx.attr.enabled:
        ctx.actions.symlink(output = out, target_file = ctx.file.linked)
        return [DefaultInfo(files = depset([out]))]
    label = ctx.attr.ctf_label_setting[BuildSettingInfo].value if ctx.attr.ctf_label_setting else ctx.attr.ctf_label
    if not label:
        fail("an explicit CTF label is required")
    if not ctx.files.objects:
        fail("CTF merge requires explicit converted object inputs")
    # ctfmerge sorts paths internally. Give inputs a common directory and
    # basename-first ordering independent of their originating Bazel package.
    # Symlinks retain declared dependencies without copying object contents.
    objects = []
    for index, obj in enumerate(ctx.files.objects):
        staged = ctx.actions.declare_file(ctx.label.name + "/merge_inputs/" + obj.basename + "/" + str(index) + "/" + obj.basename)
        ctx.actions.symlink(output = staged, target_file = obj)
        objects.append(staged)
    args = ctx.actions.args()
    args.add_all(["--copy-executable" if ctx.attr.is_executable else "--copy", ctx.file.linked.path, out.path,
        "--", ctx.executable.merger.path] + (["-g"] if ctx.attr.preserve_debug else []) + ["-l", label, "-o", out.path])
    args.add_all(objects)
    ctx.actions.run(executable = ctx.attr.copy_runner[DefaultInfo].files_to_run,
        arguments = [args], inputs = [ctx.file.linked] + objects,
        tools = [ctx.attr.merger[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [out], env = {"LC_ALL": "C", "LD_LIBRARY_PATH": ":".join(depset([f.dirname for f in ctx.files.runtime]).to_list())},
        use_default_shell_env = False, mnemonic = "BSDCtfMerge")
    return [DefaultInfo(files = depset([out]))]

bsd_ctf_merge = rule(implementation = _merge, attrs = {
    "linked": attr.label(allow_single_file = True, mandatory = True),
    "objects": attr.label_list(allow_files = True, mandatory = True),
    "merger": attr.label(executable = True, cfg = "exec", mandatory = True),
    "copy_runner": attr.label(executable = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
    "enabled": attr.bool(default = True),
    "output": attr.string(mandatory = True),
    "ctf_label": attr.string(),
    "ctf_label_setting": attr.label(providers = [BuildSettingInfo]),
    "preserve_debug": attr.bool(default = False),
    "is_executable": attr.bool(default = False),
})
