# SPDX-License-Identifier: BSD-2-Clause
"""Archive explicitly selected component groups with ordinary or PIC objects.

Unlike cc_static_library's transitive PIC preference, the installed BSD archive
contract selects a variant and includes only these groups' own objects. External
link dependencies remain the responsibility of the component's normal CcInfo.
"""
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

def _impl(ctx):
    toolchain = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
        requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    objects = []
    for group in ctx.attr.groups:
        selected = []
        for item in group[CcInfo].linking_context.linker_inputs.to_list():
            if item.owner == group.label:
                for library in item.libraries:
                    selected += library.pic_objects if ctx.attr.pic else library.objects
        if not selected:
            fail("component group has no requested object variant: " + str(group.label))
        objects += selected
    if len(depset(objects).to_list()) != len(objects):
        fail("component groups contain duplicate object inputs")
    compilation = cc_common.create_compilation_outputs(
        objects = depset([] if ctx.attr.pic else objects),
        pic_objects = depset(objects if ctx.attr.pic else []))
    _, outputs = cc_common.create_linking_context_from_compilation_outputs(
        actions = ctx.actions, name = ctx.label.name, cc_toolchain = toolchain,
        feature_configuration = features, compilation_outputs = compilation,
        disallow_dynamic_library = True)
    library = outputs.library_to_link
    archive = library.pic_static_library if ctx.attr.pic else library.static_library
    if archive == None:
        fail("toolchain did not produce the requested archive variant")
    return [DefaultInfo(files = depset([archive]))]

bsd_component_archive = rule(implementation = _impl,
    attrs = {"groups": attr.label_list(providers = [CcInfo], mandatory = True),
             "pic": attr.bool(default = False)},
    toolchains = use_cc_toolchain(), fragments = ["cpp"])


def _object(ctx):
    objects = []
    group = ctx.attr.group
    for item in group[CcInfo].linking_context.linker_inputs.to_list():
        if item.owner == group.label:
            for library in item.libraries:
                objects += library.pic_objects if ctx.attr.pic else library.objects
    if len(objects) != 1:
        fail("single component object required for " + str(group.label))
    ctx.actions.symlink(output = ctx.outputs.out, target_file = objects[0])
    return [DefaultInfo(files = depset([ctx.outputs.out]))]

# Installed startup objects need a stable filename, without an archive wrapper.
bsd_component_object = rule(implementation = _object, attrs = {
    "group": attr.label(providers = [CcInfo], mandatory = True),
    "pic": attr.bool(default = False),
    "out": attr.output(mandatory = True),
})


def _selected_objects(ctx):
    group = ctx.attr.group
    available = {}
    for item in group[CcInfo].linking_context.linker_inputs.to_list():
        if item.owner == group.label:
            for library in item.libraries:
                for obj in (library.pic_objects if ctx.attr.pic else library.objects):
                    if obj.basename in available:
                        fail("ambiguous component object basename: " + obj.basename)
                    available[obj.basename] = obj
    requested = ctx.attr.object_names
    if not requested or len(requested) != len(depset(requested).to_list()):
        fail("component object selection must be nonempty and unique")
    missing = [name for name in requested if name not in available]
    if missing:
        fail("component object selection absent from " + str(group.label) + ": " + str(missing))
    # Forward declared compiler outputs directly: no archive extraction action,
    # filesystem search, or transitive link dependency can expand this selection.
    return [DefaultInfo(files = depset([available[name] for name in requested]))]

bsd_component_selected_objects = rule(implementation = _selected_objects, attrs = {
    "group": attr.label(providers = [CcInfo], mandatory = True),
    "pic": attr.bool(default = False),
    "object_names": attr.string_list(mandatory = True),
})


def _all_objects(ctx):
    group = ctx.attr.group
    objects = []
    for item in group[CcInfo].linking_context.linker_inputs.to_list():
        if item.owner == group.label:
            for library in item.libraries:
                objects += library.pic_objects if ctx.attr.pic else library.objects
    if not objects or len(objects) != len(depset(objects).to_list()):
        fail("component must expose a nonempty unique object set: " + str(group.label))
    # Preserve full artifact paths, including equal basenames in subdirectories.
    return [DefaultInfo(files = depset(objects))]

bsd_component_objects = rule(implementation = _all_objects, attrs = {
    "group": attr.label(providers = [CcInfo], mandatory = True),
    "pic": attr.bool(default = False),
})


_ComponentSources = provider(fields = ["sources"])

def _sources_aspect_impl(target, ctx):
    if not hasattr(ctx.rule.files, "srcs"):
        fail("component has no declared srcs: " + str(target.label))
    return [_ComponentSources(sources = ctx.rule.files.srcs)]

_sources_aspect = aspect(implementation = _sources_aspect_impl)

def _sources_impl(ctx):
    rows = []
    seen = {}
    for group in ctx.attr.groups:
        sources = group[_ComponentSources].sources
        if not sources:
            fail("component has no selected sources: " + str(group.label))
        for source in sources:
            if source.path in seen:
                fail("duplicate component source: " + source.path)
            seen[source.path] = True
        rows.append({"label": str(group.label), "sources": sorted([f.short_path for f in sources])})
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(output, json.encode_indent({"components": rows}) + "\n")
    return [DefaultInfo(files = depset([output]))]

# Resolve source selections in Bazel analysis; no parsing of BUILD or Make files.
bsd_component_sources = rule(implementation = _sources_impl, attrs = {
    "groups": attr.label_list(aspects = [_sources_aspect], mandatory = True),
})
