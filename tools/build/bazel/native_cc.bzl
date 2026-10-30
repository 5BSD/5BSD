# SPDX-License-Identifier: BSD-2-Clause
load(":source_identity.bzl", "source_files")
load(":bsd_dtrace.bzl", "BSDDTraceInfo", "dtrace_rewrite")
load(":bsd_fidl.bzl", "BSDFidlBindingsInfo")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")

def _source_alias(ctx):
    output = ctx.outputs.output
    ctx.actions.symlink(output = output, target_file = ctx.file.source)
    return [DefaultInfo(files = depset([output]))]

bsd_source_alias = rule(
    implementation = _source_alias,
    attrs = {
        "source": attr.label(allow_single_file = [".c", ".cc", ".cpp", ".cxx", ".C", ".S"], mandatory = True),
        "output": attr.output(mandatory = True),
    },
)

BSDStaticSourceInfo = provider(fields = ["source", "flags"])

def _static_source(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.symlink(output = output, target_file = ctx.file.source)
    return [DefaultInfo(files = depset([output])),
            BSDStaticSourceInfo(source = output, flags = ctx.attr.copts)]

bsd_static_source = rule(
    implementation = _static_source,
    attrs = {
        "source": attr.label(allow_single_file = [".c", ".cc", ".cpp", ".cxx", ".C"], mandatory = True),
        "output": attr.string(mandatory = True),
        "copts": attr.string_list(),
    },
)

def _library(ctx):
    toolchain = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
        requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    if not cc_common.is_enabled(feature_configuration = features, feature_name = "supports_pic"):
        fail("BSD library requires a toolchain with PIC support")
    # Compile exactly the configured variants, preserving the regular archive
    # even when Bazel optimization mode would otherwise suppress it.
    providers = [dep[BSDDTraceInfo] for dep in ctx.attr.dtrace_providers]
    if len(providers) > 1:
        fail("multiple DTrace providers require composition qualification")
    if providers and not ctx.attr.dtrace_copy_runner:
        fail("DTrace requires an execution-platform copy runner")
    provider_headers = [spec.header for spec in providers]
    bindings = [dep[BSDFidlBindingsInfo] for dep in ctx.attr.fidl_bindings]
    generated_sources = [source for binding in bindings for source in binding.sources]
    generated_headers = [header for binding in bindings for header in binding.headers] + ctx.files.generated_headers
    generated_roots = [binding.include_root for binding in bindings] + depset([header.dirname for header in ctx.files.generated_headers]).to_list()
    # Share the library's public context once. Implementation-only inputs stay
    # private to their source actions and must not propagate to consumers.
    public_context = cc_common.create_compilation_context(
        headers = depset(ctx.files.hdrs + provider_headers + generated_headers),
        includes = depset(ctx.attr.includes + [header.dirname for header in provider_headers] + generated_roots),
    )
    compile_contexts = [public_context] + [dep[CcInfo].compilation_context for dep in ctx.attr.deps]

    if not ctx.attr.variants or ctx.attr.variants[0] != "regular" or len(ctx.attr.variants) != len(depset(ctx.attr.variants).to_list()):
        fail("unique library variants starting with regular required")
    for variant in ctx.attr.variants:
        if variant not in ["regular", "pic", "pie", "nossp_pic"]:
            fail("unsupported library variant: " + variant)
    if ctx.attr.archive_member_order and sorted(ctx.attr.archive_member_order.keys()) != sorted(ctx.attr.variants):
        fail("archive order inventory must cover every configured variant")
    static = [dep[BSDStaticSourceInfo] for dep in ctx.attr.static_sources]
    static_flags = {spec.source.path: spec.flags for spec in static}
    static_sources = [spec.source for spec in static]
    if len(static_flags) != len(static_sources):
        fail("duplicate static-only source")
    configured_sources = source_files(ctx.files.srcs, ctx.attr.source_keys, "library source")
    source_keys = {file.path: key for key, file in configured_sources.items()}
    if ctx.attr.source_variants:
        if sorted(ctx.attr.source_variants.keys()) != sorted(configured_sources.keys()):
            fail("source variant inventory differs from declared sources")
        for path, selected in ctx.attr.source_variants.items():
            if not selected or len(selected) != len(depset(selected).to_list()):
                fail("nonempty unique source variants required: " + path)
            if any([variant not in ctx.attr.variants for variant in selected]):
                fail("source selects an unconfigured variant: " + path)
    textual = source_files(ctx.files.textual_inputs, ctx.attr.textual_keys, "textual input")
    objects_by_variant = {variant: [] for variant in ctx.attr.variants}
    static_archive_objects = []
    for index, source in enumerate(ctx.files.srcs + generated_sources + static_sources):
        source_key = source_keys[source.path] if source.path in source_keys else source.short_path
        cxx = source.extension in ["cc", "cpp", "cxx", "C"]
        flags = (ctx.attr.cxxopts if cxx else ctx.attr.copts) + ctx.attr.per_file_flags.get(source.basename, [])
        if source.extension == "S":
            flags += ctx.attr.assembly_flags
        source_textual = []
        for path in ctx.attr.source_textual_inputs.get(source_key, []):
            if path not in textual:
                fail("missing declared textual input: " + path)
            source_textual.append(textual[path])
        source_variants = ["regular"] if source in static_sources else ctx.attr.source_variants.get(source_key, ctx.attr.variants)
        for variant in source_variants:
            pic = variant in ["pic", "nossp_pic"]
            variant_flags = ctx.attr.cxx_variant_flags if cxx else ctx.attr.variant_flags
            key = source_key + "|" + variant
            if source not in static_sources and source.path in source_keys and ctx.attr.source_variant_flags and key not in ctx.attr.source_variant_flags:
                fail("missing effective source/variant flags: " + key)
            if variant == "nossp_pic" and key not in ctx.attr.source_variant_flags:
                fail("NOSSP requires explicit effective source flags: " + key)
            effective_flags = static_flags[source.path] if source in static_sources else ctx.attr.source_variant_flags.get(key, variant_flags.get(variant, []) + flags)
            _context, compiled = cc_common.compile(
                actions = ctx.actions, feature_configuration = features,
                cc_toolchain = toolchain, srcs = [source], private_hdrs = source_textual,
                user_compile_flags = [ctx.expand_make_variables("copts", flag, {}) for flag in effective_flags],
                compilation_contexts = compile_contexts,
                disallow_pic_outputs = not pic, disallow_nopic_outputs = pic,
                name = ctx.label.name + "_" + variant + "_" + (str(index) + "_" if source in generated_sources else "") + source.basename.replace(".", "_"),
            )
            compiled_objects = compiled.pic_objects if pic else compiled.objects
            expected = ctx.attr.archive_object_names.get(key)
            if expected:
                if "/" in expected or expected in [".", ".."] or len(compiled_objects) != 1:
                    fail("one configured archive member basename required")
                original = compiled_objects[0]
                if original.basename != expected:
                    renamed = ctx.actions.declare_file(ctx.label.name + "/archive-members/" + variant + "/" + expected)
                    ctx.actions.symlink(output = renamed, target_file = original)
                    compiled_objects = [renamed]
            if source in static_sources:
                static_archive_objects.extend(compiled_objects)
            else:
                objects_by_variant[variant].extend(compiled_objects)
    archives = {}
    suffixes = {"regular": ".a", "pic": ".pic.a", "pie": "_pie.a", "nossp_pic": "_nossp_pic.a"}
    for variant in ctx.attr.variants:
        objects = objects_by_variant[variant]
        if not objects and not (variant == "regular" and static_archive_objects and not providers):
            fail("library variant has no ordinary objects: " + variant)
        for index, spec in enumerate(providers):
            rewritten, provider_object = dtrace_rewrite(ctx.actions, spec, objects,
                ctx.attr.dtrace_copy_runner[DefaultInfo].files_to_run,
                ctx.label.name + "_dtrace/" + variant + "/" + str(index),
                ctx.attr.dtrace_object_names.get(variant, spec.source.basename[:-2] + ".o"))
            objects = rewritten + [provider_object]
        # Make passes OBJS (not STATICOBJS) to DTrace and adds STATICOBJS
        # separately to the regular archive after the rewritten objects.
        if variant == "regular":
            objects += static_archive_objects
        if ctx.attr.archive_member_order:
            order = ctx.attr.archive_member_order[variant]
            members = {obj.basename: obj for obj in objects}
            if len(members) != len(objects) or len(order) != len(depset(order).to_list()):
                fail("duplicate archive member requires explicit support: " + variant)
            if sorted(order) != sorted(members.keys()):
                fail("archive members differ from configured inventory: " + variant)
            objects = [members[name] for name in order]
        objects_by_variant[variant] = objects
        suffix = suffixes[variant]
        archive = ctx.actions.declare_file((ctx.attr.archive_basename or "lib" + ctx.label.name) + suffix)
        variables = cc_common.create_link_variables(cc_toolchain = toolchain,
            feature_configuration = features, output_file = archive.path,
            is_using_linker = False, must_keep_debug = True)
        command = cc_common.get_memory_inefficient_command_line(
            feature_configuration = features, action_name = ACTION_NAMES.cpp_link_static_library,
            variables = variables)
        # The public API has no object-list argument. Append ordered objects
        # after the configured options/output; reject any unqualified archiver
        # policy rather than silently discarding it or guessing its syntax.
        if ctx.attr.arflags != ["-crsD"] or command != ["rcsD", archive.path]:
            fail("unsupported archive policy: maintained %s, configured %s" % (ctx.attr.arflags, command))
        args = ctx.actions.args()
        args.add_all(command)
        args.add_all(objects)
        environment = cc_common.get_environment_variables(feature_configuration = features,
            action_name = ACTION_NAMES.cpp_link_static_library, variables = variables)
        environment = dict(environment)
        environment["LC_ALL"] = "C"
        ctx.actions.run(
            executable = cc_common.get_tool_for_action(feature_configuration = features,
                action_name = ACTION_NAMES.cpp_link_static_library),
            arguments = [args], inputs = depset(objects),
            tools = ctx.files.archive_inputs, outputs = [archive],
            mnemonic = "BSDNativeArchive", env = environment,
            use_default_shell_env = False,
        )
        archives[variant] = archive
    library = cc_common.create_library_to_link(actions = ctx.actions,
        feature_configuration = features, cc_toolchain = toolchain,
        static_library = archives["regular"], pic_static_library = archives.get("pic"))
    linking = cc_common.create_linking_context(linker_inputs = depset([
        cc_common.create_linker_input(owner = ctx.label, libraries = depset([library])),
    ]))
    return [DefaultInfo(files = depset([archives["regular"]])),
            cc_common.merge_cc_infos(cc_infos = [CcInfo(compilation_context = public_context, linking_context = linking)] + [dep[CcInfo] for dep in ctx.attr.deps]),
            OutputGroupInfo(nossp_pic_archive = depset([archives["nossp_pic"]] if "nossp_pic" in archives else []),
                            nossp_pic_objects = depset(objects_by_variant.get("nossp_pic", [])),
                            pic_archive = depset([archives["pic"]] if "pic" in archives else []),
                            pie_archive = depset([archives["pie"]] if "pie" in archives else []),
                            regular_objects = depset(objects_by_variant["regular"]),
                            pic_objects = depset(objects_by_variant.get("pic", [])),
                            pie_objects = depset(objects_by_variant.get("pie", [])))]

bsd_library = rule(
    implementation = _library,
    attrs = {
        "srcs": attr.label_list(allow_files = [".c", ".S", ".cc", ".cpp", ".cxx", ".C"], mandatory = True),
        "hdrs": attr.label_list(allow_files = True),
        "generated_headers": attr.label_list(allow_files = True),
        "arflags": attr.string_list(mandatory = True),
        "archive_basename": attr.string(),
        "archive_inputs": attr.label(allow_files = True, cfg = "exec", mandatory = True),
        "variants": attr.string_list(default = ["regular", "pic"]),
        "variant_flags": attr.string_list_dict(),
        "cxx_variant_flags": attr.string_list_dict(),
        "deps": attr.label_list(providers = [CcInfo]),
        "dtrace_providers": attr.label_list(providers = [BSDDTraceInfo]),
        "dtrace_copy_runner": attr.label(executable = True, cfg = "exec"),
        "copts": attr.string_list(),
        "cxxopts": attr.string_list(),
        "fidl_bindings": attr.label_list(providers = [BSDFidlBindingsInfo]),
        "static_sources": attr.label_list(providers = [BSDStaticSourceInfo]),
        "assembly_flags": attr.string_list(),
        "textual_inputs": attr.label_list(allow_files = True),
        "source_keys": attr.label_keyed_string_dict(allow_files = True),
        "textual_keys": attr.label_keyed_string_dict(allow_files = True),
        "source_textual_inputs": attr.string_list_dict(),
        "archive_object_names": attr.string_dict(),
        "archive_member_order": attr.string_list_dict(),
        "dtrace_object_names": attr.string_dict(),
        "per_file_flags": attr.string_list_dict(),
        "source_variant_flags": attr.string_list_dict(),
        "source_variants": attr.string_list_dict(),
        "includes": attr.string_list(),
    },
    fragments = ["cpp"],
    toolchains = use_cc_toolchain(),
)

def _shared_alias(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.symlink(output = output, target_file = ctx.file.library)
    return [DefaultInfo(files = depset([output]), runfiles = ctx.runfiles(files = [output, ctx.file.library]))]

bsd_shared_alias = rule(
    implementation = _shared_alias,
    attrs = {
        "library": attr.label(allow_single_file = True, mandatory = True),
        "output": attr.string(mandatory = True),
    },
)


def _template(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    if len(ctx.files.tools) != len(ctx.attr.tools):
        fail("each template tool must select exactly one executable file")
    ctx.actions.run(
        executable = ctx.executable.shell,
        arguments = [ctx.file.script.path, ctx.file.template.path, output.path] + [f.path for f in ctx.files.tools] + ctx.attr.arguments,
        inputs = [ctx.file.script, ctx.file.template] + ctx.files.dependencies,
        tools = ctx.files.tools + ctx.files.execution_runtime,
        outputs = [output], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDTemplateGenerate",
    )
    return [DefaultInfo(files = depset([output]))]

bsd_template = rule(
    implementation = _template,
    attrs = {
        "script": attr.label(allow_single_file = True, mandatory = True),
        "template": attr.label(allow_single_file = True, mandatory = True),
        "dependencies": attr.label_list(allow_files = True),
        "output": attr.string(mandatory = True),
        "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "tools": attr.label_list(allow_files = True, cfg = "exec", mandatory = True),
        "execution_runtime": attr.label_list(allow_files = True, cfg = "exec"),
        "arguments": attr.string_list(mandatory = True),
    },
)
