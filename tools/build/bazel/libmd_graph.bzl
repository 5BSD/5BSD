# SPDX-License-Identifier: BSD-2-Clause
"""Candidate declared libmd actions; requires rules_cc 0.2.17 qualification."""
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")

def _generate(ctx):
    out = ctx.outputs.output
    inputs = [ctx.file.script, ctx.file.template]
    tools = [ctx.executable.sed, ctx.executable.mv, ctx.executable.rm]
    arguments = [ctx.file.script.path] + ctx.attr.arguments + [ctx.file.template.path]
    if ctx.attr.kind == "manual":
        if ctx.file.copyright == None or ctx.executable.cat == None:
            fail("manual generation requires declared copyright and cat inputs")
        tools.append(ctx.executable.cat)
        inputs.append(ctx.file.copyright)
        arguments.append(ctx.file.copyright.path)
    arguments += [out.path, ctx.executable.sed.path]
    if ctx.attr.kind == "manual":
        arguments.append(ctx.executable.cat.path)
    arguments += [ctx.executable.mv.path, ctx.executable.rm.path]
    ctx.actions.run(
        executable = ctx.executable.shell,
        arguments = arguments,
        inputs = inputs,
        tools = tools + ctx.files.execution_runtime,
        env = {"LC_ALL": "C"},
        use_default_shell_env = False,
        outputs = [out],
        mnemonic = "BSDLibmdGenerate",
    )
    return [DefaultInfo(files = depset([out]))]

libmd_generated = rule(
    implementation = _generate,
    attrs = {
        "script": attr.label(allow_single_file = True, mandatory = True),
        "template": attr.label(allow_single_file = True, mandatory = True),
        "copyright": attr.label(allow_single_file = True),
        "arguments": attr.string_list(mandatory = True),
        "kind": attr.string(values = ["high_level", "manual"], mandatory = True),
        "output": attr.output(mandatory = True),
        "shell": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "sed": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "mv": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "rm": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "cat": attr.label(allow_single_file = True, executable = True, cfg = "exec"),
        "execution_runtime": attr.label_list(allow_files = True, cfg = "exec"),
    },
)

def _library(ctx):
    toolchain = find_cc_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = toolchain,
        requested_features = ctx.features, unsupported_features = ctx.disabled_features)
    if not cc_common.is_enabled(feature_configuration = features, feature_name = "supports_pic"):
        fail("libmd requires a toolchain with PIC support")
    # Both maintained archive variants are outputs even in fastbuild/dbg or
    # --force_pic configurations. rules_cc's library linking helper intentionally
    # omits the regular archive in those modes, so archive the explicit object
    # sets below and construct the public CcInfo ourselves.
    contexts = []
    regular_objects = []
    pic_objects = []
    for source in ctx.files.srcs:
        flags = ctx.attr.copts + ctx.attr.per_file_flags.get(source.basename, [])
        if source.extension == "S":
            flags += ctx.attr.assembly_flags
        for pic in [False, True]:
            context, compiled = cc_common.compile(
                actions = ctx.actions, feature_configuration = features,
                cc_toolchain = toolchain, srcs = [source], public_hdrs = ctx.files.hdrs,
                includes = ctx.attr.includes, user_compile_flags = flags,
                disallow_pic_outputs = not pic, disallow_nopic_outputs = pic,
                name = ctx.label.name + ("_pic_" if pic else "_regular_") + source.basename.replace(".", "_"),
            )
            contexts.append(context)
            if pic:
                pic_objects.extend(compiled.pic_objects)
            else:
                regular_objects.extend(compiled.objects)
    if not regular_objects or not pic_objects:
        fail("libmd requires both regular and PIC compilation outputs")
    archives = []
    for suffix, objects in [(".a", regular_objects), (".pic.a", pic_objects)]:
        archive = ctx.actions.declare_file("lib" + ctx.label.name + suffix)
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
            mnemonic = "BSDLibmdArchive", env = environment,
            use_default_shell_env = False,
        )
        archives.append(archive)
    library = cc_common.create_library_to_link(actions = ctx.actions,
        feature_configuration = features, cc_toolchain = toolchain,
        static_library = archives[0], pic_static_library = archives[1])
    linking = cc_common.create_linking_context(linker_inputs = depset([
        cc_common.create_linker_input(owner = ctx.label, libraries = depset([library])),
    ]))
    info = cc_common.merge_cc_infos(cc_infos = [CcInfo(compilation_context = c) for c in contexts])
    return [DefaultInfo(files = depset([archives[0]])),
            CcInfo(compilation_context = info.compilation_context, linking_context = linking),
            OutputGroupInfo(pic_archive = depset([archives[1]]))]

libmd_library = rule(
    implementation = _library,
    attrs = {
        "srcs": attr.label_list(allow_files = [".c", ".S"], mandatory = True),
        "hdrs": attr.label_list(allow_files = [".h", ".inc", ".def"]),
        "arflags": attr.string_list(mandatory = True),
        "archive_inputs": attr.label(allow_files = True, cfg = "exec", mandatory = True),
        "copts": attr.string_list(),
        "assembly_flags": attr.string_list(),
        "per_file_flags": attr.string_list_dict(),
        "includes": attr.string_list(),
    },
    fragments = ["cpp"],
    toolchains = use_cc_toolchain(),
)

def _shared_alias(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.symlink(output = output, target_file = ctx.file.library)
    return [DefaultInfo(files = depset([output]), runfiles = ctx.runfiles(files = [output, ctx.file.library]))]

libmd_shared_alias = rule(
    implementation = _shared_alias,
    attrs = {
        "library": attr.label(allow_single_file = True, mandatory = True),
        "output": attr.string(mandatory = True),
    },
)

def _test_body(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.run(
        executable = ctx.executable.redirect,
        arguments = [output.path, ctx.executable.shell.path, ctx.file.generator.path] + ctx.attr.arguments,
        inputs = [ctx.file.generator],
        tools = [ctx.executable.shell] + ctx.files.shell_runtime,
        outputs = [output], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDLibmdTestBody",
    )
    return [DefaultInfo(files = depset([output]))]

libmd_test_body = rule(
    implementation = _test_body,
    attrs = {
        "generator": attr.label(allow_single_file = True, mandatory = True),
        "arguments": attr.string_list(mandatory = True),
        "output": attr.string(mandatory = True),
        "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "shell_runtime": attr.label_list(cfg = "exec", allow_files = True),
        "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    },
)
