# SPDX-License-Identifier: BSD-2-Clause
"""Declared generator actions and a mixed C/C++ shared library rule.

These rules reproduce the generation steps maintained Make runs for
cddl/lib/libdtrace (yacc, lex and the shell generators) and its link, as
separate declared actions.  No Make subprocess and no shell pipeline is
involved: tools are explicit executables staged from the SDK's bootstrap
directory, redirections go through the stdout_redirect helper, and the
generated files are compared with Make's object directory by the probe.
"""

load(":cc_compat.bzl", "BSD_CC_TOOLCHAINS", "BSD_CC_TOOLCHAIN_ATTRS", CcInfo = "bsd_CcInfo", cc_common = "bsd_cc_common", find_cpp_toolchain = "bsd_find_cc_toolchain")

def _tool_path_env(ctx):
    # Generator scripts call sed/nawk/awk/cat through PATH; only the staged
    # tool directory is searched.
    return {"PATH": ctx.attr.tool_dir, "LC_ALL": "C"}

def _yacc_impl(ctx):
    out_c = ctx.actions.declare_file(ctx.attr.out)
    out_h = ctx.actions.declare_file(ctx.attr.out[:-2] + ".h")
    ctx.actions.run(
        executable = ctx.executable.yacc,
        arguments = ctx.attr.yflags + ["-o", out_c.path, ctx.file.src.path],
        inputs = [ctx.file.src],
        outputs = [out_c, out_h],
        env = {"LC_ALL": "C"},
        mnemonic = "BSDYacc",
    )
    return [DefaultInfo(files = depset([out_c, out_h])),
            OutputGroupInfo(source = depset([out_c]), header = depset([out_h]))]

bsd_yacc = rule(
    implementation = _yacc_impl,
    doc = "bsd.lib.mk .y rule with YFLAGS (-d): <out>.c and <out>.h.",
    attrs = {
        "src": attr.label(allow_single_file = [".y"], mandatory = True),
        "out": attr.string(mandatory = True),
        "yflags": attr.string_list(),
        "yacc": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
    },
)

def _lex_impl(ctx):
    out = ctx.actions.declare_file(ctx.attr.out)
    ctx.actions.run(
        executable = ctx.executable.lex,
        arguments = ctx.attr.lflags + ["-o" + out.path, ctx.file.src.path],
        inputs = [ctx.file.src],
        tools = ctx.files.path_tools,
        outputs = [out],
        env = _tool_path_env(ctx),
        mnemonic = "BSDLex",
    )
    return [DefaultInfo(files = depset([out]))]

bsd_lex = rule(
    implementation = _lex_impl,
    doc = "sys.mk .l.c rule; flex runs m4, found only in the staged tool directory.",
    attrs = {
        "src": attr.label(allow_single_file = [".l"], mandatory = True),
        "out": attr.string(mandatory = True),
        "lflags": attr.string_list(),
        "lex": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "path_tools": attr.label_list(allow_files = True, cfg = "exec"),
        "tool_dir": attr.string(mandatory = True),
    },
)

def _generate_impl(ctx):
    out = ctx.actions.declare_file(ctx.attr.out)
    args = [ctx.expand_location(a.replace("$(OUT)", out.path), ctx.attr.data)
            for a in ctx.attr.arguments]
    inputs = ctx.files.data + ([ctx.file.stdin] if ctx.file.stdin else [])
    if ctx.attr.redirect_stdout:
        argv = (["-i", ctx.file.stdin.path] if ctx.file.stdin else []) + \
               [out.path, ctx.executable.interpreter.path] + args
        ctx.actions.run(executable = ctx.executable.redirect, arguments = argv, inputs = inputs,
                        tools = [ctx.executable.interpreter] + ctx.files.path_tools,
                        outputs = [out], env = _tool_path_env(ctx), mnemonic = "BSDGenerate")
    else:
        if ctx.file.stdin:
            fail("stdin needs redirect_stdout")
        ctx.actions.run(executable = ctx.executable.interpreter, arguments = args, inputs = inputs,
                        tools = ctx.files.path_tools, outputs = [out],
                        env = _tool_path_env(ctx), mnemonic = "BSDGenerate")
    return [DefaultInfo(files = depset([out]))]

bsd_generate = rule(
    implementation = _generate_impl,
    doc = """Run `interpreter arguments` with optional stdin/stdout redirection.

    $(OUT) is the declared output; $(location <label>) names a data file.
    """,
    attrs = {
        "out": attr.string(mandatory = True),
        "interpreter": attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True),
        "arguments": attr.string_list(),
        "data": attr.label_list(allow_files = True),
        "stdin": attr.label(allow_single_file = True),
        "redirect_stdout": attr.bool(default = False),
        "redirect": attr.label(executable = True, cfg = "exec"),
        "path_tools": attr.label_list(allow_files = True, cfg = "exec"),
        "tool_dir": attr.string(mandatory = True),
    },
)

def _stem(f):
    return f.basename[:f.basename.rfind(".")]

def _mixed_shared_impl(ctx):
    cc_toolchain = find_cpp_toolchain(ctx)
    features = cc_common.configure_features(ctx = ctx, cc_toolchain = cc_toolchain,
                                            requested_features = ctx.features,
                                            unsupported_features = ctx.disabled_features)
    deps = [d[CcInfo] for d in ctx.attr.deps]
    contexts = [d.compilation_context for d in deps]
    c_srcs = [f for f in ctx.files.srcs if f.extension == "c"]
    cxx_srcs = [f for f in ctx.files.srcs if f.extension == "cc"]
    hdrs = [f for f in ctx.files.srcs if f.extension in ("h", "hh")] + ctx.files.private_hdrs

    # Make compiles .pico objects with its own PICFLAG (-fpic -DPIC) in front of
    # CFLAGS/CXXFLAGS; the toolchain's -fPIC feature is not used.
    objects = {}
    for name, srcs, flags in (("c", c_srcs, ctx.attr.copts), ("cxx", cxx_srcs, ctx.attr.cxxopts)):
        _, out = cc_common.compile(
            name = ctx.label.name + "_" + name,
            actions = ctx.actions,
            feature_configuration = features,
            cc_toolchain = cc_toolchain,
            srcs = srcs,
            private_hdrs = hdrs,
            compilation_contexts = contexts,
            user_compile_flags = flags,
            disallow_pic_outputs = True,
        )
        for obj in out.objects:
            objects[_stem(obj)] = obj

    # Link objects in Make SRCS order.
    ordered = []
    for f in ctx.attr.order:
        stem = f[:f.rfind(".")]
        if stem not in objects:
            fail("no object for " + f)
        ordered.append(objects.pop(stem))
    if objects:
        fail("objects missing from order: " + str(objects.keys()))
    outputs = cc_common.create_compilation_outputs(objects = depset(ordered),
                                                   pic_objects = depset(ordered))
    linking = cc_common.link(
        name = ctx.label.name,
        actions = ctx.actions,
        feature_configuration = features,
        cc_toolchain = cc_toolchain,
        compilation_outputs = outputs,
        linking_contexts = [d.linking_context for d in deps],
        user_link_flags = ctx.attr.linkopts,
        output_type = "dynamic_library",
        link_deps_statically = True,
    )
    library = linking.library_to_link.resolved_symlink_dynamic_library or \
              linking.library_to_link.dynamic_library
    named = ctx.actions.declare_file(ctx.attr.soname)
    ctx.actions.symlink(output = named, target_file = library)
    to_link = cc_common.create_library_to_link(actions = ctx.actions,
                                               feature_configuration = features,
                                               cc_toolchain = cc_toolchain,
                                               dynamic_library = named)
    linker_input = cc_common.create_linker_input(owner = ctx.label,
                                                 libraries = depset([to_link]))
    return [
        DefaultInfo(files = depset([named, library])),
        CcInfo(linking_context = cc_common.create_linking_context(
            linker_inputs = depset([linker_input]))),
        OutputGroupInfo(objects = depset(ordered)),
    ]

bsd_mixed_shared_library = rule(
    implementation = _mixed_shared_impl,
    doc = """LIB_CXX shared library: C and C++ objects with separate flag lists.

    rules_cc rules apply target-wide flags to every source; Make compiles .c
    with CFLAGS and .cc with CXXFLAGS (and per-file flags), so this rule compiles them in two groups
    and links the .pico-equivalent objects in Make's SRCS order (`order`).
    """,
    attrs = dict({
        "srcs": attr.label_list(allow_files = [".c", ".cc", ".h", ".hh"]),
        "private_hdrs": attr.label_list(allow_files = True),
        "order": attr.string_list(mandatory = True),
        "deps": attr.label_list(providers = [CcInfo]),
        "copts": attr.string_list(),
        "cxxopts": attr.string_list(),
        "linkopts": attr.string_list(),
        "soname": attr.string(mandatory = True),
    }, **BSD_CC_TOOLCHAIN_ATTRS),
    fragments = ["cpp"],
    toolchains = BSD_CC_TOOLCHAINS,
)
