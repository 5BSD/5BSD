# SPDX-License-Identifier: BSD-2-Clause
"""Declared DTrace generation; mutating tools receive fresh object copies."""

load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")


def _runtime_object(ctx):
    # drti is linked into the consumer, so resolve its C/C++ target toolchain.
    # cfg=exec consumers must use the host SDK; cross consumers use their target.
    toolchain = find_cc_toolchain(ctx)
    objects = [f for f in toolchain.all_files.to_list()
               if f.path.endswith("/sysroot/usr/lib/dtrace/drti.o")]
    if len(objects) != 1:
        fail("selected C/C++ toolchain must declare exactly one DTrace runtime object")
    return [DefaultInfo(files = depset(objects))]

bsd_dtrace_runtime = rule(
    implementation = _runtime_object,
    fragments = ["cpp"],
    toolchains = use_cc_toolchain(),
)

BSDDTraceInfo = provider(doc = "Declared provider header and object generation inputs.", fields = [
    "header", "source", "drti", "headers", "options", "tools", "dtrace", "static_anchor", "objcopy", "object_path_mode", "environment", "linker",
])

def _info(ctx, header = None):
    return BSDDTraceInfo(environment = _environment(ctx), header = header, source = ctx.file.source,
        drti = ctx.file.drti, headers = ctx.files.headers, options = _options(ctx),
        tools = _tools(ctx), dtrace = ctx.attr.dtrace[DefaultInfo].files_to_run,
        static_anchor = ctx.attr.static_anchor, object_path_mode = ctx.attr.object_path_mode,
        objcopy = ctx.attr.objcopy[DefaultInfo].files_to_run,
        linker = ctx.attr.linker[DefaultInfo].files_to_run)

def _environment(ctx):
    env = {"LC_ALL": "C"}
    if ctx.files.runtime_libraries:
        env["LD_LIBRARY_PATH"] = ":".join(depset([f.dirname for f in ctx.files.runtime_libraries]).to_list())
    return env

def _options(ctx):
    return ctx.attr.flags + [
        "-x", "cpppath=" + ctx.executable.cpp.path,
        "-x", "ldpath=" + ctx.executable.linker.path,
        "-x", "objcopypath=" + ctx.executable.objcopy.path,
        "-x", "syslibdir=" + ctx.file.drti.dirname,
    ]

def _tools(ctx):
    # Keep executable targets' runfiles, including tools invoked by DTrace.
    return [getattr(ctx.attr, name)[DefaultInfo].files_to_run
            for name in ["dtrace", "cpp", "linker", "objcopy"]] + ctx.files.tool_inputs + ctx.files.runtime_libraries

def _header(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.run(
        executable = ctx.attr.dtrace[DefaultInfo].files_to_run,
        arguments = _options(ctx) + ["-h", "-o", output.path, "-s", ctx.file.source.path],
        inputs = [ctx.file.source, ctx.file.drti] + ctx.files.headers,
        tools = _tools(ctx), outputs = [output],
        env = _environment(ctx), use_default_shell_env = False,
        mnemonic = "BSDDTraceHeader",
    )
    return [DefaultInfo(files = depset([output])), _info(ctx, output)]

def dtrace_rewrite(actions, spec, objects, runner, directory, provider_name, nopic_names = False):
    """Register a copy/rewrite action; return rewritten inputs and provider ELF."""
    if not objects:
        fail("DTrace requires declared object inputs")
    output = actions.declare_file(directory + "/" + provider_name)
    rewritten = []
    args = []
    names = [provider_name]
    for source in objects:
        if source.basename in names:
            fail("duplicate DTrace object basename: " + source.basename)
        names.append(source.basename)
        basename = source.basename[:-2] + ".nopic.o" if nopic_names else source.basename
        target = actions.declare_file(directory + "/" + basename)
        rewritten.append(target)
        args += ["--copy", source.path, target.path]
    args += ["--", spec.dtrace.executable.path] + spec.options
    if spec.object_path_mode == "relative":
        args += ["-x", "linkpath=relative"]
    args += ["-G", "-o", output.path, "-s", spec.source.path]
    args += [f.path for f in rewritten]
    actions.run(
        executable = runner,
        arguments = args,
        inputs = [spec.source, spec.drti] + objects + spec.headers,
        tools = spec.tools, outputs = rewritten + [output],
        env = spec.environment, use_default_shell_env = False,
        mnemonic = "BSDDTraceObjects",
    )
    if spec.static_anchor:
        anchored = actions.declare_file(directory + "/anchored/" + provider_name)
        symbol = "__bsd_dof_anchor_" + spec.source.basename[:-2]
        actions.run(
            executable = spec.objcopy,
            arguments = ["--add-symbol", symbol + "=.SUNW_dof:0,global,hidden",
                         output.path, anchored.path],
            inputs = [output], tools = spec.tools, outputs = [anchored],
            env = {"LC_ALL": "C"}, use_default_shell_env = False,
            mnemonic = "BSDDTraceAnchor",
        )
        output = anchored
    return rewritten, output

def _objects(ctx):
    rewritten, output = dtrace_rewrite(ctx.actions, _info(ctx), ctx.files.objects,
        ctx.attr.copy_runner[DefaultInfo].files_to_run, ctx.label.name, ctx.attr.output)
    return [DefaultInfo(files = depset(rewritten + [output])),
            OutputGroupInfo(rewritten_objects = depset(rewritten), provider_object = depset([output]))]

def _attrs():
    result = {
        "source": attr.label(allow_single_file = [".d"], mandatory = True),
        "output": attr.string(mandatory = True),
        "flags": attr.string_list(),
        "static_anchor": attr.bool(default = False),
        "object_path_mode": attr.string(default = "absolute", values = ["absolute", "relative"]),
        "headers": attr.label_list(allow_files = True),
        "drti": attr.label(allow_single_file = True, mandatory = True),
        "tool_inputs": attr.label_list(allow_files = True, cfg = "exec"),
        "runtime_libraries": attr.label_list(allow_files = True, cfg = "exec"),
    }
    for name in ["dtrace", "cpp", "linker", "objcopy"]:
        result[name] = attr.label(allow_single_file = True, executable = True, cfg = "exec", mandatory = True)
    return result

_header_attrs = _attrs()
bsd_dtrace_header = rule(implementation = _header, attrs = _header_attrs)
_object_attrs = _attrs()
_object_attrs["objects"] = attr.label_list(allow_files = True, mandatory = True)
_object_attrs["copy_runner"] = attr.label(executable = True, cfg = "exec", mandatory = True)
bsd_dtrace_objects = rule(implementation = _objects, attrs = _object_attrs)


def _spec(ctx):
    return [DefaultInfo(files = depset()), _info(ctx)]

# For providers whose consumers already have maintained probe macros.
bsd_dtrace_spec = rule(implementation = _spec, attrs = _attrs())

def _cc_objects(ctx):
    if ctx.attr.archive_members and not ctx.attr.archive_runner:
        fail("archive member composition requires a declared archive_runner")
    if ctx.attr.library and ctx.attr.libraries:
        fail("choose library or libraries, not both")
    sources = [ctx.attr.library] if ctx.attr.library else ctx.attr.libraries
    if not sources:
        fail("DTrace requires explicit component compilation groups")
    regular = []
    pic = []
    # Only each group's own objects; external dependencies must not be rewritten.
    # The consuming cc_import retains its normal link dependencies.
    for source in sources:
        own_regular = []
        own_pic = []
        for linker_input in source[CcInfo].linking_context.linker_inputs.to_list():
            if linker_input.owner == source.label:
                for library in linker_input.libraries:
                    own_regular += library.objects
                    own_pic += library.pic_objects
        if not own_regular and not own_pic:
            fail("DTrace input must expose its own compiled C/C++ objects: " + str(source.label))
        regular += own_regular
        pic += own_pic
    for objects in [regular, pic]:
        if len(depset(objects).to_list()) != len(objects):
            fail("DTrace component groups contain duplicate object inputs")
    outputs = []
    groups = {}
    for variant, objects, suffix in [("regular", regular, ".nopic.o"), ("pic", pic, ".pic.o")]:
        if objects:
            rewritten, provider = dtrace_rewrite(
                ctx.actions, ctx.attr.provider[BSDDTraceInfo], objects,
                ctx.attr.copy_runner[DefaultInfo].files_to_run,
                ctx.label.name + "/" + variant, ctx.attr.provider_object + suffix,
                nopic_names = variant == "regular",
            )
            outputs += rewritten + [provider]
            groups[variant] = depset(rewritten + [provider])
            groups[variant + "_objects"] = depset(rewritten)
            groups[variant + "_provider"] = depset([provider])
            if ctx.attr.archive_members:
                # Prototype: a relocatable member owns its code and DOF together.
                # This output is opt-in; existing shared/program composition is
                # unchanged. A final archive selects members by normal symbols.
                members = []
                spec = ctx.attr.provider[BSDDTraceInfo]
                for index, original in enumerate(objects):
                    directory = ctx.label.name + "/archive_" + variant + "/" + str(index)
                    member = ctx.actions.declare_file(directory + "/" + original.basename)
                    options = spec.options + (["-x", "linkpath=relative"] if spec.object_path_mode == "relative" else [])
                    ctx.actions.run(
                        executable = ctx.attr.archive_runner[DefaultInfo].files_to_run,
                        arguments = [original.path, member.path, spec.linker.executable.path, "--", spec.dtrace.executable.path] + options +
                            ["-G", "-o", member.path + ".dof.o", "-s", spec.source.path, member.path + ".rewrite.o"],
                        inputs = [original, spec.source, spec.drti] + spec.headers,
                        tools = spec.tools, outputs = [member], env = spec.environment, use_default_shell_env = False,
                        mnemonic = "BSDDTraceArchiveMember",
                    )
                    members.append(member)
                groups[variant + "_archive_objects"] = depset(members)
    return [DefaultInfo(files = depset(outputs)), OutputGroupInfo(**groups)]

bsd_dtrace_cc_objects = rule(
    implementation = _cc_objects,
    attrs = {
        "library": attr.label(providers = [CcInfo]),
        "libraries": attr.label_list(providers = [CcInfo]),
        "provider": attr.label(providers = [BSDDTraceInfo], mandatory = True),
        "provider_object": attr.string(mandatory = True),
        "archive_runner": attr.label(executable = True, cfg = "exec"),
        "archive_members": attr.bool(default = False, doc = "Experimental section-associated static archive composition; not production-qualified."),
        "copy_runner": attr.label(executable = True, cfg = "exec", mandatory = True),
    },
)
