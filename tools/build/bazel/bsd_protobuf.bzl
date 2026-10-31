# SPDX-License-Identifier: BSD-2-Clause
"""Native protobuf binding generation (lib/protobuf/protoc-gen.mk).

One protoc action writes a whole binding set, as protoc-gen.mk's stamp rule
does: the upb language writes NAME.upb.h, NAME.upb_minitable.{c,h} with the
protoc-gen-upb and protoc-gen-upb_minitable plugins; upbdefs adds
NAME.upbdefs.{c,h} (protoc-gen-upbdefs); cpp writes NAME.pb.{cc,h}.  The
tools are execution-platform targets built without DTrace instrumentation
(their ":bootstrap" variants), the native equivalent of buildworld's
bootstrap protoc and plugins.  The well-known types (contrib/protobuf/src)
are always importable.  Outputs live under <package>/<name>/, whose path is
the generated include root (protoc-gen.mk's PROTOGEN.NAME).
"""

_SUFFIXES = {
    "upb": [".upb.h", ".upb_minitable.h", ".upb_minitable.c"],
    "upbdefs": [".upb.h", ".upb_minitable.h", ".upb_minitable.c", ".upbdefs.h", ".upbdefs.c"],
    "cpp": [".pb.h", ".pb.cc"],
}

def _relative(file, root):
    if not file.short_path.startswith(root + "/"):
        fail("proto file outside proto_root " + root + ": " + file.short_path)
    return file.short_path[len(root) + 1:]

def _impl(ctx):
    root = ctx.attr.proto_root
    if root.startswith("/") or root.endswith("/") or ".." in root.split("/"):
        fail("proto_root must be a workspace-relative directory")
    stems = []
    for proto in ctx.files.srcs:
        stem = _relative(proto, root)
        if not stem.endswith(".proto"):
            fail("not a .proto file: " + proto.short_path)
        stems.append(stem[:-len(".proto")])
    # Suffix-major, as protoc-gen.mk lists PROTOGEN_SRCS: every file's
    # mini-table source, then every definition source.
    outputs = []
    sources = []
    headers = []
    for suffix in _SUFFIXES[ctx.attr.language]:
        for stem in stems:
            out = ctx.actions.declare_file(ctx.label.name + "/" + stem + suffix)
            outputs.append(out)
            (sources if suffix.endswith(".c") or suffix.endswith(".cc") else headers).append(out)
    out_dir = ctx.bin_dir.path + "/" + ctx.label.package + "/" + ctx.label.name
    arguments = ctx.actions.args()
    tools = [ctx.attr.protoc[DefaultInfo].files_to_run]
    if ctx.attr.language == "cpp":
        arguments.add("--cpp_out=" + out_dir)
    else:
        plugins = {"upb": ctx.attr.upb_plugin, "upb_minitable": ctx.attr.upb_minitable_plugin}
        if ctx.attr.language == "upbdefs":
            plugins["upbdefs"] = ctx.attr.upbdefs_plugin
        for name, plugin in plugins.items():
            if plugin == None:
                fail("language " + ctx.attr.language + " requires the protoc-gen-" + name + " plugin")
            arguments.add("--plugin=protoc-gen-" + name + "=" + plugin[DefaultInfo].files_to_run.executable.path)
            tools.append(plugin[DefaultInfo].files_to_run)
        for name in plugins:
            arguments.add("--" + name + "_out=" + out_dir)
    arguments.add("-I" + (ctx.label.workspace_root + "/" if ctx.label.workspace_root else "") + root)
    for path in ctx.attr.import_paths:
        arguments.add("-I" + path)
    arguments.add("-I" + ctx.attr.well_known_root)
    arguments.add_all(ctx.files.srcs)
    ctx.actions.run(
        executable = ctx.attr.protoc[DefaultInfo].files_to_run,
        arguments = [arguments],
        inputs = depset(ctx.files.srcs + ctx.files.imports + ctx.files.well_known),
        tools = tools,
        outputs = outputs,
        mnemonic = "ProtocGenerate",
        progress_message = "Generating %s bindings %%{label}" % ctx.attr.language,
        env = {"LC_ALL": "C"},
    )
    return [
        DefaultInfo(files = depset(outputs)),
        OutputGroupInfo(sources = depset(sources), headers = depset(headers)),
    ]

bsd_protoc_generate = rule(
    implementation = _impl,
    doc = "Generate one protobuf binding set (protoc-gen.mk PROTO_SETS entry).",
    attrs = {
        "srcs": attr.label_list(allow_files = [".proto"], mandatory = True, doc = "PROTO_FILES, in Make order"),
        "proto_root": attr.string(mandatory = True, doc = "PROTO_ROOT, workspace-relative"),
        "imports": attr.label_list(allow_files = [".proto"], doc = "further .proto files reachable from PROTO_PATHS"),
        "import_paths": attr.string_list(doc = "PROTO_PATHS, workspace-relative"),
        "language": attr.string(default = "upb", values = ["upb", "upbdefs", "cpp"]),
        "well_known": attr.label(default = "//contrib/protobuf:well_known_protos", allow_files = True),
        "well_known_root": attr.string(default = "contrib/protobuf/src"),
        "protoc": attr.label(default = "//usr.bin/protoc:bootstrap", executable = True, cfg = "exec"),
        "upb_plugin": attr.label(default = "//libexec/protoc-gen-upb:bootstrap", executable = True, cfg = "exec"),
        "upb_minitable_plugin": attr.label(default = "//libexec/protoc-gen-upb_minitable:bootstrap", executable = True, cfg = "exec"),
        "upbdefs_plugin": attr.label(default = "//libexec/protoc-gen-upbdefs:bootstrap", executable = True, cfg = "exec"),
    },
)
