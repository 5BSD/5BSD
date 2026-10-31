# SPDX-License-Identifier: BSD-2-Clause
"""Per-source compile groups, archives, shared objects, programs and protoc.

rules_cc cc_library/cc_binary apply target-wide compile options to every
source of the target and name objects after the source basename, while
bsd.lib.mk/bsd.prog.mk compile .c with CFLAGS and .cc with CXXFLAGS, add
per-file flags (CFLAGS.<file>, CXXFLAGS.<file>, CWARNFLAGS.<file>), keep
objects in subdirectories when SRCS name them (bsd.obj.mk) and build several object kinds from one SRCS list (.o for
lib<name>.a, .pico for the shared object, .pieo for an INTERNALLIB _pie.a or
a PIE program).  These rules compile every source in its own declared
action with an explicit, Make-ordered flag list, keep Make's SRCS order for
archive members and link inputs, and write a manifest that maps each Make
object path (as `make -n` prints it) to the Bazel object, which the probe
uses for the per-object comparison.  No Make subprocess is involved.

The flag builders mirror share/mk/bsd.sys.mk for WARNS 1, 3 and 6 as the
contrib Makefiles that use these rules print them (checked by the probes;
an unexplained difference fails them).
"""

load(":cc_compat.bzl", "BSD_CC_TOOLCHAINS", "BSD_CC_TOOLCHAIN_ATTRS", CcInfo = "bsd_CcInfo", cc_common = "bsd_cc_common", find_cpp_toolchain = "bsd_find_cc_toolchain")

_BASE = ["-O2", "-pipe", "-fno-common"]
_DEBUG = ["-g", "-gz=zlib"]
_SSP = ["-fstack-protector-strong"]
_TAIL = ["-Qunused-arguments"]
_CLANG_TAIL = ["-Wno-empty-body", "-Wno-string-plus-int", "-Wno-unused-const-variable",
               "-Wno-error=unused-but-set-parameter", "-Wno-error=cast-function-type-mismatch"]
_W_LOW_TAIL = ["-Wno-tautological-compare", "-Wno-unused-value", "-Wno-parentheses-equality",
               "-Wno-unused-function", "-Wno-enum-conversion", "-Wno-unused-local-typedef",
               "-Wno-address-of-packed-member"]
_W1_TAIL = _W_LOW_TAIL + ["-Wno-switch", "-Wno-switch-enum", "-Wno-knr-promoted-parameter",
                          "-Wno-parentheses"]
_W_COMMON = ["-Wsystem-headers", "-Werror", "-Wall", "-Wno-format-y2k", "-W",
             "-Wno-unused-parameter", "-Wstrict-prototypes", "-Wmissing-prototypes",
             "-Wpointer-arith"]

# WFORMAT for programs under libexec (bsd.sys.mk -Wformat=2 with -Werror and
# the clang -Wno-format-nonliteral at the end of the warning list).
_WFORMAT = ["-Wformat=2", "-Wno-format-extra-args", "-Werror"]
_WFORMAT_END = ["-Wno-format-nonliteral"]

def _c_warns(warns, wformat):
    fmt = _WFORMAT if wformat else []
    end = _WFORMAT_END if wformat else []
    if warns == 1:
        return (["-Wsystem-headers", "-Werror", "-Wno-pointer-sign", "-Wdate-time"] + fmt +
                _CLANG_TAIL + _W1_TAIL + end)
    if warns == 3:
        return (_W_COMMON + ["-Wno-uninitialized", "-Wno-pointer-sign", "-Wdate-time"] + fmt +
                _CLANG_TAIL + _W_LOW_TAIL + end)
    if warns == 6:
        return (_W_COMMON + ["-Wreturn-type", "-Wcast-qual", "-Wwrite-strings", "-Wswitch",
                             "-Wshadow", "-Wunused-parameter", "-Wcast-align",
                             "-Wchar-subscripts", "-Wnested-externs", "-Wold-style-definition",
                             "-Wno-pointer-sign", "-Wdate-time",
                             "-Wmissing-variable-declarations", "-Wthread-safety"] + fmt +
                _CLANG_TAIL + end)
    fail("unsupported WARNS level %d" % warns)

def _cxx_warns(warns, wformat):
    if warns != 1:
        fail("unsupported C++ WARNS level %d" % warns)
    fmt = _WFORMAT if wformat else []
    end = _WFORMAT_END if wformat else []
    return ["-Wsystem-headers", "-Werror", "-Wdate-time"] + fmt + _CLANG_TAIL + _W1_TAIL + end

# Object kinds: Make's PICFLAG/PIEFLAG prefixes (C++ PIEFLAG has no -DPIC).
_C_PREFIX = {"o": [], "pico": ["-fpic", "-DPIC"], "pieo": ["-fpie", "-DPIC"]}
_CXX_PREFIX = {"o": [], "pico": ["-fpic", "-DPIC"], "pieo": ["-fpie"]}

def bsd_c_flags(kind, warns, local = [], prog = False, wformat = False, cwarn = []):
    """CFLAGS of a .c object: PIC/PIE prefix, base, component CFLAGS, PIE,
    debug, -std, SSP, WARNS (+ CWARNFLAGS of the file), tail."""
    return (_C_PREFIX[kind] + _BASE + local + (["-fPIE"] if prog else []) + _DEBUG +
            ["-std=gnu17", "-Wno-format-zero-length"] + _SSP + _c_warns(warns, wformat) + cwarn +
            _TAIL)

def bsd_cxx_flags(kind, warns, cxxstd, local = [], cxx_local = [], prog = False,
                  wformat = False, cxxwarn = []):
    """CXXFLAGS of a .cc object: the C flags without the C-only ones, then the
    component CXXFLAGS, PIE, debug flags again, -std, CXXWARNFLAGS and the
    clang C++ warning tail.  Per-file CXXFLAGS.<file> follow (per_file)."""
    pie = ["-fPIE"] if prog else []
    return (_CXX_PREFIX[kind] + _BASE + local + pie + _DEBUG + ["-Wno-format-zero-length"] +
            _SSP + _cxx_warns(warns, wformat) + _TAIL + cxx_local + pie + _DEBUG +
            ["-std=" + cxxstd] + cxxwarn +
            ["-Wno-c++20-extensions", "-Wno-c++23-lambda-attributes",
             "-Wno-nullability-completeness"])

BsdObjectsInfo = provider(fields = ["objects", "make_paths", "kind"])

def _stem(path):
    return path[:path.rfind(".")]

def _features(ctx, cc_toolchain):
    return cc_common.configure_features(ctx = ctx, cc_toolchain = cc_toolchain,
                                        requested_features = ctx.features,
                                        unsupported_features = ctx.disabled_features + ["pic"])

def _compile_all(ctx, cc_toolchain, features, kind, suffix):
    contexts = [d[CcInfo].compilation_context for d in ctx.attr.deps if CcInfo in d]
    # Pair every Make SRCS name with the one input file whose path ends in
    # it; the compile and member order is the Make order.
    files = ctx.files.srcs
    if len(files) != len(ctx.attr.src_paths):
        fail("srcs and src_paths differ in length")
    srcs = []
    for path in ctx.attr.src_paths:
        found = [f for f in files if f.short_path == path or f.short_path.endswith("/" + path)]
        if len(found) != 1:
            fail("no single source file for " + path)
        srcs.append(found[0])
    hdrs = ctx.files.hdrs
    objects, make_paths = [], []
    for i, (src, path) in enumerate(zip(srcs, ctx.attr.src_paths)):
        if path.endswith(".c"):
            flags = ctx.attr.copts
        elif path.endswith(".cc"):
            flags = ctx.attr.cxxopts
        else:
            fail("unsupported source " + path)
        # CWARNFLAGS.<file> sit in the warning list, before the final
        # -Qunused-arguments; CFLAGS/CXXFLAGS.<file> come last.
        cwarn = ctx.attr.per_file_cwarn.get(path, [])
        if cwarn:
            if flags[-1] != "-Qunused-arguments":
                fail("per_file_cwarn needs a bsd_c_flags list for " + path)
            flags = flags[:-1] + cwarn + flags[-1:]
        flags = flags + ctx.attr.per_file.get(path, [])
        _, out = cc_common.compile(
            name = "%s_%d" % (ctx.label.name, i),
            actions = ctx.actions,
            feature_configuration = features,
            cc_toolchain = cc_toolchain,
            srcs = [src],
            private_hdrs = hdrs,
            system_includes = [ctx.bin_dir.path + "/" + x for x in ctx.attr.generated_includes],
            compilation_contexts = contexts,
            user_compile_flags = flags,
            disallow_pic_outputs = True,
        )
        if len(out.objects) != 1:
            fail("expected one object for " + path)
        objects.append(out.objects[0])
        make_paths.append(_stem(path) + suffix)
    return objects, make_paths

def _manifest(ctx, objects, make_paths):
    out = ctx.actions.declare_file(ctx.label.name + ".objects.json")
    ctx.actions.write(out, json.encode({"srcs": ctx.attr.src_paths,
                                        "objects": {m: o.path for m, o in zip(make_paths, objects)}}))
    return out

def _archive_impl(ctx):
    cc_toolchain = find_cpp_toolchain(ctx)
    features = _features(ctx, cc_toolchain)
    kind = ctx.attr.kind
    objects, make_paths = _compile_all(ctx, cc_toolchain, features, kind, "." + kind)
    outputs = cc_common.create_compilation_outputs(objects = depset(objects))
    linking, linking_out = cc_common.create_linking_context_from_compilation_outputs(
        actions = ctx.actions,
        feature_configuration = features,
        cc_toolchain = cc_toolchain,
        compilation_outputs = outputs,
        user_link_flags = ctx.attr.linkopts,
        linking_contexts = [d[CcInfo].linking_context for d in ctx.attr.deps if CcInfo in d],
        name = ctx.attr.archive,
        disallow_dynamic_library = True,
    )
    archive = linking_out.library_to_link.static_library
    manifest = _manifest(ctx, objects, make_paths)
    own = CcInfo(compilation_context = cc_common.create_compilation_context(
        headers = depset(ctx.files.public_hdrs),
        includes = depset([ctx.label.package + "/" + x if x != "." else ctx.label.package
                           for x in ctx.attr.public_includes]),
    ), linking_context = linking)
    return [
        DefaultInfo(files = depset([archive, manifest])),
        cc_common.merge_cc_infos(direct_cc_infos = [own],
                                 cc_infos = [d[CcInfo] for d in ctx.attr.deps if CcInfo in d]),
        BsdObjectsInfo(objects = objects, make_paths = make_paths, kind = kind),
        OutputGroupInfo(manifest = depset([manifest]), objects = depset(objects)),
    ]

_COMMON_ATTRS = {
    "srcs": attr.label_list(allow_files = [".c", ".cc"], mandatory = True),
    "src_paths": attr.string_list(mandatory = True),
    "hdrs": attr.label_list(allow_files = True),
    "deps": attr.label_list(),
    "copts": attr.string_list(),
    "cxxopts": attr.string_list(),
    "per_file": attr.string_list_dict(),
    "per_file_cwarn": attr.string_list_dict(),
    "generated_includes": attr.string_list(),
    "linkopts": attr.string_list(),
}
_COMMON_ATTRS.update(BSD_CC_TOOLCHAIN_ATTRS)

bsd_cc_archive = rule(
    implementation = _archive_impl,
    doc = """lib<archive>.a from per-source objects of one kind ("o", or "pieo"
    for an INTERNALLIB _pie archive), members in Make SRCS order.  `src_paths`
    are the Make SRCS names (object subdirectories follow them).  `linkopts`
    carry the library's _DP_ system libraries for consumers.""",
    attrs = dict(_COMMON_ATTRS, **{
        "kind": attr.string(values = ["o", "pieo"], default = "o"),
        "archive": attr.string(mandatory = True),
        "public_hdrs": attr.label_list(allow_files = True),
        "public_includes": attr.string_list(),
    }),
    fragments = ["cpp"],
    toolchains = BSD_CC_TOOLCHAINS,
)

def _link(ctx, cc_toolchain, features, objects, output_type, link_deps, flags, extra):
    outputs = cc_common.create_compilation_outputs(objects = depset(objects),
                                                   pic_objects = depset(objects))
    return cc_common.link(
        name = ctx.attr.output if output_type == "executable" else ctx.label.name,
        actions = ctx.actions,
        feature_configuration = features,
        cc_toolchain = cc_toolchain,
        compilation_outputs = outputs,
        linking_contexts = link_deps,
        user_link_flags = flags,
        output_type = output_type,
        link_deps_statically = True,
        additional_inputs = extra,
    )

def _shared_impl(ctx):
    cc_toolchain = find_cpp_toolchain(ctx)
    features = _features(ctx, cc_toolchain)
    objects, make_paths = _compile_all(ctx, cc_toolchain, features, "pico", ".pico")
    flags = list(ctx.attr.linkopts)
    extra = []
    if ctx.file.version_script:
        flags = ["-Wl,--version-script=" + ctx.file.version_script.path] + flags
        extra = [ctx.file.version_script]
    linking = _link(ctx, cc_toolchain, features, objects, "dynamic_library",
                    [d[CcInfo].linking_context for d in ctx.attr.deps if CcInfo in d], flags, extra)
    library = linking.library_to_link.resolved_symlink_dynamic_library or \
              linking.library_to_link.dynamic_library
    named = ctx.actions.declare_file(ctx.attr.soname)
    ctx.actions.symlink(output = named, target_file = library)
    manifest = _manifest(ctx, objects, make_paths)
    return [
        DefaultInfo(files = depset([named, library, manifest])),
        BsdObjectsInfo(objects = objects, make_paths = make_paths, kind = "pico"),
        OutputGroupInfo(manifest = depset([manifest]), objects = depset(objects)),
    ]

bsd_cc_shared = rule(
    implementation = _shared_impl,
    doc = """A PRIVATELIB/LIB shared object from .pico-equivalent objects, linked
    in Make SRCS order with an explicit SONAME flag list and an optional
    version script (LDFLAGS+=-Wl,--version-script=...).""",
    attrs = dict(_COMMON_ATTRS, **{
        "soname": attr.string(mandatory = True),
        "version_script": attr.label(allow_single_file = True),
    }),
    fragments = ["cpp"],
    toolchains = BSD_CC_TOOLCHAINS,
)

def _program_impl(ctx):
    cc_toolchain = find_cpp_toolchain(ctx)
    features = _features(ctx, cc_toolchain)
    kind = "o" if ctx.attr.static else "pieo"
    objects, make_paths = _compile_all(ctx, cc_toolchain, features, kind, "." + kind)
    linking = _link(ctx, cc_toolchain, features, objects, "executable",
                    [d[CcInfo].linking_context for d in ctx.attr.deps if CcInfo in d],
                    ctx.attr.linkopts, [])
    program = linking.executable
    manifest = _manifest(ctx, objects, make_paths)
    return [
        DefaultInfo(files = depset([program, manifest]), executable = program),
        BsdObjectsInfo(objects = objects, make_paths = make_paths, kind = kind),
        OutputGroupInfo(manifest = depset([manifest]), objects = depset(objects)),
    ]

bsd_cc_program = rule(
    implementation = _program_impl,
    doc = """A program from per-source objects: a dynamic PIE (.pieo objects,
    as PROG.full) or, with static = True, a static non-PIE tool for build-time
    use in the exec configuration (the equivalent of a bootstrap tool).""",
    attrs = dict(_COMMON_ATTRS, **{
        "output": attr.string(mandatory = True),
        "static": attr.bool(default = False),
    }),
    executable = True,
    fragments = ["cpp"],
    toolchains = BSD_CC_TOOLCHAINS,
)

def _protoc_impl(ctx):
    outs = []
    out_dir = ctx.bin_dir.path + "/" + ctx.label.package + "/" + ctx.attr.out_dir
    suffixes = {"upb": [".upb.h", ".upb.c", ".upb_minitable.h", ".upb_minitable.c"],
                "upbdefs": [".upb.h", ".upb.c", ".upb_minitable.h", ".upb_minitable.c",
                            ".upbdefs.h", ".upbdefs.c"]}
    if ctx.attr.lang not in suffixes:
        fail("unsupported protoc language " + ctx.attr.lang)
    for proto in ctx.attr.proto_paths:
        for s in suffixes[ctx.attr.lang]:
            outs.append(ctx.actions.declare_file(ctx.attr.out_dir + "/" + _stem(proto) + s))
    args = ["-I" + ctx.attr.proto_root, "-I" + ctx.attr.wkt_root,
            "--plugin=protoc-gen-upb=" + ctx.executable.gen_upb.path,
            "--plugin=protoc-gen-upb_minitable=" + ctx.executable.gen_upb_minitable.path,
            "--upb_out=" + out_dir, "--upb_minitable_out=" + out_dir]
    tools = [ctx.executable.gen_upb, ctx.executable.gen_upb_minitable]
    if ctx.attr.lang == "upbdefs":
        args += ["--plugin=protoc-gen-upbdefs=" + ctx.executable.gen_upbdefs.path,
                 "--upbdefs_out=" + out_dir]
        tools.append(ctx.executable.gen_upbdefs)
    args += [ctx.attr.proto_root + "/" + p for p in ctx.attr.proto_paths]
    ctx.actions.run(
        executable = ctx.executable.protoc,
        arguments = args,
        inputs = ctx.files.protos,
        tools = tools,
        outputs = outs,
        env = {"LC_ALL": "C"},
        mnemonic = "BSDProtoc",
    )
    return [DefaultInfo(files = depset(outs)),
            # protoc-gen-upb's .upb.c holds no code; protoc-gen.mk compiles
            # only the mini-tables and the definitions.
            OutputGroupInfo(sources = depset([f for f in outs if f.extension == "c" and
                                              not f.basename.endswith(".upb.c")]),
                            headers = depset([f for f in outs if f.extension == "h"]))]

bsd_protoc = rule(
    implementation = _protoc_impl,
    doc = """lib/protobuf/protoc-gen.mk: one protoc run over a PROTO_SETS set,
    with the workspace-built protoc and upb plugins (exec configuration) and
    the same -I roots, writing <out_dir>/<file>.upb*.{c,h}.  protoc-gen-upb
    also writes a .upb.c without code; it is declared and compared but, as
    in protoc-gen.mk, not compiled (output group "sources" leaves it out).""",
    attrs = {
        "protos": attr.label_list(allow_files = [".proto"], mandatory = True),
        "proto_paths": attr.string_list(mandatory = True),
        "proto_root": attr.string(mandatory = True),
        "wkt_root": attr.string(mandatory = True),
        "out_dir": attr.string(mandatory = True),
        "lang": attr.string(default = "upb"),
        "protoc": attr.label(executable = True, cfg = "exec", mandatory = True),
        "gen_upb": attr.label(executable = True, cfg = "exec", mandatory = True),
        "gen_upb_minitable": attr.label(executable = True, cfg = "exec", mandatory = True),
        "gen_upbdefs": attr.label(executable = True, cfg = "exec"),
    },
)
