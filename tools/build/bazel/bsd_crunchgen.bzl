# SPDX-License-Identifier: BSD-2-Clause
"""Run the original crunchgen dispatcher producer with explicit object metadata.

No source directories, Makefiles or discovery commands are accepted. Every
program supplies its object list, so crunchgen never enters its Make-query path.
The incidental Makefile/cache are declared outputs and are never executed.
"""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

_NAME_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
_IDENT_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"

def _token(value, chars, description):
    if not value or any([c not in chars for c in value.elems()]):
        fail("invalid " + description + ": " + value)

def crunchgen_identifier(program):
    """Match original genident: map hyphens, discard other non-identifier chars."""
    return "".join([c for c in program.replace("-", "_").elems() if c in _IDENT_CHARS])

def _impl(ctx):
    programs = ctx.attr.programs
    if not programs or len(depset(programs).to_list()) != len(programs):
        fail("crunchgen programs must be nonempty and unique")
    if sorted(ctx.attr.object_names.keys()) != sorted(programs):
        fail("crunchgen requires an explicit object list for every program")
    if any([name not in programs for name in ctx.attr.aliases.keys()]):
        fail("crunchgen aliases require a declared program")
    executable = ctx.attr.executable_name
    _token(executable, _NAME_CHARS, "crunched executable name")
    seen = {executable: True, "--list": True}
    identifiers = {}
    lines = []
    for program in programs:
        _token(program, _NAME_CHARS, "crunchgen program name")
        if program in seen:
            fail("duplicate or reserved crunchgen entry: " + program)
        seen[program] = True
        ident = crunchgen_identifier(program)
        if not ident or ident[0] in "0123456789" or ident in identifiers:
            fail("crunchgen program identifiers must be valid and unique")
        identifiers[ident] = True
        objects = ctx.attr.object_names[program]
        if not objects or len(depset(objects).to_list()) != len(objects):
            fail("crunchgen object lists must be nonempty and unique")
        for obj in objects:
            _token(obj, _NAME_CHARS + "/", "crunchgen object name")
            if not obj.endswith(".o") or any([part in ["", ".", ".."] for part in obj.split("/")]):
                fail("crunchgen object names must be canonical relative .o paths")
        lines += ["progs " + program, "special " + program + " objs " + " ".join(objects)]
        for alias in ctx.attr.aliases.get(program, []):
            _token(alias, _NAME_CHARS + "[]", "crunchgen alias")
            if alias in seen or alias in programs:
                fail("duplicate or reserved crunchgen entry: " + alias)
            seen[alias] = True
            lines.append("ln " + program + " " + alias)
    for setting, expected in ctx.attr.required_configuration.items():
        value = setting[BuildSettingInfo].value
        if expected not in ["true", "false"] or type(value) != "bool":
            fail("crunchgen configuration guards require declared boolean values")
        if value != (expected == "true"):
            fail("crunchgen catalog configuration mismatch: " + str(setting.label))
    directory = ctx.label.name + ".generated/"
    config = ctx.actions.declare_file(directory + executable + ".conf")
    main = ctx.actions.declare_file(directory + executable + ".c")
    makefile = ctx.actions.declare_file(directory + executable + ".mk")
    cache = ctx.actions.declare_file(directory + executable + ".cache")
    ctx.actions.write(config, "\n".join(lines) + "\n")
    aliases = []
    basenames = [config.basename, main.basename, makefile.basename, cache.basename]
    for library in ctx.files.libraries:
        if library.basename in basenames:
            fail("duplicate crunchgen runtime basename: " + library.basename)
        basenames.append(library.basename)
        alias = ctx.actions.declare_file(directory + library.basename)
        ctx.actions.symlink(output = alias, target_file = library)
        aliases.append(alias)
    stubs = [ctx.actions.declare_file(directory + program + "_stub.c")
             for program in programs] if ctx.attr.emit_stubs else []
    args = ctx.actions.args()
    args.add_all([main.dirname, ctx.executable.tool.path, "-f", "-q", "-e", executable,
                  "-c", main.basename, "-m", makefile.basename])
    if ctx.attr.emit_stubs:
        args.add_all(["-s", "."])
    args.add(config.basename)
    ctx.actions.run(executable = ctx.attr.runner[DefaultInfo].files_to_run,
        arguments = [args], inputs = [config] + aliases + ctx.files.libraries,
        tools = [ctx.attr.tool[DefaultInfo].files_to_run], outputs = [main, makefile, cache] + stubs,
        env = {"LC_ALL": "C", "PATH": "", "LD_LIBRARY_PATH": ".",
               "MAKE": "/__crunchgen_make_discovery_disabled__", "DTRACE_DOF_INIT_DISABLE": "1"},
        use_default_shell_env = False, mnemonic = "BSDCrunchgen")
    groups = {"metadata": depset([config, makefile, cache]), "stubs": depset(stubs)}
    for program, stub in zip(programs, stubs):
        ident = crunchgen_identifier(program)
        groups["stub_" + ident] = depset([stub])
    return [DefaultInfo(files = depset([main])), OutputGroupInfo(**groups)]

bsd_crunchgen = rule(implementation = _impl, attrs = {
    "programs": attr.string_list(mandatory = True),
    "object_names": attr.string_list_dict(mandatory = True),
    "aliases": attr.string_list_dict(),
    "executable_name": attr.string(mandatory = True),
    "emit_stubs": attr.bool(default = False, doc = "Declare original crunchgen -s entry stubs."),
    "required_configuration": attr.label_keyed_string_dict(providers = [BuildSettingInfo]),
    "tool": attr.label(executable = True, cfg = "exec", default = "//usr.sbin/crunch/crunchgen:crunchgen"),
    "runner": attr.label(executable = True, cfg = "exec", default = "//tools/build/bazel:cwd_exec"),
    "libraries": attr.label_list(allow_files = True, cfg = "exec", default = [
        "@bsd_sdk//toolchain:sysroot/lib/libc.so.7",
        "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7",
    ]),
})
