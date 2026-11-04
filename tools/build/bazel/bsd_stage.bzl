# SPDX-License-Identifier: BSD-2-Clause
"""Local physical materialization; canonical installation archives are cacheable.

A directory artifact cannot serialize POSIX hardlink identity or BSD installation
policy. Never upload/restore this output through a file-content action cache.
"""
load(":bsd_install.bzl", "BsdInstallManifestInfo", "resolve_hardlinks")

def _quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"

def _path(path):
    if not path.startswith("/") or (path != "/" and ("" in path[1:].split("/") or "." in path.split("/") or ".." in path.split("/"))):
        fail("installation path must be absolute and normalized: " + path)

def _parent(path):
    return path.rsplit("/", 1)[0] or "/"

def _stage(ctx):
    directories = {p: json.decode(v) for p, v in ctx.attr.directories.items()}
    if "/" not in directories:
        fail("stage requires explicit root directory policy")
    for path in directories:
        _path(path)
        if path != "/" and _parent(path) not in directories:
            fail("undeclared parent directory: " + path)
    records, inputs = {}, []
    for target in ctx.attr.manifests:
        info = target[BsdInstallManifestInfo]
        inputs.append(info.payload)
        for record in info.records:
            path = record["destination"]
            _path(path)
            if path in records or path in directories:
                fail("duplicate stage destination: " + path)
            if _parent(path) not in directories:
                fail("undeclared payload parent: " + path)
            records[path] = record
    hardlink_roots = resolve_hardlinks(records)
    tree = ctx.actions.declare_directory(ctx.label.name + ".root")
    metalog = ctx.actions.declare_file(ctx.label.name + ".METALOG")
    script = ctx.actions.declare_file(ctx.label.name + ".sh")
    common = [ctx.executable.installer.path, "-U", "-D", tree.path, "-M", metalog.path, "-h", "sha256"]
    lines = ["set -eu", ": > " + _quote(metalog.path)]
    # Lexical ordering places every parent before its descendants.
    for path in sorted(directories):
        meta = directories[path]
        if meta["type"] != "dir":
            fail("non-directory policy: " + path)
        argv = common + ["-d", "-o", meta["uname"], "-g", meta["gname"], "-m", meta["mode"]]
        if meta.get("flags"):
            argv += ["-f", meta["flags"]]
        if meta.get("tags"):
            argv += ["-T", ",".join(meta["tags"])]
        argv += [tree.path if path == "/" else tree.path + path]
        lines.append(" ".join([_quote(v) for v in argv]))
    for kind in ["file", "hardlink", "symlink"]:
        for path in sorted(records):
            meta = records[path]
            if meta["type"] != kind:
                continue
            argv = common + ["-o", meta["owner"], "-g", meta["group"], "-m", meta["mode"]]
            if meta.get("flags"):
                argv += ["-f", meta["flags"]]
            if meta["tags"]:
                argv += ["-T", ",".join(meta["tags"])]
            if kind == "file":
                source = meta["source"]
            elif kind == "hardlink":
                argv += ["-l", "h"]
                source = tree.path + hardlink_roots[path]
            else:
                argv += ["-l", "s"]
                source = meta["link"]
            argv += ["--", source, tree.path + path]
            lines.append(" ".join([_quote(v) for v in argv]))
    ctx.actions.write(script, "\n".join(lines) + "\n")
    ctx.actions.run(
        executable = ctx.executable.shell,
        arguments = [script.path],
        inputs = depset([script], transitive = inputs),
        tools = [ctx.attr.installer[DefaultInfo].files_to_run, ctx.attr.shell[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [tree, metalog],
        env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDStageInstall",
        execution_requirements = {"no-cache": "1", "no-remote": "1"},
    )
    return [DefaultInfo(files = depset([tree, metalog])), OutputGroupInfo(stage = depset([tree]), metalog = depset([metalog]))]

bsd_stage = rule(
    implementation = _stage,
    attrs = {
        "manifests": attr.label_list(providers = [BsdInstallManifestInfo], mandatory = True),
        "directories": attr.string_dict(mandatory = True),
        "installer": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "runtime": attr.label_list(cfg = "exec", allow_files = True, doc = "Declared execution runtimes for file-based installer/shell tools."),
        "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    },
)
