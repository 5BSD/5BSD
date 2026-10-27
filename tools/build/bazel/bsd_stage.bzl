# SPDX-License-Identifier: BSD-2-Clause
"""Stage declared installation payloads using the maintained BSD installer."""
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
        tools = [ctx.executable.installer],
        outputs = [tree, metalog],
        env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDStageInstall",
    )
    return [DefaultInfo(files = depset([tree, metalog])), OutputGroupInfo(stage = depset([tree]), metalog = depset([metalog]))]

bsd_stage = rule(
    implementation = _stage,
    attrs = {
        "manifests": attr.label_list(providers = [BsdInstallManifestInfo], mandatory = True),
        "directories": attr.string_dict(mandatory = True),
        "installer": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    },
)
