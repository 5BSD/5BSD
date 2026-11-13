# SPDX-License-Identifier: BSD-2-Clause
"""Construct a bounded certificate tree from selected package payloads.

The tree contains paths relative to its installation prefix (normally /etc/ssl),
so bsd_install_tree_archive can serialize the dynamic output without root-wide
exceptions. certctl alone parses certificates and chooses subject-hash names.
"""
load(":bsd_install.bzl", "BsdInstallManifestInfo")
load(":bsd_install_archive.bzl", "BsdInstallArchiveInfo")
load(":bsd_python_test.bzl", "bsd_python_test")

def _destination(path):
    if not path or path.startswith("/") or any([part in ["", ".", ".."] for part in path.split("/")]) or any([c in " \t\r\n\\" for c in path.elems()]):
        fail("canonical relative certificate output path required")
    return path

def _certificates(targets):
    records = {}
    payloads = []
    for target in targets:
        info = target[BsdInstallManifestInfo]
        payloads.append(info.payload)
        for row in info.records:
            if row["type"] == "dir":
                continue
            if row["type"] != "file":
                fail("certificate selection requires regular certificate installation records")
            if row["destination"] in records:
                fail("duplicate certificate installation destination")
            records[row["destination"]] = row["source"]
    # Installation order and directory discovery never determine trust precedence.
    files = {file.path: file for payload in payloads for file in payload.to_list()}
    return [files[records[path]] for path in sorted(records)], payloads

def _store(ctx):
    trusted, trusted_payloads = _certificates(ctx.attr.trusted)
    untrusted, untrusted_payloads = _certificates(ctx.attr.untrusted)
    trust_dir = _destination(ctx.attr.trusted_directory)
    distrust_dir = _destination(ctx.attr.untrusted_directory)
    bundle = _destination(ctx.attr.bundle)
    if trust_dir == distrust_dir or trust_dir.startswith(distrust_dir + "/") or distrust_dir.startswith(trust_dir + "/"):
        fail("trusted and untrusted output trees must not overlap")
    if any([bundle == path or bundle.startswith(path + "/") or path.startswith(bundle + "/") for path in [trust_dir, distrust_dir]]):
        fail("certificate bundle must not overlap certificate directories")
    tree = ctx.actions.declare_directory(ctx.label.name + ".root")
    metalog = ctx.actions.declare_file(ctx.label.name + ".METALOG")
    args = ctx.actions.args()
    args.add_all(["-E", "-U", "-D", tree.path, "-M", metalog.path,
                  "-C", tree.path + "/" + trust_dir, "-R", tree.path + "/" + distrust_dir,
                  "-b", tree.path + "/" + bundle])
    args.add_all(trusted, before_each = "-T")
    args.add_all(untrusted, before_each = "-X")
    args.add("rehash")
    runtime = ctx.files.runtime
    ctx.actions.run(executable = ctx.attr.certctl[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = depset(transitive = trusted_payloads + untrusted_payloads),
        tools = [ctx.attr.certctl[DefaultInfo].files_to_run] + runtime,
        outputs = [tree, metalog], use_default_shell_env = False,
        env = {"LC_ALL": "C", "PATH": "/nonexistent",
               "LD_LIBRARY_PATH": ":".join(sorted(depset([file.dirname for file in runtime]).to_list()))},
        mnemonic = "BSDCertificateStore")
    return [DefaultInfo(files = depset([tree])),
            OutputGroupInfo(metadata = depset([metalog]))]

bsd_certificate_store = rule(implementation = _store, attrs = {
    "trusted": attr.label_list(providers = [BsdInstallManifestInfo], mandatory = True),
    "untrusted": attr.label_list(providers = [BsdInstallManifestInfo], mandatory = True),
    "trusted_directory": attr.string(default = "certs"),
    "untrusted_directory": attr.string(default = "untrusted"),
    "bundle": attr.string(default = "cert.pem"),
    "certctl": attr.label(default = "//usr.sbin/certctl:certctl", executable = True, cfg = "exec"),
    "runtime": attr.label_list(allow_files = True, cfg = "exec", mandatory = True),
})

def _runfile(ctx, file):
    path = file.short_path
    return path[3:] if path.startswith("../") else ctx.workspace_name + "/" + path

def _test_selection(ctx):
    trusted, _ = _certificates(ctx.attr.trusted)
    untrusted, _ = _certificates(ctx.attr.untrusted)
    tree = ctx.file.store
    metadata = ctx.attr.store[OutputGroupInfo].metadata.to_list()
    if len(metadata) != 1:
        fail("one certificate-store METALOG required")
    archive = ctx.file.archive
    archive_trees = ctx.attr.archive[BsdInstallArchiveInfo].trees
    if len(archive_trees) != 1 or archive_trees[0].tree != tree:
        fail("certificate test archive must serialize the selected producer tree")
    archive_metadata = archive_trees[0].metadata
    tools = [ctx.executable.certctl, ctx.executable.openssl]
    runtime = ctx.files.runtime
    names = {}
    for file in runtime:
        if file.basename in names and names[file.basename] != file:
            fail("ambiguous certificate test runtime library " + file.basename)
        names[file.basename] = file
    output = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(output, json.encode(dict(format = 1,
        certctl = _runfile(ctx, tools[0]), openssl = _runfile(ctx, tools[1]),
        trusted = [_runfile(ctx, file) for file in trusted],
        untrusted = [_runfile(ctx, file) for file in untrusted],
        runtime = [_runfile(ctx, file) for file in runtime],
        tree = _runfile(ctx, tree), tree_execpath = tree.path, metalog = _runfile(ctx, metadata[0]),
        archive = _runfile(ctx, archive), archive_metadata = _runfile(ctx, archive_metadata),
        prefix = archive_trees[0].prefix)) + "\n")
    files = tools + runtime + trusted + untrusted + [tree, metadata[0], archive, archive_metadata, output]
    runfiles = ctx.runfiles(files = files).merge_all([
        target[DefaultInfo].default_runfiles for target in [ctx.attr.certctl, ctx.attr.openssl, ctx.attr.store]
    ])
    return [DefaultInfo(files = depset([output]), runfiles = runfiles)]

_test_inputs = rule(implementation = _test_selection, attrs = {
    "trusted": attr.label_list(providers = [BsdInstallManifestInfo], mandatory = True),
    "untrusted": attr.label_list(providers = [BsdInstallManifestInfo], mandatory = True),
    "store": attr.label(allow_single_file = True, mandatory = True),
    "archive": attr.label(allow_single_file = True, providers = [BsdInstallArchiveInfo], mandatory = True),
    "certctl": attr.label(default = "//usr.sbin/certctl:certctl", executable = True, cfg = "exec"),
    "openssl": attr.label(default = "//secure/usr.bin/openssl:openssl", executable = True, cfg = "exec"),
    "runtime": attr.label_list(allow_files = True, cfg = "exec", mandatory = True),
})

def certificate_store_test(name, store, archive, trusted, untrusted, runtime):
    """Execute host tools against selected target certificate data and produced tree."""
    _test_inputs(name = name + "_inputs", store = store, archive = archive, trusted = trusted,
        untrusted = untrusted, runtime = runtime, testonly = True)
    bsd_python_test(name = name, src = "//tools/build/bazel:certificate-store-test.py",
        data = [":" + name + "_inputs"],
        args = ["--selection", "$(rlocationpath :" + name + "_inputs)"],
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_python_runtime"],
        size = "small")
