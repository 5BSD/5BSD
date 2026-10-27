# SPDX-License-Identifier: BSD-2-Clause
"""Declared native pkg creation; no package publication or host installation."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load(":bsd_pkg_manifest.bzl", "BsdPackageManifestsInfo")

load(":bsd_install_archive.bzl", "BsdInstallArchiveInfo")

def _create(ctx):
    threads = ctx.attr.threads[BuildSettingInfo].value
    if type(threads) != "int" or threads < 0 or ctx.attr.epoch < 0:
        fail("nonnegative compression threads and epoch required")
    info = ctx.attr.manifests[BsdPackageManifestsInfo]
    outputs = {}
    for name in sorted(info.manifests):
        filename = info.prefix + "-" + name + "-" + info.version + ".pkg"
        if any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.+,-" for c in filename.elems()]):
            fail("invalid package output filename")
        outputs[name] = ctx.actions.declare_file(ctx.label.name + "/" + filename)
    index = ctx.actions.declare_file(ctx.label.name + "/index.json")
    request = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(request, json.encode(dict(
        index = index.path,
        packages = info.layout.packages,
        manifests = {name: file.path for name, file in info.manifests.items()},
        outputs = {name: file.path for name, file in outputs.items()},
        directory_metadata = ctx.attr.archive[BsdInstallArchiveInfo].directory_metadata.path,
        suffix_tags = info.layout.suffix_tags,
        archive = ctx.file.archive.path, abi_file = ctx.file.abi_file.path,
        osversion_header = ctx.file.osversion_header.path,
        pkg = ctx.executable.pkg.path, tar = ctx.executable.tar.path,
        format = ctx.attr.format, threads = threads, epoch = ctx.attr.epoch,
    )) + "\n")
    args = ctx.actions.args()
    args.add_all(["-B", "-S", ctx.file._driver.path, request.path])
    ctx.actions.run(
        executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = [request, ctx.file._driver, ctx.file.archive, ctx.attr.archive[BsdInstallArchiveInfo].directory_metadata, ctx.file.abi_file, ctx.file.osversion_header, ctx.file.python_home] + info.manifests.values(),
        tools = [ctx.attr.pkg[DefaultInfo].files_to_run, ctx.attr.tar[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = outputs.values() + [index],
        env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
        use_default_shell_env = False,
        mnemonic = "BSDPackageCreate",
    )
    return [DefaultInfo(files = depset(outputs.values() + [index])), OutputGroupInfo(package_index = depset([index]))]

bsd_pkg_create = rule(
    implementation = _create,
    attrs = {
        "manifests": attr.label(providers = [BsdPackageManifestsInfo], mandatory = True),
        "archive": attr.label(allow_single_file = True, providers = [BsdInstallArchiveInfo], mandatory = True),
        "abi_file": attr.label(allow_single_file = True, mandatory = True),
        "osversion_header": attr.label(allow_single_file = True, mandatory = True),
        "format": attr.string(values = ["tzst", "txz", "tbz", "tgz", "tar"], mandatory = True),
        "threads": attr.label(providers = [BuildSettingInfo], mandatory = True),
        "epoch": attr.int(mandatory = True),
        "pkg": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "tar": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "python_home": attr.label(cfg = "exec", allow_single_file = True, mandatory = True),
        "runtime": attr.label_list(cfg = "exec", allow_files = True),
        "_driver": attr.label(default = Label(":pkg_create.py"), allow_single_file = True, cfg = "exec"),
    },
)
