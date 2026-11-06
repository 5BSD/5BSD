# SPDX-License-Identifier: BSD-2-Clause
"""Build a disk image from complete native pkgbase and declared construction inputs."""
load(":bsd_install.bzl", "BsdInstallManifestInfo")
load(":bsd_pkg_family.bzl", "BsdPackageFamilySetInfo")

def _image(ctx):
    packages = ctx.files.packages
    indexes = [file for file in packages if file.basename == "index.json"]
    if len(indexes) != 1:
        fail("one complete package index required")
    archives = [file for file in packages if file.basename.endswith(".pkg")]
    if len(archives) + 1 != len(packages):
        fail("image packages must be indexed pkg archives")
    records, construction = [], []
    for target in ctx.attr.construction:
        info = target[BsdInstallManifestInfo]
        records.extend(info.records)
        construction.append(info.payload)
    site = ctx.attr.site[BsdInstallManifestInfo]
    image = ctx.actions.declare_file(ctx.label.name + ".img")
    report = ctx.actions.declare_file(ctx.label.name + ".report.json")
    metalog = ctx.actions.declare_file(ctx.label.name + ".METALOG")
    request = ctx.actions.declare_file(ctx.label.name + ".inputs.json")
    ctx.actions.write(request, json.encode(dict(format = 1,
        packages = [file.path for file in archives], index = indexes[0].path,
        catalogue = ctx.attr.families[BsdPackageFamilySetInfo].catalogue.path,
        inventory = ctx.file.inventory.path, payload_inventory = ctx.file.payload_inventory.path,
        construction = records, site = site.records, policy = ctx.file.policy.path,
        pkg = ctx.executable.pkg.path, makefs = ctx.executable.makefs.path,
        mkimg = ctx.executable.mkimg.path, abi_file = ctx.file.abi_file.path,
        osversion_header = ctx.file.osversion_header.path,
        runtime = [file.path for file in ctx.files.tool_runtime],
        image = image.path, report = report.path, metalog = metalog.path)) + "\n")
    inputs = [request, ctx.file._driver, ctx.file._root_module, ctx.file.policy, ctx.file.inventory,
        ctx.file.payload_inventory, indexes[0], ctx.attr.families[BsdPackageFamilySetInfo].catalogue,
        ctx.file.abi_file, ctx.file.osversion_header, ctx.file._python_home] + archives + ctx.files._runtime
    ctx.actions.run(executable = ctx.attr._python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", ctx.file._driver.path, request.path],
        inputs = depset(inputs, transitive = construction + [site.payload]),
        tools = [ctx.attr.pkg[DefaultInfo].files_to_run, ctx.attr.makefs[DefaultInfo].files_to_run,
            ctx.attr.mkimg[DefaultInfo].files_to_run] + ctx.files.tool_runtime,
        outputs = [image, report, metalog], env = {"LC_ALL": "C", "PYTHONHOME": ctx.file._python_home.dirname,
            "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "",
            "LD_LIBRARY_PATH": ":".join(sorted(depset([file.dirname for file in ctx.files._runtime]).to_list()))},
        use_default_shell_env = False, mnemonic = "BSDPackageImage")
    return [DefaultInfo(files = depset([image])), OutputGroupInfo(metadata = depset([request, report, metalog]))]

bsd_pkg_image = rule(implementation = _image, attrs = {
    "packages": attr.label(mandatory = True),
    "families": attr.label(providers = [BsdPackageFamilySetInfo], mandatory = True),
    "inventory": attr.label(allow_single_file = True, mandatory = True),
    "payload_inventory": attr.label(allow_single_file = True, mandatory = True),
    "construction": attr.label_list(providers = [BsdInstallManifestInfo], mandatory = True),
    "site": attr.label(providers = [BsdInstallManifestInfo], mandatory = True),
    "policy": attr.label(allow_single_file = True, mandatory = True),
    "abi_file": attr.label(default = "//usr.bin/uname:uname", allow_single_file = True),
    "osversion_header": attr.label(default = "//sys/sys:param.h", allow_single_file = True),
    "pkg": attr.label(default = "@bsd_sdk//toolchain:extra_pkg", executable = True, allow_single_file = True, cfg = "exec"),
    "makefs": attr.label(default = "//usr.sbin/makefs:makefs", executable = True, cfg = "exec"),
    "mkimg": attr.label(default = "//usr.bin/mkimg:mkimg", executable = True, cfg = "exec"),
    "tool_runtime": attr.label_list(default = ["//lib/libutil:util_shared", "//lib/libsbuf:sbuf_shared", "//lib/libz:z_shared",
        "@bsd_sdk//toolchain:execution-runtime/lib/libc.so.7", "@bsd_sdk//toolchain:execution-runtime/lib/libsys.so.7"], cfg = "exec", allow_files = True),
    "_root_module": attr.label(default = Label(":pkg_relocated.py"), cfg = "exec", allow_single_file = True),
    "_driver": attr.label(default = Label(":pkg_image.py"), cfg = "exec", allow_single_file = True),
    "_python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "_python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", cfg = "exec", allow_single_file = True),
    "_runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib"], cfg = "exec", allow_files = True),
})
