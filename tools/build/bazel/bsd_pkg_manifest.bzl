# SPDX-License-Identifier: BSD-2-Clause
"""Generate declared pkgbase manifests with the maintained UCL processor."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load(":bsd_pkg_layout.bzl", "BsdPackageLayoutInfo")

BsdPackageManifestsInfo = provider(fields = ["manifests", "version", "prefix", "layout"])

def _manifests(ctx):
    version = ctx.attr.version[BuildSettingInfo].value
    if not version or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.+,-" for c in version.elems()]):
        fail("explicit valid package version setting required")
    layout = ctx.attr.layout[BsdPackageLayoutInfo]
    if layout.scope != "package":
        fail("component partition cannot produce complete package manifests")
    if ctx.file.template and ctx.attr.templates:
        fail("choose a common template or exact per-package templates, not both")
    templates = {}
    if ctx.file.template:
        templates = {name: ctx.file.template for name in layout.packages}
    else:
        if sorted(ctx.attr.templates.keys()) != sorted(layout.packages.keys()):
            fail("per-package templates must cover the exact package inventory")
        for name, target in ctx.attr.templates.items():
            files = target[DefaultInfo].files.to_list()
            if len(files) != 1:
                fail("one template file required for package: " + name)
            templates[name] = files[0]
    outputs = {}
    for name in sorted(layout.packages):
        template = templates[name]
        full_name = ctx.attr.prefix + "-" + name
        output = ctx.actions.declare_file(ctx.label.name + "/" + full_name + ".pkgucl")
        request = ctx.actions.declare_file(ctx.label.name + "/" + full_name + ".json")
        fields = dict(name = full_name, origin = "base/" + full_name, categories = ["base"], prefix = "/",
                      version = version, maintainer = ctx.attr.maintainer, www = ctx.attr.www,
                      licenselogic = ctx.attr.license_logic, licenses = ctx.attr.licenses,
                      annotations = ctx.attr.annotations)
        dependencies = layout.dependencies.get(name, [])
        if dependencies:
            fields["deps"] = {dep: layout.external_dependencies.get(dep, dict(origin = "base/" + ctx.attr.prefix + "-" + dep, version = version)) for dep in dependencies}
        # Dependency edges belong to the layout provider. Empty PKGGENNAME
        # disables the Lua generator's automatic family dependency inference.
        variables = dict(VERSION = version, PKG_NAME_PREFIX = ctx.attr.prefix,
                         PKG_WWW = ctx.attr.www, PKG_MAINTAINER = ctx.attr.maintainer,
                         PKGNAME = name, PKGGENNAME = "", SRCDIR = template.dirname)
        ctx.actions.write(request, json.encode(dict(fields = fields, variables = variables,
            template = template.path, flua = ctx.executable.flua.path, generator = ctx.file.generator.path)) + "\n")
        args = ctx.actions.args()
        args.add_all(["-B", "-S", ctx.file._driver.path, request.path, output.path])
        ctx.actions.run(
            executable = ctx.attr.python[DefaultInfo].files_to_run,
            arguments = [args],
            inputs = [request, template, ctx.file.generator, ctx.file._driver, ctx.file.python_home] + ctx.files.template_inputs,
            tools = [ctx.attr.flua[DefaultInfo].files_to_run] + ctx.files.runtime,
            outputs = [output],
            env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
            use_default_shell_env = False,
            mnemonic = "BSDPackageManifest",
        )
        outputs[name] = output
    return [DefaultInfo(files = depset(outputs.values())),
            BsdPackageManifestsInfo(manifests = outputs, version = version, prefix = ctx.attr.prefix, layout = layout)]

bsd_pkg_manifests = rule(
    implementation = _manifests,
    attrs = {
        "layout": attr.label(providers = [BsdPackageLayoutInfo], mandatory = True),
        "version": attr.label(providers = [BuildSettingInfo], mandatory = True),
        "prefix": attr.string(mandatory = True),
        "maintainer": attr.string(mandatory = True),
        "www": attr.string(mandatory = True),
        "license_logic": attr.string(mandatory = True),
        "licenses": attr.string_list(mandatory = True),
        "annotations": attr.string_dict(),
        "template": attr.label(allow_single_file = True),
        "templates": attr.string_keyed_label_dict(allow_files = True),
        "template_inputs": attr.label_list(allow_files = True),
        "generator": attr.label(allow_single_file = True, cfg = "exec", mandatory = True),
        "flua": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "python": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "python_home": attr.label(cfg = "exec", allow_single_file = True, mandatory = True),
        "runtime": attr.label_list(cfg = "exec", allow_files = True),
        "_driver": attr.label(default = Label(":pkg_manifest.py"), allow_single_file = True, cfg = "exec"),
    },
)
