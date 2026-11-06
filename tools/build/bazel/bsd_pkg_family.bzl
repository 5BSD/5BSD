# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned pkgbase family metadata; no payload, creation or publication claim."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")

BsdPackageFamilyInfo = provider(fields = ["family", "manifests", "metadata"])

def _name(value):
    if not value or any([c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.+,-" for c in value.elems()]):
        fail("valid explicit package identity required: " + value)
    return value

def _family(ctx):
    family = _name(ctx.attr.family)
    version = _name(ctx.attr.version[BuildSettingInfo].value)
    prefix = _name(ctx.attr.prefix[BuildSettingInfo].value)
    debug = ctx.attr.debug_files[BuildSettingInfo].value
    split = ctx.attr.split_manpages[BuildSettingInfo].value
    names = [family] if ctx.attr.base else []
    names += [family + "-" + part for part in ctx.attr.subpackages
        if (part != "dbg" or debug) and (part != "man" or split)]
    names += [family + "-" + part for part in ctx.attr.extra_subpackages]
    if not names or len(names) != len(depset(names).to_list()):
        fail("package family requires distinct selected package names")
    for name in names:
        _name(name)
    for name in ctx.attr.dependencies:
        if name not in names:
            fail("dependency declaration for inactive or unknown package: " + name)
        deps = ctx.attr.dependencies[name]
        if name in deps or len(deps) != len(depset(deps).to_list()):
            fail("duplicate or self package dependency: " + name)
        for dep in deps:
            _name(dep)
    if not ctx.file.template:
        fail("family default template is required; overrides are explicit")
    templates = {name: ctx.file.template for name in names}
    for name, target in ctx.attr.template_overrides.items():
        if name not in templates:
            fail("template override for inactive or unknown package: " + name)
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1 or files[0].is_directory:
            fail("one UCL template file required: " + name)
        templates[name] = files[0]
    for name in ctx.attr.vital + ctx.attr.metadata_only:
        if name not in names:
            fail("package property for inactive or unknown package: " + name)
    if "set" in ctx.attr.annotations:
        fail("declare family sets through the sets input")
    reserved = ["VERSION", "PKG_NAME_PREFIX", "PKG_WWW", "PKG_MAINTAINER", "PKGNAME", "PKGGENNAME", "SRCDIR"]
    for key, value in ctx.attr.ucl_variables.items():
        if not key or key in reserved or any([c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789" for c in key.elems()]):
            fail("invalid or reserved UCL variable: " + key)
        if any([c < " " for c in value.elems()]):
            fail("UCL variable contains control characters: " + key)
    outputs, declarations = {}, {}
    # A base override can include the default even when no subpackage selects it.
    all_templates = depset([ctx.file.template] + templates.values()).to_list()
    for name in names:
        full_name = prefix + "-" + name
        fields = dict(name = full_name, origin = "base/" + full_name, categories = ["base"], prefix = "/",
            version = version, maintainer = ctx.attr.maintainer[BuildSettingInfo].value,
            www = ctx.attr.www[BuildSettingInfo].value, licenselogic = ctx.attr.license_logic,
            licenses = ctx.attr.licenses, annotations = dict(ctx.attr.annotations, set = ",".join(ctx.attr.sets)))
        if name in ctx.attr.vital:
            fields["vital"] = True
        dependencies = ctx.attr.dependencies.get(name, [])
        if dependencies:
            fields["deps"] = {dep: dict(origin = "base/" + prefix + "-" + dep, version = version) for dep in dependencies}
        variables = dict(ctx.attr.ucl_variables, VERSION = version, PKG_NAME_PREFIX = prefix,
            PKG_WWW = fields["www"], PKG_MAINTAINER = fields["maintainer"], PKGNAME = name,
            PKGGENNAME = family, SRCDIR = ctx.label.package)
        output = ctx.actions.declare_file(ctx.label.name + "/" + full_name + ".pkgucl")
        request = ctx.actions.declare_file(ctx.label.name + "/" + full_name + ".inputs.json")
        ctx.actions.write(request, json.encode(dict(fields = fields, variables = variables,
            template = templates[name].path, flua = ctx.executable.flua.path, generator = ctx.file.generator.path)) + "\n")
        ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
            arguments = ["-B", "-S", ctx.file._driver.path, request.path, output.path],
            inputs = [request, ctx.file.generator, ctx.file._driver, ctx.file.python_home] + all_templates + ctx.files.template_inputs,
            tools = [ctx.attr.flua[DefaultInfo].files_to_run] + ctx.files.runtime, outputs = [output],
            env = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"},
            use_default_shell_env = False, mnemonic = "BSDPackageFamilyManifest")
        outputs[name] = output
        declarations[name] = dict(template = templates[name].path, dependencies = dependencies,
            vital = name in ctx.attr.vital, metadata_only = name in ctx.attr.metadata_only)
    metadata = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(metadata, json.encode(dict(format = 1, scope = "pkgbase-family-metadata",
        family = family, prefix = prefix, version = version, packages = declarations)) + "\n")
    return [DefaultInfo(files = depset([metadata] + outputs.values())),
        OutputGroupInfo(metadata = depset([metadata]), manifests = depset(outputs.values())),
        BsdPackageFamilyInfo(family = family, manifests = outputs, metadata = metadata)]

bsd_pkg_family = rule(implementation = _family, attrs = {
    "family": attr.string(mandatory = True), "base": attr.bool(default = True),
    "subpackages": attr.string_list(default = ["dbg", "man"]), "extra_subpackages": attr.string_list(),
    "template": attr.label(allow_single_file = True, mandatory = True),
    "template_overrides": attr.string_keyed_label_dict(allow_files = True),
    "template_inputs": attr.label_list(allow_files = True),
    "dependencies": attr.string_list_dict(), "vital": attr.string_list(), "metadata_only": attr.string_list(),
    "sets": attr.string_list(default = ["optional", "optional-jail"]),
    "annotations": attr.string_dict(), "ucl_variables": attr.string_dict(),
    "licenses": attr.string_list(default = ["BSD2CLAUSE"]), "license_logic": attr.string(default = "single"),
    "version": attr.label(default = "//tools/build/bazel/config:package_version", providers = [BuildSettingInfo]),
    "prefix": attr.label(default = "//tools/build/bazel/config:package_name_prefix", providers = [BuildSettingInfo]),
    "maintainer": attr.label(default = "//tools/build/bazel/config:package_maintainer", providers = [BuildSettingInfo]),
    "www": attr.label(default = "//tools/build/bazel/config:package_www", providers = [BuildSettingInfo]),
    "debug_files": attr.label(default = "//tools/build/bazel/config:debug_files", providers = [BuildSettingInfo]),
    "split_manpages": attr.label(default = "//tools/build/bazel/config:split_manpages", providers = [BuildSettingInfo]),
    "generator": attr.label(default = "//release/packages:generate-ucl.lua", allow_single_file = True, cfg = "exec"),
    "flua": attr.label(default = "@bsd_sdk//toolchain:extra_flua", executable = True, allow_single_file = True, cfg = "exec"),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_flua_runtime"], allow_files = True, cfg = "exec"),
    "_driver": attr.label(default = Label(":pkg_manifest.py"), allow_single_file = True),
})
