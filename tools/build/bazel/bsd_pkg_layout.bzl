# SPDX-License-Identifier: BSD-2-Clause
"""Partition declared installation providers into explicit pkgbase subpackages."""
load(":bsd_install.bzl", "BsdInstallManifestInfo", "resolve_hardlinks")

load(":bsd_pkg_dependency.bzl", "BsdPackageDependencyInfo")

BsdPackageLayoutInfo = provider(fields = ["packages", "dependencies", "payload", "manifest", "scope", "suffix_tags", "external_dependencies"])

def _layout(ctx):
    packages = {name: [] for name in ctx.attr.packages}
    if len(packages) != len(ctx.attr.packages) or not packages:
        fail("explicit unique package inventory required")
    if len(depset(ctx.attr.suffix_tags).to_list()) != len(ctx.attr.suffix_tags):
        fail("duplicate package suffix tag")
    records, owners, inputs = {}, {}, []
    for target in ctx.attr.manifests:
        info = target[BsdInstallManifestInfo]
        inputs.append(info.payload)
        for record in info.records:
            path = record["destination"]
            if path in records:
                fail("duplicate package destination: " + path)
            records[path] = record
            tags = record["tags"]
            bases = [tag[len("package="):] for tag in tags if tag.startswith("package=")]
            if len(bases) != 1 or not bases[0] or len(depset(tags).to_list()) != len(tags):
                fail("one package tag and no duplicate tags required: " + path)
            unknown = [tag for tag in tags if not tag.startswith("package=") and tag not in ctx.attr.suffix_tags and tag != "config"]
            if unknown:
                fail("unmodeled package tags: " + str(unknown))
            name = bases[0]
            for suffix in ctx.attr.suffix_tags:
                if suffix in tags:
                    name += "-" + suffix
            if name not in packages:
                fail("payload belongs to undeclared package: " + name)
            if "config" in tags and record["type"] != "file":
                fail("configuration entry must be a regular payload: " + path)
            packages[name].append(record)
            owners[path] = name
    roots = resolve_hardlinks(records)
    for path, record in records.items():
        if record["type"] == "hardlink" and owners[path] != owners[roots[path]]:
            fail("hardlink crosses package boundary: " + path)
    for name in packages:
        if not packages[name]:
            fail("empty package must have explicit metadata-only modeling: " + name)
    external = {}
    for target in ctx.attr.external_dependencies:
        info = target[BsdPackageDependencyInfo]
        if info.package in external or info.package in packages:
            fail("duplicate or internal external dependency: " + info.package)
        external[info.package] = dict(origin = info.origin, version = info.version)
    used_external = {}
    for name, deps in ctx.attr.dependencies.items():
        if name not in packages or name in deps or len(depset(deps).to_list()) != len(deps):
            fail("invalid package dependency declaration: " + name)
        for dep in deps:
            if dep not in packages:
                if dep not in external:
                    fail("external dependency requires explicit metadata modeling: " + dep)
                used_external[dep] = True
    if sorted(used_external) != sorted(external):
        fail("unused external package dependency declaration")
    manifest = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(manifest, json.encode(dict(format = 1, suffix_tags = ctx.attr.suffix_tags, scope = ctx.attr.scope, packages = packages, external_dependencies = external, dependencies = ctx.attr.dependencies)) + "\n")
    payload = depset(transitive = inputs)
    return [
        DefaultInfo(files = depset([manifest], transitive = [payload])),
        OutputGroupInfo(metadata = depset([manifest])),
        BsdPackageLayoutInfo(suffix_tags = ctx.attr.suffix_tags, scope = ctx.attr.scope, packages = packages, external_dependencies = external, dependencies = ctx.attr.dependencies, payload = payload, manifest = manifest),
    ]

bsd_pkg_layout = rule(
    implementation = _layout,
    attrs = {
        "scope": attr.string(default = "package", values = ["package", "component"]),
        "manifests": attr.label_list(providers = [BsdInstallManifestInfo], mandatory = True),
        "packages": attr.string_list(mandatory = True),
        "suffix_tags": attr.string_list(mandatory = True),
        "dependencies": attr.string_list_dict(),
        "external_dependencies": attr.label_list(providers = [BsdPackageDependencyInfo]),
    },
)
