# SPDX-License-Identifier: BSD-2-Clause
"""Native per-package actions over reconciled source installation providers."""
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load(":bsd_pkg_family.bzl", "BsdPackageFamilySetInfo")
load(":bsd_install.bzl", "resolve_hardlinks")
load(":package_symlinks.bzl", "inspection_paths")
load(":bsd_install_archive.bzl", "BsdInstallArchiveSetInfo")

def _package_name(tags, suffixes):
    bases = [t[len("package="):] for t in tags if t.startswith("package=")]
    if len(bases) != 1:
        fail("one source package tag required")
    return bases[0] + "".join(["-" + suffix for suffix in suffixes if suffix in tags])

def _create(ctx):
    families = ctx.attr.families[BsdPackageFamilySetInfo]
    archives = ctx.attr.archives[BsdInstallArchiveSetInfo]
    threads = ctx.attr.threads[BuildSettingInfo].value
    jobs = ctx.attr.jobs[BuildSettingInfo].value
    epoch = ctx.attr.epoch[BuildSettingInfo].value
    if threads < 0 or jobs <= 0 or epoch < 0:
        fail("nonnegative epoch/threads and positive build_jobs required")
    if threads == 0:
        threads = jobs
    files = {f.path: f for f in archives.payload.to_list()}
    records = {r["destination"]: r for r in archives.records if r["type"] != "dir"}
    roots = resolve_hardlinks(records)
    sources = {name: {} for name in families.manifests}
    trees = {name: [] for name in families.manifests}
    for path, record in records.items():
        if not record["tags"] or record["type"] not in ["file", "hardlink"]:
            continue
        name = _package_name(record["tags"], ctx.attr.suffix_tags)
        if name not in sources:
            fail("unselected package payload: " + name)
        source = records[roots[path]]["source"]
        if source not in files:
            fail("source record lacks its declared payload File: " + source)
        sources[name][source] = files[source]
    # Pkg inspects the ELF behind installation aliases. Those referents are
    # action inputs, even when they are owned by a different package.
    for path, record in records.items():
        if record["type"] != "symlink" or not record["tags"]:
            continue
        name = _package_name(record["tags"], ctx.attr.suffix_tags)
        for target in inspection_paths(path, records):
            referent = records.get(target)
            if referent != None and referent["type"] in ["file", "hardlink"]:
                source = records[roots[target]]["source"]
                if source not in files:
                    fail("inspection referent lacks its declared File: " + source)
                sources[name][source] = files[source]
            for tree in archives.trees:
                if target == tree.prefix or target.startswith(tree.prefix.rstrip("/") + "/") or target in tree.destinations:
                    trees[name].append(tree.tree)
                    for file in tree.files:
                        sources[name][file.path] = file
    for tree in archives.trees:
        names = depset([_package_name(tags, ctx.attr.suffix_tags) for tags in [tree.file_tags, tree.directory_tags] if tags]).to_list()
        for name in names:
            if name not in trees:
                fail("unselected generated-tree package: " + name)
            trees[name].append(tree.tree)
            for file in tree.files:
                sources[name][file.path] = file
    trees = {name: depset(entries).to_list() for name, entries in trees.items()}
    plans = {name: ctx.actions.declare_file(ctx.label.name + "/plans/" + name + ".json") for name in families.manifests}
    plan_request = ctx.actions.declare_file(ctx.label.name + "/plans.inputs.json")
    ctx.actions.write(plan_request, json.encode(dict(inventory = ctx.file.inventory.path,
        catalogue = families.catalogue.path, reconciliation = ctx.file.reconciliation.path,
        outputs = {name: f.path for name, f in plans.items()})) + "\n")
    common_inputs = [ctx.file._driver, ctx.file.python_home] + ctx.files._modules
    environment = {"PYTHONHOME": ctx.file.python_home.dirname, "PYTHONNOUSERSITE": "1", "LC_ALL": "C"}
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", ctx.file._driver.path, "plans", plan_request.path],
        inputs = common_inputs + [plan_request, ctx.file.inventory, families.catalogue, ctx.file.reconciliation],
        tools = ctx.files.runtime, outputs = plans.values(), env = environment,
        use_default_shell_env = False, mnemonic = "BSDWorldPackagePlans")
    outputs, indexes = [], []
    for name, manifest in families.manifests.items():
        output = ctx.actions.declare_file(ctx.label.name + "/" + families.prefix + "-" + name + "-" + families.version + ".pkg")
        index = ctx.actions.declare_file(ctx.label.name + "/indexes/" + name + ".json")
        request = ctx.actions.declare_file(ctx.label.name + "/inputs/" + name + ".json")
        ctx.actions.write(request, json.encode(dict(package = name, plan = plans[name].path,
            manifest = manifest.path, output = output.path, index = index.path,
            sources = sorted(sources[name]), trees = [t.path for t in trees[name]],
            abi_file = ctx.file.abi_file.path, osversion_header = ctx.file.osversion_header.path,
            pkg = ctx.executable.pkg.path, format = ctx.attr.format, threads = threads, epoch = epoch)) + "\n")
        ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
            arguments = ["-B", "-S", ctx.file._driver.path, "package", request.path],
            inputs = common_inputs + [request, plans[name], manifest, ctx.file.abi_file, ctx.file.osversion_header] + sources[name].values() + trees[name],
            tools = [ctx.attr.pkg[DefaultInfo].files_to_run] + ctx.files.runtime,
            outputs = [output, index], env = environment, use_default_shell_env = False,
            resource_set = {"cpu": threads, "memory": ctx.attr.memory_mb}, mnemonic = "BSDWorldPackageCreate")
        outputs.append(output)
        indexes.append(index)
    index = ctx.actions.declare_file(ctx.label.name + "/index.json")
    request = ctx.actions.declare_file(ctx.label.name + "/index.inputs.json")
    ctx.actions.write(request, json.encode(dict(indexes = [f.path for f in indexes], output = index.path)) + "\n")
    ctx.actions.run(executable = ctx.attr.python[DefaultInfo].files_to_run,
        arguments = ["-B", "-S", ctx.file._driver.path, "index", request.path],
        inputs = common_inputs + [request] + indexes, tools = ctx.files.runtime,
        outputs = [index], env = environment, use_default_shell_env = False, mnemonic = "BSDWorldPackageIndex")
    return [DefaultInfo(files = depset(outputs + [index])),
        OutputGroupInfo(metadata = depset(plans.values()), package_index = depset([index]))]

bsd_world_pkg_create = rule(implementation = _create, attrs = {
    "families": attr.label(providers = [BsdPackageFamilySetInfo], mandatory = True),
    "archives": attr.label(providers = [BsdInstallArchiveSetInfo], mandatory = True),
    "inventory": attr.label(allow_single_file = True, mandatory = True),
    "reconciliation": attr.label(allow_single_file = True, mandatory = True),
    "suffix_tags": attr.string_list(mandatory = True),
    "abi_file": attr.label(allow_single_file = True, mandatory = True),
    "osversion_header": attr.label(default = Label("//sys/sys:param.h"), allow_single_file = True),
    "format": attr.string(default = "tzst", values = ["tzst", "txz", "tbz", "tgz", "tar"]),
    "threads": attr.label(default = Label("//tools/build/bazel/config:package_threads"), providers = [BuildSettingInfo]),
    "jobs": attr.label(default = Label("//tools/build/bazel/config:build_jobs"), providers = [BuildSettingInfo]),
    "epoch": attr.label(default = Label("//tools/build/bazel/config:package_epoch"), providers = [BuildSettingInfo]),
    "memory_mb": attr.int(default = 512),
    "pkg": attr.label(default = "@bsd_sdk//toolchain:extra_pkg", executable = True, allow_single_file = True, cfg = "exec"),
    "python": attr.label(default = "@bsd_sdk//toolchain:extra_python", executable = True, allow_single_file = True, cfg = "exec"),
    "python_home": attr.label(default = "@bsd_sdk//toolchain:python-home/runtime.json", allow_single_file = True, cfg = "exec"),
    "runtime": attr.label_list(default = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_pkg_runtime"], allow_files = True, cfg = "exec"),
    "_driver": attr.label(default = Label(":world_pkg_create.py"), allow_single_file = True),
    "_modules": attr.label_list(default = [Label(":pkg_create.py"), Label(":package_symlinks.py")], allow_files = True),
})
