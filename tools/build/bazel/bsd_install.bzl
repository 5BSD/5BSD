# SPDX-License-Identifier: BSD-2-Clause
load(":bsd_kyua_metadata.bzl", "kyua_metadata_fields")
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
"""Typed installation payloads. No writes to the host installation tree."""
# A disabled optional entry carries neither source nor metadata. Manifests must
# skip it before composing payload dependencies and checking hardlink closure.
BsdInstallFileInfo = provider(fields = ["source", "metadata"])
BsdInstallManifestInfo = provider(fields = ["manifest", "payload", "records"])

def _install_destination(destination, settings):
    prefixes = []
    for setting in settings:
        value = setting[BuildSettingInfo].value
        if type(value) != "string" or (value and not value.startswith("/")):
            fail("installation prefixes must be absolute directory strings or empty")
        prefixes.append(value.rstrip("/"))
    destination = "".join(prefixes) + destination
    if not destination.startswith("/") or ".." in destination.split("/"):
        fail("installation destination must be absolute without traversal")
    return destination

def _install_file(ctx):
    destination = _install_destination(ctx.attr.destination, ctx.attr.destination_prefixes)
    if ctx.attr.manual and not ctx.attr._man[BuildSettingInfo].value:
        return [BsdInstallFileInfo(source = None, metadata = None), DefaultInfo(files = depset())]
    metadata = {
        "destination": destination,
        "owner": ctx.attr.owner,
        "group": ctx.attr.group,
        "mode": ctx.attr.mode,
        "tags": ctx.attr.install_tags,
        "type": "file",
        "flags": ctx.attr.flags,
    }
    return [BsdInstallFileInfo(source = ctx.file.src, metadata = metadata),
            DefaultInfo(files = depset([ctx.file.src]))]

bsd_install_file = rule(
    implementation = _install_file,
    attrs = {
        "manual": attr.bool(default = False, doc = "Source-owned manual payload/alias controlled by MAN."),
        "_man": attr.label(default = Label("//tools/build/bazel/config:man"), providers = [BuildSettingInfo]),
        "src": attr.label(allow_single_file = True, mandatory = True),
        "flags": attr.string(),
        "destination": attr.string(mandatory = True),
        "destination_prefixes": attr.label_list(providers = [BuildSettingInfo], doc = "Ordered configured directory prefixes; empty strings are allowed."),
        "owner": attr.string(mandatory = True),
        "group": attr.string(mandatory = True),
        "mode": attr.string(mandatory = True),
        "install_tags": attr.string_list(mandatory = True),
    },
)

def resolve_hardlinks(records):
    """Validate inode relationships and resolve chains in O(vertices + edges)."""
    roots, pending, queue = {}, {}, []
    for path, record in records.items():
        if record["type"] == "file":
            roots[path] = path
            queue.append(path)
        elif record["type"] == "hardlink":
            target = record["link"]
            original = records.get(target)
            if original == None or original["type"] not in ["file", "hardlink"]:
                fail("hardlink must reference a regular payload file or hardlink: " + target)
            if target not in pending:
                pending[target] = []
            pending[target].append(path)
    # Each vertex enters the queue once. Index a bounded loop so appending does
    # not mutate a Starlark list under iteration, and no recursion is needed.
    for index in range(len(records)):
        if index == len(queue):
            break
        target = queue[index]
        for path in pending.get(target, []):
            root = roots[target]
            for key in ["owner", "group", "mode", "flags"]:
                if records[root].get(key, "") != records[path].get(key, ""):
                    fail("hardlink inode metadata differs: " + path)
            roots[path] = root
            queue.append(path)
    for path, record in records.items():
        if record["type"] == "hardlink" and path not in roots:
            fail("hardlink cycle: " + path)
    return roots

def _append_installation_record(entries, seen, record, merge_identical_directories):
    path = record["destination"]
    if path in seen:
        # World installation repeats directory records across components. Only
        # an explicit composition may coalesce complete, identical metadata.
        if (merge_identical_directories and record["type"] == "dir" and
            record == seen[path]):
            return
        fail("duplicate installation destination: " + path)
    seen[path] = record
    entries.append(record)

def _install_manifest(ctx):
    entries, payload, seen = [], [], {}
    inherited_payloads = []
    for target in ctx.attr.manifests:
        info = target[BsdInstallManifestInfo]
        inherited_payloads.append(info.payload)
        for original in info.records:
            _append_installation_record(entries, seen, dict(original), ctx.attr.merge_identical_directories)
    for target in ctx.attr.entries:
        item = target[BsdInstallFileInfo]
        if item.metadata == None:
            continue
        record = dict(item.metadata)
        if item.source != None:
            record["source"] = item.source.path
        _append_installation_record(entries, seen, record, ctx.attr.merge_identical_directories)
        if item.source != None:
            payload.append(item.source)
    resolve_hardlinks(seen)
    manifest = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.write(manifest, json.encode({"format": 1, "files": entries}) + "\n")
    inputs = depset(payload, transitive = inherited_payloads)
    # Building an installation target must materialize its declared payloads.
    # Consumers needing only metadata can select the manifest output group.
    return [DefaultInfo(files = depset([manifest], transitive = [inputs])),
            OutputGroupInfo(manifest = depset([manifest]), payload = inputs),
            BsdInstallManifestInfo(manifest = manifest, payload = inputs, records = entries)]

bsd_install_manifest = rule(
    implementation = _install_manifest,
    attrs = {
        "entries": attr.label_list(providers = [BsdInstallFileInfo]),
        "manifests": attr.label_list(providers = [BsdInstallManifestInfo]),
        "merge_identical_directories": attr.bool(default = False),
    },
)

def _kyuafile(ctx):
    content = "-- Automatically generated by bsd.test.mk.\n\nsyntax(2)\n\ntest_suite(" + json.encode(ctx.attr.suite) + ")\n\n"
    if len(depset(ctx.attr.names).to_list()) != len(ctx.attr.names):
        fail("duplicate Kyua program name")
    for name in ctx.attr.metadata:
        if name not in ctx.attr.names:
            fail("metadata for unknown Kyua program: " + name)
    metadata = dict(ctx.attr.metadata)
    for setting, name in ctx.attr.required_programs_settings.items():
        if name not in ctx.attr.names:
            fail("required-program setting for unknown Kyua program: " + name)
        fields = json.decode(metadata.get(name, "{}"))
        if "required_programs" in fields:
            fail("duplicate required_programs for " + name)
        fields["required_programs"] = setting[BuildSettingInfo].value
        metadata[name] = json.encode(fields)
    for name in ctx.attr.names:
        interface = ctx.attr.interfaces[name]
        if interface not in ["atf", "tap", "plain"]:
            fail("unsupported Kyua interface: " + interface)
        fields = kyua_metadata_fields(metadata.get(name, "{}"))
        content += interface + "_test_program{name=" + json.encode(name) + ", " + ", ".join(fields) + "}\n"
    for directory in ctx.attr.subdirectories:
        if not directory or any([part in ["", ".", ".."] for part in directory.split("/")]):
            fail("Kyua subdirectories require normalized relative paths")
        content += "include(" + json.encode(directory + "/Kyuafile") + ")\n"
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.write(output, content)
    return [DefaultInfo(files = depset([output]))]

bsd_kyuafile = rule(
    implementation = _kyuafile,
    attrs = {
        "output": attr.string(default = "Kyuafile", doc = "Package-relative output path for composing multiple suite registrations."),
        "suite": attr.string(mandatory = True),
        "names": attr.string_list(mandatory = True),
        "interfaces": attr.string_dict(mandatory = True),
        "subdirectories": attr.string_list(),
        "metadata": attr.string_dict(doc = "Per-program JSON objects of typed Kyua properties."),
        "required_programs_settings": attr.label_keyed_string_dict(providers = [BuildSettingInfo], doc = "Build setting to test-program name for required_programs."),
    },
)


def _install_link(ctx):
    destination = _install_destination(ctx.attr.destination, ctx.attr.destination_prefixes)
    if ctx.attr.kind == "hardlink" and (not ctx.attr.target.startswith("/") or ".." in ctx.attr.target.split("/")):
        fail("hardlink target must be an installation destination")
    if ctx.attr.manual and not ctx.attr._man[BuildSettingInfo].value:
        return [BsdInstallFileInfo(source = None, metadata = None), DefaultInfo(files = depset())]
    metadata = {"destination": destination, "owner": ctx.attr.owner,
                "group": ctx.attr.group, "mode": ctx.attr.mode,
                "tags": ctx.attr.install_tags, "type": ctx.attr.kind, "link": ctx.attr.target}
    return [BsdInstallFileInfo(source = None, metadata = metadata), DefaultInfo(files = depset())]

bsd_install_link = rule(
    implementation = _install_link,
    attrs = {
        "manual": attr.bool(default = False, doc = "Source-owned manual payload/alias controlled by MAN."),
        "_man": attr.label(default = Label("//tools/build/bazel/config:man"), providers = [BuildSettingInfo]),
        "destination": attr.string(mandatory = True),
        "destination_prefixes": attr.label_list(providers = [BuildSettingInfo], doc = "Ordered configured directory prefixes; empty strings are allowed."),
        "target": attr.string(mandatory = True),
        "kind": attr.string(values = ["symlink", "hardlink"], mandatory = True),
        "owner": attr.string(mandatory = True),
        "group": attr.string(mandatory = True),
        "mode": attr.string(mandatory = True),
        "install_tags": attr.string_list(mandatory = True),
    },
)

def _compress(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    ctx.actions.run(
        executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = [output.path, ctx.executable.compressor.path] + ctx.attr.arguments + [ctx.file.src.path],
        inputs = [ctx.file.src], tools = [ctx.attr.compressor[DefaultInfo].files_to_run] + ctx.files.runtime,
        outputs = [output], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "BSDCompressManual",
    )
    return [DefaultInfo(files = depset([output]))]

bsd_compress = rule(
    implementation = _compress,
    attrs = {
        "runtime": attr.label_list(allow_files = True, cfg = "exec"),
        "src": attr.label(allow_single_file = True, mandatory = True),
        "output": attr.string(mandatory = True),
        "arguments": attr.string_list(mandatory = True),
        "compressor": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
        "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    },
)


def _install_directory(ctx):
    metadata = {
        "destination": _install_destination(ctx.attr.destination, ctx.attr.destination_prefixes),
        "type": "dir", "owner": ctx.attr.owner, "group": ctx.attr.group,
        "mode": ctx.attr.mode, "tags": ctx.attr.install_tags, "flags": ctx.attr.flags,
    }
    return [BsdInstallFileInfo(source = None, metadata = metadata), DefaultInfo(files = depset())]

bsd_install_directory = rule(
    implementation = _install_directory,
    attrs = {
        "destination": attr.string(mandatory = True),
        "destination_prefixes": attr.label_list(providers = [BuildSettingInfo]),
        "owner": attr.string(mandatory = True),
        "group": attr.string(mandatory = True),
        "mode": attr.string(mandatory = True),
        "install_tags": attr.string_list(mandatory = True),
        "flags": attr.string(),
    },
)
