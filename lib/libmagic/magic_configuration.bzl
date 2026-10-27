# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "BsdInstallFileInfo")
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")
load("@rules_cc//cc/common:cc_info.bzl", "CcInfo")

MagicConfigurationInfo = provider(fields = ["directory"])

def _configuration(ctx):
    directory = ctx.attr.path[BuildSettingInfo].value
    if not directory.startswith("/") or any([p in ["", ".", ".."] for p in directory.split("/")[1:]]):
        fail("magic_path must be a normalized absolute directory")
    if any([c in directory for c in ["\n", "\r", "\t", "\\", '\"']]):
        fail("magic_path contains unsupported control or quoting characters")
    return [MagicConfigurationInfo(directory = directory),
            CcInfo(compilation_context = cc_common.create_compilation_context(
                defines = depset(['MAGIC="' + directory + '/magic"'])))]

magic_configuration = rule(implementation = _configuration, attrs = {
    "path": attr.label(providers = [BuildSettingInfo], mandatory = True),
})

def _manual(ctx):
    output = ctx.actions.declare_file(ctx.attr.output)
    args = ctx.actions.args()
    args.add_all([output.path, ctx.executable.awk.path, "-v",
                  "magic=" + ctx.attr.configuration[MagicConfigurationInfo].directory + "/magic",
                  "-f", ctx.file.script.path, ctx.file.config.path, ctx.file.template.path])
    ctx.actions.run(executable = ctx.executable.redirect, arguments = [args],
        inputs = [ctx.file.script, ctx.file.config, ctx.file.template] + ctx.files.runtime,
        tools = [ctx.attr.awk[DefaultInfo].files_to_run], outputs = [output],
        env = {"LC_ALL": "C"}, use_default_shell_env = False, mnemonic = "MagicManual")
    return [DefaultInfo(files = depset([output]))]

magic_manual = rule(implementation = _manual, attrs = {
    "configuration": attr.label(providers = [MagicConfigurationInfo], mandatory = True),
    "config": attr.label(allow_single_file = True, mandatory = True),
    "template": attr.label(allow_single_file = True, mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "output": attr.string(mandatory = True),
    "awk": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
    "runtime": attr.label_list(allow_files = True, cfg = "exec"),
})


def _database_install(ctx):
    directory = ctx.attr.configuration[MagicConfigurationInfo].directory
    source = ctx.file.src
    if source and ctx.attr.basename not in ["magic", "magic.mgc"]:
        fail("database installation requires the maintained database filename")
    if not source and ctx.attr.basename:
        fail("directory installation cannot have a basename")
    metadata = {"destination": directory + ("/" + ctx.attr.basename if source else ""),
                "owner": "root", "group": "wheel", "mode": "0444" if source else "0755",
                "tags": ["package=libmagic"], "type": "file" if source else "dir", "flags": ""}
    return [BsdInstallFileInfo(source = source, metadata = metadata),
            DefaultInfo(files = depset([source] if source else []))]

magic_database_install = rule(implementation = _database_install, attrs = {
    "configuration": attr.label(providers = [MagicConfigurationInfo], mandatory = True),
    "src": attr.label(allow_single_file = True),
    "basename": attr.string(),
})
