# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//rules:common_settings.bzl", "BuildSettingInfo")
load("//tools/build/bazel:bsd_install.bzl", "BsdInstallFileInfo")

def _default_repository(ctx):
    branch = ctx.attr.branch[BuildSettingInfo].value
    channel = ctx.attr.channel[BuildSettingInfo].value
    if not channel:
        if not branch:
            fail("pkg repository selection requires version_branch or pkg_config_branch, or an explicit pkg_repository_config label")
        words = branch.split(" ")
        if "CURRENT" in words:
            channel = "latest"
        elif any([word.startswith(prefix) for word in words for prefix in ["BETA", "RC", "RELEASE"]]):
            channel = "quarterly-release"
        elif any([ctx.target_platform_has_constraint(cpu[platform_common.ConstraintValueInfo]) for cpu in ctx.attr.latest_cpus]):
            channel = "latest"
        else:
            channel = "quarterly"
    choices = {"latest": ctx.file.latest, "quarterly": ctx.file.quarterly, "quarterly-release": ctx.file.release}
    if channel not in choices:
        fail("unknown pkg_config_branch; supply pkg_repository_config for a custom file")
    return [DefaultInfo(files = depset([choices[channel]]))]

default_repository = rule(implementation = _default_repository, attrs = {
    "branch": attr.label(default = "//tools/build/bazel/config:version_branch", providers = [BuildSettingInfo]),
    "channel": attr.label(default = "//tools/build/bazel/config:pkg_config_branch", providers = [BuildSettingInfo]),
    "latest_cpus": attr.label_list(default = ["@platforms//cpu:x86_64", "@platforms//cpu:x86_32", "@platforms//cpu:aarch64"]),
    "latest": attr.label(default = "FreeBSD.conf.latest", allow_single_file = True),
    "quarterly": attr.label(default = "FreeBSD.conf.quarterly", allow_single_file = True),
    "release": attr.label(default = "FreeBSD.conf.quarterly-release", allow_single_file = True),
})

def _repository_install(ctx):
    source = ctx.file.src
    # Match CONFSNAME_${PKGCONF}: remove the suffix following .conf.
    name = source.basename
    index = name.find(".conf")
    if index >= 0:
        name = name[:index + 5]
    return [BsdInstallFileInfo(source = source, metadata = {
        "destination": "/etc/pkg/" + name, "owner": "root", "group": "wheel",
        "mode": "0644", "tags": ["package=pkg-bootstrap", "config"], "type": "file", "flags": "",
    }), DefaultInfo(files = depset([source]))]

repository_install = rule(implementation = _repository_install, attrs = {
    "src": attr.label(default = "//tools/build/bazel/config:pkg_repository_config", allow_single_file = True),
})
