# SPDX-License-Identifier: BSD-2-Clause
"""Artifact boundary between hosted world consumers and freestanding producers.

The dependency selects its target platform; MODULE.bazel registers the disjoint
SDK toolchains. Execution tools use
Bazel's execution configuration. No CcInfo crosses this boundary: boot objects
must not become hosted link dependencies accidentally.
"""
load(":bsd_install.bzl", "BsdInstallFileInfo", "BsdInstallManifestInfo")

_CPU = {
    "amd64": "@platforms//cpu:x86_64",
    "aarch64": "@platforms//cpu:aarch64",
    "riscv64": "@platforms//cpu:riscv64",
}

def _transition_impl(settings, attr):
    return {"//command_line_option:platforms": [
        "@bsd_sdk//toolchain:standalone_" + attr.architecture,
    ]}

_standalone = transition(
    implementation = _transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _impl(ctx):
    if len(ctx.attr.src) != 1:
        fail("one freestanding artifact dependency required")
    target = ctx.attr.src[0]
    default = target[DefaultInfo]
    if default.files_to_run.executable != None:
        fail("freestanding boundary accepts artifacts, not executable tools or tests")
    result = [DefaultInfo(files = default.files, runfiles = default.default_runfiles)]
    for info in [OutputGroupInfo, BsdInstallFileInfo, BsdInstallManifestInfo]:
        if info in target:
            result.append(target[info])
    return result

_artifact = rule(
    implementation = _impl,
    attrs = {
        "src": attr.label(mandatory = True, cfg = _standalone),
        "architecture": attr.string(mandatory = True, values = _CPU.keys()),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist"),
    },
)

def bsd_freestanding_artifact(name, src, architecture = None, **kwargs):
    """Forward an artifact and installation providers under a standalone ABI.

    By default retain the consumer's CPU; explicit architecture supports a
    host-driven multi-architecture image. Both use the verified SDK platforms.
    """
    selected = architecture if architecture != None else select({cpu: arch for arch, cpu in _CPU.items()})
    _artifact(name = name, src = src, architecture = selected, **kwargs)
