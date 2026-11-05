# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned rescue application compiler variants, distinct from hosted programs."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load(":bsd_component_archive.bzl", "bsd_component_selected_objects", "BSDComponentObjectsInfo")
load(":bsd_dtrace.bzl", "bsd_dtrace_cc_objects", "BSDDTraceObjectsInfo")

# Actual nested bsd.crunchgen.mk child policy: normal SSP/debug, no PIE/PIC.
# Parent-only MK_SSP=no does not propagate to these child compilations.
_WARNINGS = ['-pipe', '-fno-common', '-std=gnu17', '-Wno-format-zero-length', '-Wsystem-headers', '-Werror', '-Wall', '-Wno-format-y2k', '-W', '-Wno-unused-parameter', '-Wstrict-prototypes', '-Wmissing-prototypes', '-Wpointer-arith', '-Wreturn-type', '-Wcast-qual', '-Wwrite-strings', '-Wswitch', '-Wshadow', '-Wunused-parameter', '-Wcast-align', '-Wchar-subscripts', '-Wnested-externs', '-Wold-style-definition', '-Wno-pointer-sign', '-Wdate-time', '-Wmissing-variable-declarations', '-Wthread-safety', '-Wno-empty-body', '-Wno-string-plus-int', '-Wno-unused-const-variable', '-Wno-error=unused-but-set-parameter', '-Wno-error=cast-function-type-mismatch', '-Qunused-arguments']
# Source-owned WARNS profiles for the selected Clang toolchain, checked against
# actual nested Make recipes. Existing WARNS=6 declarations stay unchanged.
_WARNINGS_BY_LEVEL = {
    0: ['-pipe', '-fno-common', '-std=gnu17', '-Wno-format-zero-length', '-Wno-pointer-sign', '-Wdate-time', '-Wno-empty-body', '-Wno-string-plus-int', '-Wno-unused-const-variable', '-Wno-error=unused-but-set-parameter', '-Wno-error=cast-function-type-mismatch', '-Wno-tautological-compare', '-Wno-unused-value', '-Wno-parentheses-equality', '-Wno-unused-function', '-Wno-enum-conversion', '-Wno-unused-local-typedef', '-Wno-address-of-packed-member', '-Wno-switch', '-Wno-switch-enum', '-Wno-knr-promoted-parameter', '-Wno-parentheses', '-Qunused-arguments'],
    1: ['-pipe', '-fno-common', '-std=gnu17', '-Wno-format-zero-length', '-Wsystem-headers', '-Werror', '-Wno-pointer-sign', '-Wdate-time', '-Wno-empty-body', '-Wno-string-plus-int', '-Wno-unused-const-variable', '-Wno-error=unused-but-set-parameter', '-Wno-error=cast-function-type-mismatch', '-Wno-tautological-compare', '-Wno-unused-value', '-Wno-parentheses-equality', '-Wno-unused-function', '-Wno-enum-conversion', '-Wno-unused-local-typedef', '-Wno-address-of-packed-member', '-Wno-switch', '-Wno-switch-enum', '-Wno-knr-promoted-parameter', '-Wno-parentheses', '-Qunused-arguments'],
    2: ['-pipe', '-fno-common', '-std=gnu17', '-Wno-format-zero-length', '-Wsystem-headers', '-Werror', '-Wall', '-Wno-format-y2k', '-Wno-uninitialized', '-Wno-pointer-sign', '-Wdate-time', '-Wno-empty-body', '-Wno-string-plus-int', '-Wno-unused-const-variable', '-Wno-error=unused-but-set-parameter', '-Wno-error=cast-function-type-mismatch', '-Wno-tautological-compare', '-Wno-unused-value', '-Wno-parentheses-equality', '-Wno-unused-function', '-Wno-enum-conversion', '-Wno-unused-local-typedef', '-Wno-address-of-packed-member', '-Wno-switch', '-Wno-switch-enum', '-Wno-knr-promoted-parameter', '-Qunused-arguments'],
    3: ['-pipe', '-fno-common', '-std=gnu17', '-Wno-format-zero-length', '-Wsystem-headers', '-Werror', '-Wall', '-Wno-format-y2k', '-W', '-Wno-unused-parameter', '-Wstrict-prototypes', '-Wmissing-prototypes', '-Wpointer-arith', '-Wno-uninitialized', '-Wno-pointer-sign', '-Wdate-time', '-Wno-empty-body', '-Wno-string-plus-int', '-Wno-unused-const-variable', '-Wno-error=unused-but-set-parameter', '-Wno-error=cast-function-type-mismatch', '-Wno-tautological-compare', '-Wno-unused-value', '-Wno-parentheses-equality', '-Wno-unused-function', '-Wno-enum-conversion', '-Wno-unused-local-typedef', '-Wno-address-of-packed-member', '-Qunused-arguments'],
    6: _WARNINGS,
}
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_TRACE = "//tools/build/bazel/config:dtrace_enabled"

def _transformed_objects(ctx):
    original = ctx.attr.original[BSDComponentObjectsInfo]
    objects = original.objects
    names = original.names
    if ctx.attr.transformed:
        rewritten = ctx.attr.transformed[BSDDTraceObjectsInfo]
        if any([obj not in rewritten.regular for obj in objects]) or not rewritten.regular_provider:
            fail("rescue rewrite must expose every selected regular object and provider")
        objects = [rewritten.regular[obj] for obj in objects] + [rewritten.regular_provider]
        names = names + [ctx.attr.provider_name + ".o"]
    return [DefaultInfo(files = depset(objects)), BSDComponentObjectsInfo(objects = objects, names = names, archives = original.archives)]

rescue_transformed_objects = rule(implementation = _transformed_objects, attrs = {
    "original": attr.label(providers = [BSDComponentObjectsInfo], mandatory = True),
    "transformed": attr.label(providers = [BSDDTraceObjectsInfo]),
    "provider_name": attr.string(mandatory = True),
})

def rescue_application(srcs, object_names = None, deps = [], copts = [], defines = [], provider = None, warns = 6, textual_hdrs = [], omitted_warnings = [], ordered_sources = None, components = [], compiler_options = None, archives = []):
    """Declare own compiler outputs with original source/object order metadata.

    Separate native compilation groups model source-specific options. Explicit
    compiler_options are source-owned full policies; other callers use WARNS.
    Provider artifacts carry exact rewrite maps, never inferred filename rules.
    """
    if object_names != None and ordered_sources != None:
        fail("choose object_names or ordered_sources")
    if provider and components:
        fail("provider-bearing extra compilation groups require explicit rewrite composition")
    if warns not in _WARNINGS_BY_LEVEL:
        fail("unsupported rescue WARNS profile: " + str(warns))
    if len(depset(omitted_warnings).to_list()) != len(omitted_warnings):
        fail("duplicate omitted rescue warning")
    for flag in omitted_warnings:
        if not flag.startswith("-W") or flag not in _WARNINGS_BY_LEVEL[warns]:
            fail("unknown omitted rescue warning: " + flag)
    if compiler_options != None:
        if warns != 6 or copts or omitted_warnings:
            fail("explicit compiler_options cannot be combined with WARNS/copts overrides")
        options = compiler_options
    else:
        options = [flag for flag in _WARNINGS_BY_LEVEL[warns] if flag not in omitted_warnings] + copts
    cc_library(name = "rescue_objects", srcs = srcs, textual_hdrs = textual_hdrs,
        local_defines = ["RESCUE"] + defines + (select({_TRACE: ["WITH_COVERAGE_DTRACE"], "//conditions:default": []}) if provider else []),
        deps = deps + (select({_TRACE: [":provider_headers"], "//conditions:default": []}) if provider else []),
        copts = options, target_compatible_with = _PLATFORM)
    bsd_component_selected_objects(name = "rescue_raw_compiler_outputs" if provider else "rescue_compiler_outputs",
        groups = [":rescue_objects"] + components, archives = archives,
        object_names = object_names if object_names != None else [],
        ordered_sources = ordered_sources if ordered_sources != None else [],
        visibility = ["//visibility:public"])
    if provider:
        bsd_dtrace_cc_objects(name = "rescue_traced_objects", library = ":rescue_objects", provider = ":provider",
            provider_object = provider, copy_runner = "//tools/build/bazel:dtrace_copy_runner")
        native.filegroup(name = "rescue_provider_outputs", srcs = [":rescue_traced_objects"], output_group = "regular")
        rescue_transformed_objects(name = "rescue_compiler_outputs", original = ":rescue_raw_compiler_outputs",
            transformed = select({_TRACE: ":rescue_traced_objects", "//conditions:default": None}),
            provider_name = provider, visibility = ["//visibility:public"])
