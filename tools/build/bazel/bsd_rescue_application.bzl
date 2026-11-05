# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned rescue application compiler variants, distinct from hosted programs."""
load("@rules_cc//cc:defs.bzl", "cc_library")
load(":bsd_component_archive.bzl", "bsd_component_selected_objects")
load(":bsd_dtrace.bzl", "bsd_dtrace_cc_objects")

# Actual nested bsd.crunchgen.mk child policy: normal SSP/debug, no PIE/PIC.
# Parent-only MK_SSP=no does not propagate to these child compilations.
_WARNINGS = ['-pipe', '-fno-common', '-std=gnu17', '-Wno-format-zero-length', '-Wsystem-headers', '-Werror', '-Wall', '-Wno-format-y2k', '-W', '-Wno-unused-parameter', '-Wstrict-prototypes', '-Wmissing-prototypes', '-Wpointer-arith', '-Wreturn-type', '-Wcast-qual', '-Wwrite-strings', '-Wswitch', '-Wshadow', '-Wunused-parameter', '-Wcast-align', '-Wchar-subscripts', '-Wnested-externs', '-Wold-style-definition', '-Wno-pointer-sign', '-Wdate-time', '-Wmissing-variable-declarations', '-Wthread-safety', '-Wno-empty-body', '-Wno-string-plus-int', '-Wno-unused-const-variable', '-Wno-error=unused-but-set-parameter', '-Wno-error=cast-function-type-mismatch', '-Qunused-arguments']
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]
_TRACE = "//tools/build/bazel/config:dtrace_enabled"

def rescue_application(srcs, object_names, deps = [], copts = [], defines = [], provider = None):
    """Declare compiler outputs only; ordered crunch/link/install stay in the parent.

    Provider/header targets belong to the application package. Supplying no
    provider is intentional for Make's RESCUE-specific coverage exclusions.
    """
    cc_library(name = "rescue_objects", srcs = srcs,
        local_defines = ["RESCUE"] + defines + (select({_TRACE: ["WITH_COVERAGE_DTRACE"], "//conditions:default": []}) if provider else []),
        deps = deps + (select({_TRACE: [":provider_headers"], "//conditions:default": []}) if provider else []),
        copts = _WARNINGS + copts, target_compatible_with = _PLATFORM)
    bsd_component_selected_objects(name = "rescue_raw_compiler_outputs" if provider else "rescue_compiler_outputs",
        group = ":rescue_objects", object_names = object_names, visibility = ["//visibility:public"])
    if provider:
        bsd_dtrace_cc_objects(name = "rescue_traced_objects", library = ":rescue_objects", provider = ":provider",
            provider_object = provider, copy_runner = "//tools/build/bazel:dtrace_copy_runner")
        native.filegroup(name = "rescue_provider_outputs", srcs = [":rescue_traced_objects"], output_group = "regular")
        native.filegroup(name = "rescue_compiler_outputs", srcs = select({_TRACE: [":rescue_provider_outputs"], "//conditions:default": [":rescue_raw_compiler_outputs"]}),
            visibility = ["//visibility:public"])
