# SPDX-License-Identifier: BSD-2-Clause
"""Shared configured dispatcher and static-link declarations for native rescue."""
load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//tools/build/bazel:bsd_crunchgen.bzl", "bsd_crunchgen")
load(":catalog.bzl", "ALIASES", "PROGRAMS")
load(":selection.bzl", "selected_programs", "selected_program_values")

def rescue_dispatcher(name, executable_name, objects, emit_stubs = False):
    bsd_crunchgen(name = name, executable_name = executable_name, emit_stubs = emit_stubs,
        programs = selected_programs(), catalog_programs = PROGRAMS,
        applications = selected_program_values(objects),
        aliases = {p: ALIASES[p] for p in PROGRAMS if p in ALIASES and p != "ping"} | select({
            "//tools/build/bazel/config:inet6_support_enabled": {"ping": ["ping6"]}, "//conditions:default": {},
        }))

def rescue_binary(name, dispatcher, crunched_objects, visibility = None):
    cc_binary(name = name, srcs = [dispatcher] + crunched_objects + ["//rescue/librescue:regular_compiler_outputs"],
        visibility = visibility,
        deps = [":core_crypt_static_link"],
        features = ["fully_static_link"],
        linkstatic = True,
        linkopts = ["-nodefaultlibs", "-Wl,--allow-multiple-definition", "-Wl,-znow", "-Wl,-zrelro",
            "@$(location //lib/csu/amd64:startup_link_flags)"],
        additional_linker_inputs = ["//lib/csu/amd64:startup", "//lib/csu/amd64:startup_link_flags"],
        target_compatible_with = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"],
    )
