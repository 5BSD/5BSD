# SPDX-License-Identifier: BSD-2-Clause
"""Inspect a selected Ficl context using the declared execution tools."""
load("//tools/build/bazel:bsd_python_test.bzl", "bsd_host_artifact_test")

def ficl_archive_test(name, archive, setting, compatible):
    bsd_host_artifact_test(name = name, src = "archive-test.py",
        data = [archive, ":inspection_tools", "@bsd_sdk//toolchain:bin/llvm-ar", "@bsd_sdk//toolchain:bin/llvm-nm"],
        args = ["--verification"] + select({setting: ["yes"], "//conditions:default": ["no"]}) +
            ["--machine"] + select({"@platforms//cpu:x86_64": ["62"], "@platforms//cpu:aarch64": ["183"], "@platforms//cpu:riscv64": ["243"], "//conditions:default": ["0"]}) +
            ["--archive", "$(location " + archive + ")", "--ar", "$(location @bsd_sdk//toolchain:bin/llvm-ar)",
             "--nm", "$(location @bsd_sdk//toolchain:bin/llvm-nm)", "--tool-inputs", "$(locations :inspection_tools)"],
        visibility = ["//visibility:public"], target_compatible_with = compatible, size = "small")
