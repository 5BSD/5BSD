# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//tools/build/bazel:bsd_install.bzl", "BsdInstallManifestInfo")
def _failure(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "duplicate installation destination")
    return analysistest.end(env)
failure_test = analysistest.make(_failure, expect_failure = True)
def _positive(ctx):
    env = analysistest.begin(ctx)
    records = analysistest.target_under_test(env)[BsdInstallManifestInfo].records
    asserts.equals(env, [dict(destination="/debug", type="dir", owner="root", group="wheel", mode="0755", flags="", tags=["package=bzip2", "dbg"])], records)
    return analysistest.end(env)
positive_test = analysistest.make(_positive)
