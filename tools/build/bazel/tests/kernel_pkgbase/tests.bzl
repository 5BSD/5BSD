# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//tools/build/bazel:bsd_install_archive.bzl", "BsdInstallArchiveInfo")
def _failure(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.diagnostic)
    return analysistest.end(env)
failure_test = analysistest.make(_failure, expect_failure = True,
    attrs = {"diagnostic": attr.string(mandatory = True)})

# A configuration-name guard needs only the archive provider contract; pulling
# the full kernel graph through an analysis-test transition exceeds Bazel's
# dependency guard. Complete real archives are qualified separately.
def _fixture(ctx):
    return [DefaultInfo(files = depset([ctx.file.metadata])),
        BsdInstallArchiveInfo(directory_metadata = ctx.file.metadata,
            records = [], payload = depset(), trees = [])]
fixture_archive = rule(implementation = _fixture, attrs = {
    "metadata": attr.label(allow_single_file = True, mandatory = True),
})
