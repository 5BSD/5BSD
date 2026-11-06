# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts", "unittest")
load("//tools/build/bazel:package_symlinks.bzl", "inspection_paths")

def _valid(ctx):
    env = unittest.begin(ctx)
    records = {
        "/aliases/relative": {"type": "symlink", "link": "../real/image"},
        "/aliases/absolute": {"type": "symlink", "link": "/real/image"},
        "/aliases/chain": {"type": "symlink", "link": "relative"},
        "/directory": {"type": "symlink", "link": "/real/deep"},
    }
    asserts.equals(env, ["/aliases/relative", "/real/image"], sorted(inspection_paths("/aliases/relative", records)))
    asserts.equals(env, ["/aliases/absolute", "/real/image"], sorted(inspection_paths("/aliases/absolute", records)))
    asserts.equals(env, ["/aliases/chain", "/aliases/relative", "/real/image"], sorted(inspection_paths("/aliases/chain", records)))
    asserts.equals(env, ["/directory", "/real/deep/image"], sorted(inspection_paths("/directory/image", records)))
    asserts.equals(env, ["/directory", "/real/image"], sorted(inspection_paths("/directory/../image", records)))
    asserts.equals(env, ["/missing"], inspection_paths("/../../missing", records))
    chain = {"/link" + str(i): {"type": "symlink", "link": "/link" + str(i + 1)} for i in range(40)}
    asserts.equals(env, 41, len(inspection_paths("/link0", chain)))
    asserts.true(env, "/link40" in inspection_paths("/link0", chain))
    return unittest.end(env)

valid_test = unittest.make(_valid)

def _fixture(ctx):
    inspection_paths("/link0", {path: {"type": "symlink", "link": target} for path, target in ctx.attr.links.items()})
    return [DefaultInfo()]

fixture = rule(implementation = _fixture, attrs = {"links": attr.string_dict(mandatory = True)})

def _failure(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, "package inspection exceeds 40 symlinks")
    return analysistest.end(env)

failure_test = analysistest.make(_failure, expect_failure = True)
