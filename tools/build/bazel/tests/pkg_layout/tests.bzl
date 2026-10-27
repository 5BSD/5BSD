# SPDX-License-Identifier: BSD-2-Clause
load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_pkg_layout.bzl", "BsdPackageLayoutInfo", "bsd_pkg_layout")

load("@bazel_skylib//rules:common_settings.bzl", "string_flag")
load("//tools/build/bazel:bsd_pkg_manifest.bzl", "bsd_pkg_manifests")
load("//tools/build/bazel:bsd_pkg_dependency.bzl", "bsd_pkg_dependency")

def _failure(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.expected)
    return analysistest.end(env)

failure_test = analysistest.make(_failure, expect_failure = True, attrs = {"expected": attr.string(mandatory = True)})

def _valid(ctx):
    env = analysistest.begin(ctx)
    info = analysistest.target_under_test(env)[BsdPackageLayoutInfo]
    asserts.equals(env, ["p"], sorted(info.packages.keys()))
    asserts.equals(env, ["/z", "/a"], [record["destination"] for record in info.packages["p"]])
    asserts.equals(env, 1, len(info.payload.to_list()))
    asserts.equals(env, {}, info.dependencies)
    return analysistest.end(env)

valid_test = analysistest.make(_valid)

def _external(ctx):
    env = analysistest.begin(ctx)
    info = analysistest.target_under_test(env)[BsdPackageLayoutInfo]
    asserts.equals(env, {"p": ["external"]}, info.dependencies)
    asserts.equals(env, {"external": {"origin": "base/Test-external", "version": "1"}}, info.external_dependencies)
    return analysistest.end(env)

external_test = analysistest.make(_external)

def layout_tests(name):
    cases = [
        dict(name = "valid", tags = ["package=p"], packages = ["p"], expected = None),
        dict(name = "missing_tag", tags = [], packages = ["p"], expected = "one package tag"),
        dict(name = "duplicate_tag", tags = ["package=p", "package=p"], packages = ["p"], expected = "one package tag"),
        dict(name = "unknown_tag", tags = ["package=p", "unmodeled"], packages = ["p"], expected = "unmodeled package tags"),
        dict(name = "undeclared", tags = ["package=p"], packages = ["q"], expected = "payload belongs to undeclared package"),
        dict(name = "empty", tags = ["package=p"], packages = ["p", "q"], expected = "empty package"),
        dict(name = "cross_link", tags = ["package=p"], packages = ["p", "q"], link_tags = ["package=q"], expected = "hardlink crosses package boundary"),
        dict(name = "self_dep", tags = ["package=p"], packages = ["p"], dependencies = {"p": ["p"]}, expected = "invalid package dependency declaration"),
        dict(name = "external_dep", tags = ["package=p"], packages = ["p"], dependencies = {"p": ["external"]}, expected = "external dependency requires explicit metadata"),
    ]
    tests = []
    for case in cases:
        prefix = case["name"]
        bsd_install_file(name = prefix + "_file", src = "payload.txt", destination = "/z",
                         owner = "root", group = "wheel", mode = "0444", install_tags = case["tags"], tags = ["manual"])
        bsd_install_link(name = prefix + "_link", destination = "/a", target = "/z", kind = "hardlink",
                         owner = "root", group = "wheel", mode = "0444", install_tags = case.get("link_tags", case["tags"]), tags = ["manual"])
        bsd_install_manifest(name = prefix + "_manifest", entries = [":" + prefix + "_file", ":" + prefix + "_link"], tags = ["manual"])
        bsd_pkg_layout(name = prefix + "_subject", manifests = [":" + prefix + "_manifest"],
                       packages = case["packages"], suffix_tags = ["dev", "dbg", "lib"],
                       dependencies = case.get("dependencies", {}), tags = ["manual"])
        test = prefix + "_test"
        if case["expected"] == None:
            valid_test(name = test, target_under_test = ":" + prefix + "_subject")
        else:
            failure_test(name = test, target_under_test = ":" + prefix + "_subject", expected = case["expected"])
        tests.append(":" + test)
    # Exercise the real manifest rule with otherwise valid inputs. Failure must
    # be the component-scope guard, not missing version/tool/template metadata.
    string_flag(name = "fixture_version", build_setting_default = "1")
    bsd_pkg_layout(name = "component_subject", manifests = [":valid_manifest"],
                   packages = ["p"], suffix_tags = [], scope = "component", tags = ["manual"])
    bsd_pkg_manifests(
        name = "component_manifest_subject",
        layout = ":component_subject", version = ":fixture_version",
        template = "payload.txt", prefix = "Test", maintainer = "test@example.invalid",
        www = "https://example.invalid", license_logic = "single", licenses = ["BSD2CLAUSE"],
        generator = "//release/packages:generate-ucl.lua",
        flua = "@bsd_sdk//toolchain:extra_flua",
        python = "@bsd_sdk//toolchain:extra_python",
        python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_flua_runtime"],
        tags = ["manual"],
    )
    failure_test(name = "component_scope_test", target_under_test = ":component_manifest_subject",
                 expected = "component partition cannot produce complete package manifests")
    tests.append(":component_scope_test")
    template_cases = [
        ("missing_template", {}, "per-package templates must cover the exact package inventory"),
        ("extra_template", {"templates": {"p": "payload.txt", "unowned": "payload.txt"}}, "per-package templates must cover the exact package inventory"),
        ("ambiguous_template", {"template": "payload.txt", "templates": {"p": "payload.txt"}}, "choose a common template or exact per-package templates, not both"),
    ]
    for case, template_attrs, message in template_cases:
        bsd_pkg_manifests(
            name = case + "_subject", layout = ":valid_subject", version = ":fixture_version",
            prefix = "Test", maintainer = "test@example.invalid", www = "https://example.invalid",
            license_logic = "single", licenses = ["BSD2CLAUSE"],
            generator = "//release/packages:generate-ucl.lua",
            flua = "@bsd_sdk//toolchain:extra_flua", python = "@bsd_sdk//toolchain:extra_python",
            python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
            runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_flua_runtime"],
            tags = ["manual"], **template_attrs
        )
        failure_test(name = case + "_test", target_under_test = ":" + case + "_subject", expected = message)
        tests.append(":" + case + "_test")
    for label, package in [("external", "external"), ("duplicate", "external"), ("internal", "p")]:
        bsd_pkg_dependency(name = label + "_identity", package = package,
                           origin = "base/Test-" + package, version = ":fixture_version", tags = ["manual"])
    for case, identities, deps, message in [
        ("explicit_external", [":external_identity"], {"p": ["external"]}, None),
        ("duplicate_external", [":external_identity", ":duplicate_identity"], {"p": ["external"]}, "duplicate or internal external dependency"),
        ("internal_collision", [":internal_identity"], {}, "duplicate or internal external dependency"),
        ("unused_external", [":external_identity"], {}, "unused external package dependency"),
        ("duplicate_edge", [":external_identity"], {"p": ["external", "external"]}, "invalid package dependency declaration"),
    ]:
        bsd_pkg_layout(name = case + "_subject", manifests = [":valid_manifest"], packages = ["p"],
                       suffix_tags = [], external_dependencies = identities, dependencies = deps, tags = ["manual"])
        if message == None:
            external_test(name = case + "_test", target_under_test = ":" + case + "_subject")
        else:
            failure_test(name = case + "_test", target_under_test = ":" + case + "_subject", expected = message)
        tests.append(":" + case + "_test")
    string_flag(name = "invalid_version", build_setting_default = "bad version")
    for case, package, origin, version, message in [
        ("invalid_name", "bad/name", "base/Test-external", ":fixture_version", "valid explicit package name and version"),
        ("invalid_version", "external", "base/Test-external", ":invalid_version", "valid explicit package name and version"),
        ("invalid_origin", "external", "../escape", ":fixture_version", "explicit category/package origin"),
    ]:
        bsd_pkg_dependency(name = case + "_subject", package = package, origin = origin, version = version, tags = ["manual"])
        failure_test(name = case + "_test", target_under_test = ":" + case + "_subject", expected = message)
        tests.append(":" + case + "_test")
    native.test_suite(name = name, tests = tests)
