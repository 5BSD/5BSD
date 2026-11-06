# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
_MANUAL_ALIASES = ['atf-sh-api.3', 'atf_add_test_case.3', 'atf_check.3', 'atf_check_equal.3', 'atf_config_get.3', 'atf_config_has.3', 'atf_expect_death.3', 'atf_expect_exit.3', 'atf_expect_fail.3', 'atf_expect_pass.3', 'atf_expect_signal.3', 'atf_expect_timeout.3', 'atf_fail.3', 'atf_get.3', 'atf_get_srcdir.3', 'atf_init_test_cases.3', 'atf_pass.3', 'atf_require_kmod.3', 'atf_require_prog.3', 'atf_set.3', 'atf_skip.3', 'atf_test_case.3']
def shell_support(name):
    tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=atf-man"], "//conditions:default": ["package=atf"]})
    bsd_install_file(name = name + "_subr", src = "//contrib/atf:atf-sh/libatf-sh.subr", destination = "/usr/share/atf/libatf-sh.subr", owner = "root", group = "wheel", mode = "0444", install_tags = ["package=atf"])
    bsd_compress(name = name + "_manual", src = "//contrib/atf:atf-sh/atf-sh.3", output = name + "/atf-sh.3.gz", arguments = ["-cn"],
        compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    bsd_install_file(manual = True, name = name + "_man", src = ":" + name + "_manual", destination = "/usr/share/man/man3/atf-sh.3.gz", owner = "root", group = "wheel", mode = "0444", install_tags = tags)
    entries = [":" + name + "_subr", ":" + name + "_man"]
    for alias in _MANUAL_ALIASES:
        target = name + "_" + alias.replace(".", "_")
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man3/" + alias + ".gz", target = "/usr/share/man/man3/atf-sh.3.gz", kind = "hardlink", owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
