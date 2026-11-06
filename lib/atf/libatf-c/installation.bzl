# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_compress")
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary")

_HEADERS = ['atf-c.h', 'atf-c/build.h', 'atf-c/check.h', 'atf-c/defs.h', 'atf-c/error.h', 'atf-c/error_fwd.h', 'atf-c/macros.h', 'atf-c/tc.h', 'atf-c/tp.h', 'atf-c/utils.h']
_MANUAL_ALIASES = ['ATF_CHECK.3', 'ATF_CHECK_MSG.3', 'ATF_CHECK_EQ.3', 'ATF_CHECK_EQ_MSG.3', 'ATF_CHECK_MATCH.3', 'ATF_CHECK_MATCH_MSG.3', 'ATF_CHECK_STREQ.3', 'ATF_CHECK_STREQ_MSG.3', 'ATF_CHECK_ERRNO.3', 'ATF_REQUIRE.3', 'ATF_REQUIRE_MSG.3', 'ATF_REQUIRE_EQ.3', 'ATF_REQUIRE_EQ_MSG.3', 'ATF_REQUIRE_MATCH.3', 'ATF_REQUIRE_MATCH_MSG.3', 'ATF_REQUIRE_STREQ.3', 'ATF_REQUIRE_STREQ_MSG.3', 'ATF_REQUIRE_ERRNO.3', 'ATF_TC.3', 'ATF_TC_BODY.3', 'ATF_TC_BODY_NAME.3', 'ATF_TC_CLEANUP.3', 'ATF_TC_CLEANUP_NAME.3', 'ATF_TC_HEAD.3', 'ATF_TC_HEAD_NAME.3', 'ATF_TC_NAME.3', 'ATF_TC_WITH_CLEANUP.3', 'ATF_TC_WITHOUT_HEAD.3', 'ATF_TP_ADD_TC.3', 'ATF_TP_ADD_TCS.3', 'atf_tc_get_config_var.3', 'atf_tc_get_config_var_wd.3', 'atf_tc_get_config_var_as_bool.3', 'atf_tc_get_config_var_as_bool_wd.3', 'atf_tc_get_config_var_as_long.3', 'atf_tc_get_config_var_as_long_wd.3', 'atf_no_error.3', 'atf_tc_expect_death.3', 'atf_tc_expect_exit.3', 'atf_tc_expect_fail.3', 'atf_tc_expect_pass.3', 'atf_tc_expect_signal.3', 'atf_tc_expect_timeout.3', 'atf_tc_fail.3', 'atf_tc_fail_nonfatal.3', 'atf_tc_pass.3', 'atf_tc_require_kmod.3', 'atf_tc_require_prog.3', 'atf_tc_skip.3', 'atf_utils_cat_file.3', 'atf_utils_compare_file.3', 'atf_utils_copy_file.3', 'atf_utils_create_file.3', 'atf_utils_file_exists.3', 'atf_utils_fork.3', 'atf_utils_free_charpp.3', 'atf_utils_grep_file.3', 'atf_utils_grep_string.3', 'atf_utils_readline.3', 'atf_utils_redirect.3', 'atf_utils_wait.3', 'atf-c-api.3']

def library_installation(name):
    bsd_debug_split(name = name + "_debug", src = ":atf_c_shared",
        binary_name = name + "/libprivateatf-c.so.1", debug_name = name + "/libprivateatf-c.so.1.debug",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs")
    bsd_strip_binary(name = name + "_stripped", src = ":" + name + "_debug", output = name + "/stripped/libprivateatf-c.so.1",
        strip = "@bsd_sdk//toolchain:bin/llvm-strip", strip_inputs = "@bsd_sdk//toolchain:strip_inputs")
    native.filegroup(name = name + "_symbols", srcs = [":" + name + "_debug"], output_group = "debug_files")
    files = [
        (":static_archive", "/usr/lib/libprivateatf-c.a", ["package=atf", "dev"]),
        (":" + name + "_stripped", "/usr/lib/libprivateatf-c.so.1", ["package=atf", "lib"]),
        (":" + name + "_symbols", "/usr/lib/debug/usr/lib/libprivateatf-c.so.1.debug", ["package=atf", "dbg"]),
    ]
    entries = []
    for source, destination, tags in files:
        target = name + "_file_" + destination.replace("/", "_")
        bsd_install_file(name = target, src = source, destination = destination,
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_link(name = name + "_link", destination = "/usr/lib/libprivateatf-c.so", target = "libprivateatf-c.so.1",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=atf", "dev"])
    entries.append(":" + name + "_link")
    for header in _HEADERS:
        target = name + "_header_" + header.replace("/", "_").replace(".", "_")
        bsd_install_file(name = target, src = "//contrib/atf:" + header,
            destination = "/usr/include/" + header, owner = "root", group = "wheel",
            mode = "0444", install_tags = ["package=atf", "dev"])
        entries.append(":" + target)
    tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=atf-man"], "//conditions:default": ["package=atf-dev"]})
    bsd_compress(name = name + "_manual", src = "//contrib/atf:atf-c/atf-c.3", output = name + "/atf-c.3.gz",
        arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect",
        runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
    bsd_install_file(manual = True, name = name + "_man", src = ":" + name + "_manual", destination = "/usr/share/man/man3/atf-c.3.gz",
        owner = "root", group = "wheel", mode = "0444", install_tags = tags)
    entries.append(":" + name + "_man")
    for alias in _MANUAL_ALIASES:
        target = name + "_man_" + alias.replace(".", "_")
        bsd_install_link(manual = True, name = target, destination = "/usr/share/man/man3/" + alias + ".gz",
            target = "/usr/share/man/man3/atf-c.3.gz", kind = "hardlink",
            owner = "root", group = "wheel", mode = "0444", install_tags = tags)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, visibility = ["//visibility:public"])
