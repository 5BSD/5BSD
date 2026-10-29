# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_compress")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")

def kyua_installation(name):
    entries = []
    examples = []
    for source, destination in [('AUTHORS', '/usr/share/doc/kyua/AUTHORS'), ('CONTRIBUTORS', '/usr/share/doc/kyua/CONTRIBUTORS'), ('LICENSE', '/usr/share/doc/kyua/LICENSE'), ('misc/context.html', '/usr/share/kyua/misc/context.html'), ('misc/index.html', '/usr/share/kyua/misc/index.html'), ('misc/report.css', '/usr/share/kyua/misc/report.css'), ('misc/test_result.html', '/usr/share/kyua/misc/test_result.html'), ('store/migrate_v1_v2.sql', '/usr/share/kyua/store/migrate_v1_v2.sql'), ('store/migrate_v2_v3.sql', '/usr/share/kyua/store/migrate_v2_v3.sql'), ('store/schema_v3.sql', '/usr/share/kyua/store/schema_v3.sql')]:
        target = name + "_" + source.replace("/", "_")
        bsd_install_file(name = target, src = "//contrib/kyua:" + source, destination = destination, owner = "root", group = "wheel", mode = "0444", install_tags = ["package=kyua"])
        entries.append(":" + target)
    for source, destination in [('examples/Kyuafile.top', '/usr/share/examples/kyua/Kyuafile.top'), ('examples/kyua.conf', '/usr/share/examples/kyua/kyua.conf')]:
        target = name + "_" + source.replace("/", "_")
        bsd_install_file(name = target, src = "//contrib/kyua:" + source, destination = destination, owner = "root", group = "wheel", mode = "0444", install_tags = ["package=kyua"])
        examples.append(":" + target)
    bsd_install_file(name = name + "_configuration", src = "kyua.conf-default", destination = "/etc/kyua/kyua.conf", owner = "root", group = "wheel", mode = "0644", install_tags = ["package=kyua", "config"])
    entries.append(":" + name + "_configuration")
    for manual in ['kyua-about.1', 'kyua-config.1', 'kyua-db-exec.1', 'kyua-db-migrate.1', 'kyua-debug.1', 'kyua-help.1', 'kyua-list.1', 'kyua-report-html.1', 'kyua-report-junit.1', 'kyua-report.1', 'kyua-test.1', 'kyua.1', 'kyua.conf.5', 'kyuafile.5']:
        target = name + "_manual_" + manual
        bsd_compress(name = target, src = "//contrib/kyua:doc/" + manual, output = name + "/" + manual + ".gz", arguments = ["-cn"], compressor = "@bsd_sdk//toolchain:extra_gzip", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_gzip_runtime"])
        bsd_install_file(name = target + "_file", src = ":" + target, destination = "/usr/share/man/man" + manual[-1] + "/" + manual + ".gz", owner = "root", group = "wheel", mode = "0444", install_tags = select({"//tools/build/bazel/config:split_manpages_enabled": ["package=kyua-man"], "//conditions:default": ["package=kyua"]}))
        entries.append(":" + target + "_file")
    utility_installation(name = name, program = "kyua", manual = None, package = "kyua", extra_entries = entries + select({"//tools/build/bazel/config:examples_enabled": examples, "//conditions:default": []}))
