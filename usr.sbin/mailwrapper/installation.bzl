# SPDX-License-Identifier: BSD-2-Clause
"""The maintained MAILWRAPPER/DMAGENT/SENDMAIL installation choices."""
load("@bazel_skylib//lib:selects.bzl", "selects")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")

def mailwrapper_installation():
    config = "//tools/build/bazel/config:"
    for name, flag in [("mail_off", "mail"), ("wrapper_flag_off", "mailwrapper"),
                       ("sendmail_flag_off", "sendmail"), ("dma_flag_off", "dmagent"),
                       ("openssl_off", "openssl")]:
        native.config_setting(name = name, flag_values = {config + flag: "false"})
    # src.opts.mk disables DMA for !MAIL or !OPENSSL. Do not substitute a
    # selector with additional unrelated requirements such as MK_CRYPT.
    native.config_setting(name = "dma_on", flag_values = {
        config + "mail": "true", config + "dmagent": "true", config + "openssl": "true"})
    for name, members in [
        ("wrapper_off", [":mail_off", ":wrapper_flag_off"]),
        ("sendmail_off", [":mail_off", ":sendmail_flag_off"]),
        ("dma_off", [":mail_off", ":dma_flag_off", ":openssl_off"]),
        ("any_mailer", [config + "mailwrapper_enabled", config + "sendmail_enabled", ":dma_on"]),
        ("dma_or_no_sendmail", [":dma_on", ":sendmail_off"]),
    ]:
        selects.config_setting_group(name = name, match_any = members)
    for name, members in [
        ("fallback_dma", [":wrapper_off", ":dma_on"]),
        ("fallback_sendmail", [":wrapper_off", ":dma_off", config + "sendmail_enabled"]),
        ("wrapper_without_sendmail", [config + "mailwrapper_enabled", ":sendmail_off"]),
        ("config_dma", [config + "mailwrapper_enabled", ":dma_or_no_sendmail"]),
        ("config_sendmail", [config + "mailwrapper_enabled", ":dma_off", config + "sendmail_enabled"]),
    ]:
        selects.config_setting_group(name = name, match_all = members)

    utility_installation(name = "program_manifest", program = "mailwrapper", manual = "mailwrapper.8",
        package = "utilities", bindir = "/usr/sbin", man_section = "8")
    for name, source in [("dma", "//libexec/dma/dmagent:mailer.conf"), ("sendmail", "//etc/mail:mailer.conf")]:
        bsd_install_file(name = "config_" + name + "_file", src = source, destination = "/etc/mail/mailer.conf",
            owner = "root", group = "wheel", mode = "0644", install_tags = ["package=utilities", "config"])
    bsd_install_file(name = "sendmail_example", src = "//etc/mail:mailer.conf",
        destination = "/usr/share/examples/sendmail/mailer.conf", owner = "root", group = "wheel", mode = "0444",
        install_tags = ["package=sendmail"])
    aliases = []
    for name, directory, target in [
        ("mailq", "/usr/bin", "../sbin/mailwrapper"), ("newaliases", "/usr/bin", "../sbin/mailwrapper"),
        ("hoststat", "/usr/sbin", "mailwrapper"), ("purgestat", "/usr/sbin", "mailwrapper"),
        ("sendmail", "/usr/sbin", "mailwrapper"),
    ]:
        bsd_install_link(name = "alias_" + name, destination = directory + "/" + name, target = target,
            kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities"])
        aliases.append(":alias_" + name)
    for name, target in [("dma", "../libexec/dma"), ("sendmail", "../libexec/sendmail/sendmail")]:
        bsd_install_link(name = "fallback_" + name + "_link", destination = "/usr/sbin/mailwrapper", target = target,
            kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities"])
    bsd_install_link(name = "rmail_link", destination = "/bin/rmail", target = "../usr/sbin/mailwrapper",
        kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=utilities"])
    bsd_install_manifest(name = "selected_manifest", manifests = select({config + "mailwrapper_enabled": [":program_manifest"], "//conditions:default": []}),
        entries = select({":any_mailer": aliases, "//conditions:default": []}) +
            select({":fallback_dma": [":fallback_dma_link"], ":fallback_sendmail": [":fallback_sendmail_link"], "//conditions:default": []}) +
            select({":wrapper_without_sendmail": [":rmail_link"], "//conditions:default": []}) +
            select({":config_dma": [":config_dma_file"], ":config_sendmail": [":config_sendmail_file"], "//conditions:default": []}) +
            select({config + "sendmail_enabled": [":sendmail_example"], "//conditions:default": []}))
    bsd_install_archive(name = "install_archive", manifests = [":selected_manifest"],
        directories = select({config + "mailwrapper_enabled": {d: '{"owner":"root","group":"wheel","mode":"0755","tags":["package=utilities","dbg"]}' for d in ["/usr/lib/debug/usr", "/usr/lib/debug/usr/sbin"]} | {"/etc/mail": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=utilities"]}'}, "//conditions:default": {}}) |
            select({config + "sendmail_enabled": {"/usr/share/examples/sendmail": '{"owner":"root","group":"wheel","mode":"0755","tags":["package=sendmail"]}'}, "//conditions:default": {}}),
        mtree_specs = {"//etc/mtree:BSD.root.dist": "/", "//etc/mtree:BSD.usr.dist": "/usr", "//etc/mtree:BSD.debug.dist": "/usr/lib"},
        passwd = "//etc:master.passwd", group = "//etc:group", epoch = 0,
        mtree = "@bsd_sdk//toolchain:extra_mtree", python = "@bsd_sdk//toolchain:extra_python", python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib", "@bsd_sdk//toolchain:extra_mtree_runtime"], visibility = ["//visibility:public"])
