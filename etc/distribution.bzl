# SPDX-License-Identifier: BSD-2-Clause
"""Native fresh-stage etc distribution; install/afterinstall remain separate."""
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_link", "bsd_install_manifest", "bsd_install_directory")
load("//tools/build/bazel:bsd_script_installation.bzl", "script_install_archive")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_m4.bzl", "bsd_m4")

def etc_distribution():
    # Keep installed and generated files distinct from account initialization.
    common, mail, sendmail, kerberos, unbound, boot = [], [], [], [], [], []
    def_file = [
        ("copyright", "//:COPYRIGHT", "/COPYRIGHT", "0444", "runtime", False, common),
        ("aliases", "//etc/mail:aliases", "/etc/mail/aliases", "0644", "runtime", True, mail),
        ("k5login", "root/dot.k5login", "/root/.k5login", "0644", "runtime", True, kerberos),
        ("device_hints", select({"@platforms//cpu:x86_64": "//sys/amd64/conf:GENERIC.hints", "@platforms//cpu:aarch64": "//sys/arm64/conf:GENERIC.hints", "@platforms//cpu:riscv64": "//sys/riscv/conf:GENERIC.hints"}), "/boot/device.hints", "0444", "bootloader", True, boot),
    ]
    for filename in ["Makefile", "README", "access.sample", "virtusertable.sample", "mailertable.sample"]:
        def_file.append(("mail_" + filename, "//etc/mail:" + filename, "/etc/mail/" + filename, "0644", "sendmail", False, sendmail))
    for filename in ["freebsd", "freebsd.submit"]:
        bsd_m4(name = filename + "_cf", output = "generated/" + filename + ".cf", src = "sendmail/" + filename + ".mc",
            prefixes = ["//contrib/sendmail:cf/m4/cf.m4"], directory_defines = {"//contrib/sendmail:cf/README": "_CF_DIR_"},
            includes = ["//contrib/sendmail:cf_m4_inputs"], flags = ["-D_NO_MAKEINFO_"],
            m4 = "@bsd_sdk//toolchain:extra_m4", redirect = "@bsd_sdk//toolchain:stdout_redirect", runtime = ["@bsd_sdk//toolchain:extra_m4_runtime"])
        mode = "0444" if filename == "freebsd.submit" else "0644"
        for suffix, source in [("mc", "sendmail/" + filename + ".mc"), ("cf", ":" + filename + "_cf")]:
            def_file.append((filename + "_" + suffix, source, "/etc/mail/" + filename + "." + suffix, mode, "sendmail", True, sendmail))
        def_file.append((filename + "_active", ":" + filename + "_cf", "/etc/mail/" + ("submit.cf" if filename == "freebsd.submit" else "sendmail.cf"), mode, "sendmail", True, sendmail))
    def_file.append(("helpfile", "//contrib/sendmail:src/helpfile", "/etc/mail/helpfile", "0444", "sendmail", True, sendmail))
    for name, source, destination, mode, package, config, group in def_file:
        bsd_install_file(name = "distribution_" + name, src = source, destination = destination,
            owner = "root", group = "wheel", mode = mode, install_tags = ["package=" + package] + (["config"] if config else []))
        group.append(":distribution_" + name)
    for name, destination, target, package, group in [
        ("os_release", "/etc/os-release", "../var/run/os-release", "runtime", common),
        ("termcap", "/etc/termcap", "/usr/share/misc/termcap", "ncurses-lib", common),
        ("unbound", "/etc/unbound", "../var/unbound", "local-unbound", unbound),
        ("aliases", "/etc/aliases", "mail/aliases", "runtime", mail),
    ]:
        bsd_install_link(name = "distribution_link_" + name, destination = destination, target = target,
            kind = "symlink", owner = "root", group = "wheel", mode = "0755", install_tags = ["package=" + package])
        group.append(":distribution_link_" + name)
    gss = {}
    for variant, files in [("mit", ["mech"]), ("heimdal", ["mech", "qop"])]:
        gss[variant] = []
        for filename in files:
            name = "distribution_gss_" + variant + "_" + filename
            bsd_install_file(name = name, src = ("gss-krb5/" if variant == "mit" else "gss/") + filename,
                destination = "/etc/gss/" + filename, owner = "root", group = "wheel", mode = "0444", install_tags = ["package=utilities"])
            gss[variant].append(":" + name)
    mtree = []
    for filename in ["BSD.debug.dist", "BSD.include.dist", "BSD.root.dist", "BSD.usr.dist", "BSD.var.dist", "BSD.sendmail.dist", "BSD.tests.dist"]:
        name = "distribution_mtree_" + filename
        bsd_install_file(name = name, src = "//etc/mtree:" + filename, destination = "/etc/mtree/" + filename,
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=mtree"])
        mtree.append(":" + name)
    # src.opts.mk marks LIB32 unconditionally broken; no missing spec is invented.
    common.append("//usr.sbin/rmt:compat_link")
    for directory, package in [("gss", "utilities"), ("mtree", "mtree")]:
        name = "distribution_directory_" + directory
        bsd_install_directory(name = name, destination = "/etc/" + directory,
            owner = "root", group = "wheel", mode = "0755", install_tags = ["package=" + package])
        common.append(":" + name)
    bsd_install_manifest(name = "distribution_manifest", entries = common + mtree[:5] +
        select({"//tools/build/bazel/config:sendmail_enabled": sendmail + [mtree[5]], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:tests_enabled": [mtree[6]], "//conditions:default": []}) +
        select({"//tools/build/bazel/config:mail_enabled": mail, "//conditions:default": []}) +
        select({"//tools/build/bazel/config:unbound_enabled": unbound, "//conditions:default": []}) +
        select({"//tools/build/bazel/config:kerberos_requested": kerberos, "//conditions:default": []}) +
        select({"//tools/build/bazel/config:boot_enabled": boot, "//conditions:default": []}) +
        select({"//tools/build/bazel/config:mitkrb5_requested": gss["mit"], "//conditions:default": gss["heimdal"]}))
    script_install_archive(name = "distribution_archive", manifest = ":distribution_manifest")
    bsd_install_archive_set(name = "distribution_archives", archives = [":distribution_archive"], visibility = ["//visibility:public"])
