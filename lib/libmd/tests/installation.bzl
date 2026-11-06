# SPDX-License-Identifier: BSD-2-Clause
"""Native libmd installed-test payloads and declared ATF generation."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary", "bsd_script_wrapper")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")
load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_import")
load("//tools/build/bazel:bsd_link_sequence.bzl", "bsd_link_sequence")
load("//lib/libc:test_policy.bzl", "libc_test_copts")
load("//tools/build/bazel:bsd_atf.bzl", "bsd_atf_test")
load("//tools/build/bazel:bsd_test_installation.bzl", "bsd_test_install_archive")
load("//tools/build/bazel:bsd_install_archive.bzl", "bsd_install_archive_set")
load("//tools/build/bazel:bsd_utility_installation.bzl", "utility_installation")

def _atf(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.run(
        executable = ctx.attr.redirect[DefaultInfo].files_to_run,
        arguments = [output.path, ctx.executable.shell.path, ctx.file.script.path] + ctx.attr.digests,
        inputs = [ctx.file.script], tools = [ctx.attr.shell[DefaultInfo].files_to_run],
        outputs = [output], env = {"LC_ALL": "C"}, use_default_shell_env = False,
        mnemonic = "LibmdAtfScript",
    )
    return [DefaultInfo(files = depset([output]))]

_atf_body = rule(implementation = _atf, attrs = {
    "digests": attr.string_list(mandatory = True),
    "script": attr.label(allow_single_file = True, mandatory = True),
    "shell": attr.label(executable = True, cfg = "exec", allow_single_file = True, mandatory = True),
    "redirect": attr.label(executable = True, cfg = "exec", mandatory = True),
})

def libmd_test_installation(name, digests):
    _atf_body(name = name + "_body", digests = digests, script = "gen-tests.sh",
              shell = "@bsd_sdk//toolchain:sh", redirect = "@bsd_sdk//toolchain:stdout_redirect")
    bsd_script_wrapper(name = "libmd_test", body = ":" + name + "_body", interpreter = "/usr/libexec/atf-sh",
                       cat = "@bsd_sdk//toolchain:cat", cat_runtime = ["@bsd_sdk//toolchain:cat_runtime"],
                       redirect = "@bsd_sdk//toolchain:stdout_redirect")
    bsd_kyuafile(name = "kyuafile", suite = "FreeBSD", names = ["libmd_test"], interfaces = {"libmd_test": "atf"})
    files = [("script", ":libmd_test", "/usr/tests/lib/libmd/libmd_test", "0555", ["package=tests"]),
             ("kyua", ":kyuafile", "/usr/tests/lib/libmd/Kyuafile", "0444", ["package=tests"])]
    for digest in digests:
        bsd_debug_split(name = digest + "_install_debug", src = ":" + digest + "_shared_driver",
                        binary_name = "install/" + digest + "driver", debug_name = "install/" + digest + "driver.debug",
                        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy", objcopy_inputs = "@bsd_sdk//toolchain:objcopy_inputs", testonly = True)
        bsd_strip_binary(name = digest + "_install", src = ":" + digest + "_install_debug",
                         output = "stripped/" + digest + "driver", strip = "@bsd_sdk//toolchain:bin/llvm-strip",
                         strip_inputs = "@bsd_sdk//toolchain:strip_inputs", testonly = True)
        native.filegroup(name = digest + "_debug_artifact", srcs = [":" + digest + "_install_debug"], output_group = "debug_files", testonly = True)
        files += [(digest + "_driver", ":" + digest + "_install", "/usr/tests/lib/libmd/" + digest + "driver", "0555", ["package=tests"]),
                  (digest + "_debug", ":" + digest + "_debug_artifact", "/usr/lib/debug/usr/tests/lib/libmd/" + digest + "driver.debug", "0444", ["dbg", "package=tests"]),
                  (digest + "_ref", digest + ".ref", "/usr/tests/lib/libmd/" + digest + ".ref", "0444", ["package=tests"])]
    entries = []
    for suffix, src, path, mode, tags in files:
        target = name + "_" + suffix
        bsd_install_file(name = target, src = src, destination = path, mode = mode,
                         owner = "root", group = "wheel", install_tags = tags, testonly = True)
        entries.append(":" + target)
    bsd_install_manifest(name = name, entries = entries, testonly = True, visibility = ["//visibility:public"])

# The historical component qualification above remains separate and portable.
DRIVERS = {'md4': ('mddriver.c', ['MD=4']), 'md5': ('mddriver.c', ['MD=5']), 'rmd160': ('rmddriver.c', ['RMD=160']), 'sha0': ('shadriver.c', ['SHA=0']), 'sha1': ('shadriver.c', ['SHA=1']), 'sha224': ('shadriver.c', ['SHA=224']), 'sha256': ('shadriver.c', ['SHA=256']), 'sha384': ('shadriver.c', ['SHA=384']), 'sha512': ('shadriver.c', ['SHA=512']), 'sha512t224': ('shadriver.c', ['SHA=512224']), 'sha512t256': ('shadriver.c', ['SHA=512256']), 'skein256': ('skeindriver.c', ['SKEIN=256']), 'skein512': ('skeindriver.c', ['SKEIN=512']), 'skein1024': ('skeindriver.c', ['SKEIN=1024'])}
_PLATFORM = ["@platforms//os:freebsd", "@platforms//cpu:x86_64"]

def libmd_system_tests():
    cc_import(name = "installed_md_abi", shared_library = "//lib/libmd:md_shared", deps = ["//lib/libmd:test_headers"])
    bsd_link_sequence(name = "installed_driver_abi", deps = [":installed_md_abi", "//lib/libc:shared_abi_interface"], target_compatible_with = _PLATFORM)
    entries = []
    for digest, (source, definitions) in DRIVERS.items():
        cc_binary(name = digest + "_installed_driver", srcs = [source], local_defines = definitions,
            deps = [":installed_driver_abi"], copts = libc_test_copts(6), defines = ["PIC"],
            linkopts = ["-pie", "-nodefaultlibs"], target_compatible_with = _PLATFORM)
        utility_installation(name = "system_" + digest, program = digest + "driver", binary = ":" + digest + "_installed_driver",
            manual = None, package = "tests", bindir = "/usr/tests/lib/libmd")
        bsd_install_file(name = "system_" + digest + "_ref", src = digest + ".ref", destination = "/usr/tests/lib/libmd/" + digest + ".ref",
            owner = "root", group = "wheel", mode = "0444", install_tags = ["package=tests"])
        entries.append(":system_" + digest + "_ref")
    for label, basename, mode in [(":libmd_test", "libmd_test", "0555"), (":kyuafile", "Kyuafile", "0444")]:
        name = "system_" + basename
        bsd_install_file(name = name, src = label, destination = "/usr/tests/lib/libmd/" + basename,
            owner = "root", group = "wheel", mode = mode, install_tags = ["package=tests"])
        entries.append(":" + name)
    bsd_install_manifest(name = "system_install_manifest", manifests = [":system_" + d for d in DRIVERS], entries = entries)
    bsd_test_install_archive(name = "install_archive", directory = "/usr/tests/lib/libmd", manifests = [":system_install_manifest"], debug = True)
    bsd_install_archive_set(name = "installation_archives", archives = [":install_archive"], target_compatible_with = _PLATFORM, visibility = ["//visibility:public"])
    runtime = ["//lib/libmd:md_shared", "//lib/atf/libatf-c:atf_c_shared", "//lib/libc:c_shared", "//lib/libsys:sys_shared",
        "//lib/atf/libatf-c++:atf_cxx_shared", "//lib/libc++:cxx_shared", "//lib/libcxxrt:cxxrt_shared", "//lib/msun:m_shared", "//lib/libgcc_s:gcc_s_shared"]
    for digest in DRIVERS:
        bsd_atf_test(name = "installed_" + digest, body = ":install_manifest_body", case_name = digest,
            subr = "//libexec/atf/atf-sh:shell_library",
            data_paths = {":system_" + digest + "_stripped": digest + "driver", digest + ".ref": digest + ".ref"},
            runtime_bin = ["//bin/sh:sh", "//libexec/atf/atf-sh:atf-sh", "//libexec/atf/atf-check:atf-check", "//usr.bin/dirname:dirname"],
            runtime_lib = runtime, test_environment = {"DTRACE_DOF_INIT_DISABLE": "1"}, runner = "//tools/build/bazel:atf_runner",
            tags = ["external", "no-remote"], body_timeout_seconds = 300, timeout = "long", size = "small", target_compatible_with = _PLATFORM)
    native.test_suite(name = "installed_tests", tests = [":installed_" + d for d in DRIVERS])
