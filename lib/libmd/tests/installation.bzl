# SPDX-License-Identifier: BSD-2-Clause
"""Native libmd installed-test payloads and declared ATF generation."""
load("//tools/build/bazel:bsd_artifacts.bzl", "bsd_debug_split", "bsd_strip_binary", "bsd_script_wrapper")
load("//tools/build/bazel:bsd_install.bzl", "bsd_install_file", "bsd_install_manifest", "bsd_kyuafile")

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
