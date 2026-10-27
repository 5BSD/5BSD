# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_script_output.bzl", "bsd_script_output")
load(":entries.bzl", "DEFAULT_ENTRIES")
def termcap_small(name, entries = DEFAULT_ENTRIES, testonly = False):
    for entry in entries:
        if not entry or any([c in entry for c in [" ", "\t", "\n", "\r"]]):
            fail("termcap entries must be nonempty individual patterns")
    bsd_script_output(name = name, testonly = testonly, script = "//etc/termcap:generate-small.sh",
        src = "//share/termcap:termcap", input_mode = "argument", arguments = [" ".join(entries)],
        output = name + "/termcap.small", path_tools = {"@bsd_sdk//toolchain:awk": "awk"},
        shell = "@bsd_sdk//toolchain:sh", redirect = "@bsd_sdk//toolchain:stdout_redirect",
        runtime = ["@bsd_sdk//toolchain:sh_runtime", "@bsd_sdk//toolchain:awk_runtime"])
