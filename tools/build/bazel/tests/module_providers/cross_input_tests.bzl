# SPDX-License-Identifier: BSD-2-Clause
load("//tools/build/bazel:bsd_python_test.bzl", "bsd_host_artifact_test")
load("//tools/build/bazel:bsd_kernel_module.bzl", "bsd_module_exports")

# Inspect cross-target ELF artifacts with the native execution toolchain.
# The negative fixture deliberately removes the real hgame callback exports.
def cross_input_provider_tests(arch, hid_modules):
    modules = {name: target.replace(":generic_module", ":" + arch + "_generic_module")
               for name, target in hid_modules.items()}
    modules.update({
        "uinput": "//sys/modules/uinput:" + arch + "_generic_module",
        "usbhid": "//sys/modules/usb/usbhid:" + arch + "_generic_module",
    })
    bsd_host_artifact_test(
        name = arch + "_input_known_providers_test",
        src = "check.py",
        data = modules.values(),
        args = [arg for name, target in modules.items()
                for arg in ["--module", name + "=$(location " + target + ")"]] + [
            "--require-edge", "ps4dshock", "hgame", "hgame_hat_switch_cb",
            "--require-edge", "ps5dsense", "hgame", "hgame_hat_switch_cb",
            "--require-edge", "xb360gp", "hgame", "hgame_dpad_cb",
            "--require-edge", "xb360gp", "hgame", "hgame_final_cb",
        ],
    )
    localized = arch + "_localized_hgame"
    bsd_module_exports(
        name = localized,
        src = "//sys/modules/hid/hgame:" + arch + "_generic_localized",
        output = "negative/" + arch + "/hgame.local.kld",
        exports = [],
        nm = "@bsd_sdk//toolchain:bin/llvm-nm",
        objcopy = "@bsd_sdk//toolchain:bin/llvm-objcopy",
        tool_inputs = ["@bsd_sdk//toolchain:llvm-nm_runtime", "@bsd_sdk//toolchain:objcopy_inputs"],
        redirect = "@bsd_sdk//toolchain:stdout_redirect",
        libraries = ["//lib/msun:m_shared", "@bsd_sdk//toolchain:sysroot/lib/libc.so.7", "@bsd_sdk//toolchain:sysroot/lib/libsys.so.7"],
        python = "@bsd_sdk//toolchain:extra_python",
        python_home = "@bsd_sdk//toolchain:python-home/runtime.json",
        runtime = ["@bsd_sdk//toolchain:python_stdlib"],
    )
    consumers = {name: modules[name] for name in ["ps4dshock", "ps5dsense", "xb360gp"]}
    bsd_host_artifact_test(
        name = arch + "_localized_hgame_rejected_test",
        src = "check.py",
        data = [":" + localized] + consumers.values(),
        args = ["--expect-localized", "--module", "hgame=$(location :" + localized + ")"] + [
            arg for name, target in consumers.items()
            for arg in ["--module", name + "=$(location " + target + ")"]
        ],
    )
