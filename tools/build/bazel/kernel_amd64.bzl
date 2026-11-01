# SPDX-License-Identifier: BSD-2-Clause
"""Initial amd64 GENERIC kernel compilation policy; other configurations pending."""
AMD64_KERNEL_WARNING_FLAGS = select({
    "//tools/build/bazel/config:werror_enabled": ["-Werror"],
    "//conditions:default": [],
}) + [
    "-Wall", "-Wstrict-prototypes", "-Wmissing-prototypes", "-Wpointer-arith",
    "-Wcast-qual", "-Wundef", "-Wno-pointer-sign", "-Wmissing-include-dirs",
    "-fdiagnostics-show-option", "-Wno-unknown-pragmas", "-Wswitch",
    "-Wno-error=tautological-compare", "-Wno-error=empty-body",
    "-Wno-error=parentheses-equality", "-Wno-error=unused-function",
    "-Wno-error=pointer-sign", "-Wno-error=shift-negative-value",
    "-Wno-address-of-packed-member", "-Wno-format-zero-length",
]
AMD64_KERNEL_FLAGS = [
    "-nostdinc", "-ffreestanding", "-fno-strict-aliasing", "-fcommon",
    "-include", "opt_global.h", "-mcmodel=kernel", "-mno-red-zone",
    "-mno-mmx", "-mno-sse", "-msoft-float", "-mno-aes", "-mno-avx",
    "-fno-asynchronous-unwind-tables", "-fno-omit-frame-pointer",
    "-mno-omit-leaf-frame-pointer", "-fwrapv", "-fstack-protector-strong",
    "-std=gnu17",
    # Match Make's logical generated-header paths in diagnostics and DWARF.
    # BINDIR follows the selected Bazel configuration; never bake in an output path.
    "-fmacro-prefix-map=$(BINDIR)/sys/amd64/include/_virtual_includes/kernel_headers/=",
    "-fdebug-prefix-map=$(BINDIR)/sys/kern/_virtual_includes/vnode_headers=.",
    "-fdebug-prefix-map=$(BINDIR)/sys/x86/include/_virtual_includes/kernel_headers/x86=sys/x86/include",
    "-fdebug-prefix-map=$(BINDIR)/sys/amd64/include/_virtual_includes/kernel_headers/machine=sys/amd64/include",
]
AMD64_KERNEL_DEBUG_FLAGS = select({
    "//tools/build/bazel/config:kernel_ctf_and_debug_enabled": ["-g", "-gdwarf-4"],
    "//tools/build/bazel/config:kernel_ctf_enabled": ["-g", "-gdwarf-4"],
    "//tools/build/bazel/config:kernel_debug_enabled": ["-g", "-gdwarf-4"],
    "//conditions:default": ["-g0"],
})
AMD64_KERNEL_HEADER_DEPS = [
    "//sys/amd64/conf:generic_global_headers", "//sys/sys:kernel_headers",
    "//sys/amd64/include:kernel_headers", "//sys/x86/include:kernel_headers",
    "//sys/bsm:kernel_headers",
]
