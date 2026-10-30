# SPDX-License-Identifier: BSD-2-Clause
"""Initial amd64 GENERIC kernel compilation policy; other configurations pending."""
AMD64_KERNEL_FLAGS = [
    "-nostdinc", "-ffreestanding", "-fno-strict-aliasing", "-fcommon",
    "-include", "opt_global.h", "-mcmodel=kernel", "-mno-red-zone",
    "-mno-mmx", "-mno-sse", "-msoft-float", "-mno-aes", "-mno-avx",
    "-fno-asynchronous-unwind-tables", "-fno-omit-frame-pointer",
    "-mno-omit-leaf-frame-pointer", "-fwrapv", "-fstack-protector-strong",
    "-g", "-gdwarf-4", "-std=gnu17",
    # Match Make's logical machine/ header names in __FILE__ diagnostics.
    # BINDIR follows the selected Bazel configuration; never bake in an output path.
    "-fmacro-prefix-map=$(BINDIR)/sys/amd64/include/_virtual_includes/kernel_headers/=",

]
AMD64_KERNEL_HEADER_DEPS = [
    "//sys/amd64/conf:generic_global_headers", "//sys/sys:kernel_headers",
    "//sys/amd64/include:kernel_headers", "//sys/x86/include:kernel_headers",
    "//sys/bsm:kernel_headers",
]
