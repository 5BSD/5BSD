# SPDX-License-Identifier: BSD-2-Clause
"""Source-owned component order and native runtime for shared-LLVM tools.

clang.prog.mk/llvm.prog.mk supply their component libraries. Other recipes,
such as lld/Makefile, can supply their own ordered component list. The C++
driver runtime follows those libraries, including terminal pthread ordering.
Bootstrap/static recipes require their own declared dependency contracts.
"""
LLVM_COMPONENT_LIBRARIES = [
    "//lib/clang/libllvm:llvm", "//lib/libz:z", "//lib/libzstd:zstd",
    "//lib/libexecinfo:execinfo", "//lib/ncurses/tinfo:tinfo",
]
CLANG_COMPONENT_LIBRARIES = [
    "//lib/clang/libclang:clang", "//lib/clang/libllvm:llvm",
    "//lib/libz:z", "//lib/libzstd:zstd", "//lib/libexecinfo:execinfo",
    "//lib/ncurses/ncurses:ncurses",
]

def shared_tool_libraries(components = LLVM_COMPONENT_LIBRARIES):
    libraries = components + [
        "//lib/libthr:thr", "//lib/libc++:cxx", "//lib/libcxxrt:cxxrt", "//lib/msun:m",
    ]
    return libraries, [library + "_shared" for library in libraries]
