# SPDX-License-Identifier: BSD-2-Clause
"""Make-policy compile flags and component macros for declared BSD targets.

These constants mirror what share/mk/bsd.sys.mk, bsd.lib.mk and bsd.prog.mk
emit for a native amd64 clang world build with SRCCONF=/dev/null (debug files
enabled, PIE enabled, SSP enabled).  otel-probe.py compares every Bazel compile
action with the matching maintained Make command and fails on unexplained
drift, so changes in share/mk are detected instead of silently diverging.
"""

load(":cc_compat.bzl", "bsd_cc_binary", "bsd_cc_library")

BSD_CFLAGS = ["-O2", "-pipe", "-fno-common"]
BSD_DEBUG_CFLAGS = ["-g", "-gz=zlib"]
BSD_CSTD = ["-std=gnu17", "-Wno-format-zero-length"]
BSD_SSP_CFLAGS = ["-fstack-protector-strong"]
BSD_TAIL_CFLAGS = ["-Qunused-arguments"]

# bsd.lib.mk PIEFLAG for *.pieo objects (INTERNALLIB _pie.a and PIE programs).
BSD_PIEO_CFLAGS = ["-fpie", "-DPIC"]

# bsd.prog.mk adds this to CFLAGS when MK_PIE is enabled.
BSD_PROG_PIE_CFLAGS = ["-fPIE"]
BSD_PROG_PIE_LINKOPTS = ["-pie"]

# bsd.prog.mk links with ${CFLAGS}; of those only -gz=zlib changes the link
# (clang passes --compress-debug-sections=zlib to lld).
BSD_DEBUG_LINKOPTS = ["-gz=zlib"]

_WARNS_COMMON = ["-Wsystem-headers", "-Werror", "-Wall", "-Wno-format-y2k", "-W",
                 "-Wno-unused-parameter", "-Wstrict-prototypes", "-Wmissing-prototypes",
                 "-Wpointer-arith"]
_CLANG_TAIL = ["-Wno-empty-body", "-Wno-string-plus-int", "-Wno-unused-const-variable",
               "-Wno-error=unused-but-set-parameter", "-Wno-error=cast-function-type-mismatch"]

BSD_WARNS = {
    6: _WARNS_COMMON + ["-Wreturn-type", "-Wcast-qual", "-Wwrite-strings", "-Wswitch",
                        "-Wshadow", "-Wunused-parameter", "-Wcast-align", "-Wchar-subscripts",
                        "-Wnested-externs", "-Wold-style-definition", "-Wno-pointer-sign",
                        "-Wdate-time", "-Wmissing-variable-declarations", "-Wthread-safety"] +
       _CLANG_TAIL,
    3: _WARNS_COMMON + ["-Wno-uninitialized", "-Wno-pointer-sign", "-Wdate-time",
                        "-Wno-unknown-pragmas"] + _CLANG_TAIL +
       ["-Wno-tautological-compare", "-Wno-unused-value", "-Wno-parentheses-equality",
        "-Wno-unused-function", "-Wno-enum-conversion", "-Wno-unused-local-typedef",
        "-Wno-address-of-packed-member"],
}

# WARNS 1 (cddl/lib/libdtrace, dtrace(1)): bsd.sys.mk's C list, and the
# C++ list, which drops -Wno-pointer-sign.
_WARNS1_TAIL = ["-Wno-tautological-compare", "-Wno-unused-value", "-Wno-parentheses-equality",
                "-Wno-unused-function", "-Wno-enum-conversion", "-Wno-unused-local-typedef",
                "-Wno-address-of-packed-member", "-Wno-switch", "-Wno-switch-enum",
                "-Wno-knr-promoted-parameter", "-Wno-parentheses"]
BSD_WARNS[1] = (["-Wsystem-headers", "-Werror", "-Wno-pointer-sign", "-Wdate-time",
                 "-Wno-unknown-pragmas"] + _CLANG_TAIL + _WARNS1_TAIL)
BSD_CXX_WARNS = {
    1: ["-Wsystem-headers", "-Werror", "-Wdate-time", "-Wno-unknown-pragmas"] + _CLANG_TAIL +
       _WARNS1_TAIL,
}

# bsd.lib.mk PICFLAG for *.pico objects of a shared library.
BSD_PICO_CFLAGS = ["-fpic", "-DPIC"]

# bsd.sys.mk CXXFLAGS tail after the component's own CXXFLAGS: the debug
# flags again, the C++ standard and clang's C++ warning adjustments.
BSD_CXX_STD_TAIL = ["-Wno-c++20-extensions", "-Wno-c++23-lambda-attributes",
                    "-Wno-nullability-completeness"]

def bsd_cxxflags(warns, cxxstd, pico = False, local = [], cxx_local = []):
    """Make's CXXFLAGS for a .cc object: CFLAGS without the C-only flags, then
    the component CXXFLAGS, debug flags, -std and the C++ warning tail."""
    if warns not in BSD_CXX_WARNS:
        fail("unsupported C++ WARNS level for this pilot: %d" % warns)
    return ((BSD_PICO_CFLAGS if pico else []) + BSD_CFLAGS + local + BSD_DEBUG_CFLAGS +
            ["-Wno-format-zero-length"] + BSD_SSP_CFLAGS + BSD_CXX_WARNS[warns] +
            BSD_TAIL_CFLAGS + cxx_local + BSD_DEBUG_CFLAGS + ["-std=" + cxxstd] +
            BSD_CXX_STD_TAIL)

def bsd_cflags(warns, pieo = False, prog = False, local = [], pico = False):
    """Make's CFLAGS order: PIEFLAG, base, component CFLAGS, PIE, debug, std, SSP, WARNS."""
    if warns not in BSD_WARNS:
        fail("unsupported WARNS level for this pilot: %d" % warns)
    return ((BSD_PIEO_CFLAGS if pieo else []) + (BSD_PICO_CFLAGS if pico else []) +
            BSD_CFLAGS + local +
            (BSD_PROG_PIE_CFLAGS if prog else []) + BSD_DEBUG_CFLAGS + BSD_CSTD +
            BSD_SSP_CFLAGS + BSD_WARNS[warns] + BSD_TAIL_CFLAGS)

def bsd_internal_library(name, srcs, hdrs = [], warns = 6, deps = [], local_cflags = [],
                         linkopts = [], internal_libs = []):
    """INTERNALLIB: lib<name>.a and lib<name>_pie.a, as bsd.lib.mk builds them.

    `linkopts` carries the library's _DP_<name> system libraries so that
    consumers link them the way src.libnames.mk adds them to LDADD.
    No shared object exists for an INTERNALLIB; none is created here.
    Consumers add the header directory separately (Make: CFLAGS+=-I...),
    normally through a sibling header-only target.  `internal_libs` are
    other INTERNALLIBs in _DP_<name>; the PIE variant links their _pie
    archives, as src.libnames.mk selects ${PIE_SUFFIX}.
    """
    bsd_cc_library(name = name, srcs = srcs, hdrs = hdrs,
                   deps = deps + internal_libs,
                   copts = bsd_cflags(warns, local = local_cflags),
                   linkopts = linkopts, linkstatic = True)
    bsd_cc_library(name = name + "_pie", srcs = srcs, hdrs = hdrs,
                   deps = deps + [x + "_pie" for x in internal_libs],
                   copts = bsd_cflags(warns, pieo = True, local = local_cflags),
                   linkopts = linkopts, linkstatic = True)

def bsd_program(name, srcs, warns = 6, deps = [], local_cflags = [], linkopts = [],
                testonly = False):
    """Dynamic PIE program equivalent to bsd.prog.mk's PROG.full (before debug split).

    A program that links a shared library built in the workspace (dtrace(1)
    and libdtrace.so.2) gets Bazel's PIC compile mode, whose toolchain flags
    are -fPIC -DPIC; Make compiles program objects with -fpie -DPIC only
    (bsd_cflags), so the toolchain "pic" flags are disabled for programs.
    """
    bsd_cc_binary(name = name, srcs = srcs, deps = deps, testonly = testonly,
                  features = ["-pic"],
                  copts = bsd_cflags(warns, pieo = True, prog = True, local = local_cflags),
                  linkstatic = True,
                  linkopts = BSD_DEBUG_LINKOPTS + BSD_PROG_PIE_LINKOPTS + linkopts)

def bsd_atf_test_c(name, srcs, warns = 6, deps = [], local_cflags = [], linkopts = []):
    """ATF_TESTS_C program linked with the SDK's private ATF C library (bsd.test.mk)."""
    bsd_program(name = name, srcs = srcs, warns = warns, deps = deps,
                local_cflags = local_cflags, linkopts = ["-lprivateatf-c"] + linkopts,
                testonly = True)
