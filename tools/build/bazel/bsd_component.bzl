# SPDX-License-Identifier: BSD-2-Clause
"""Make-policy compile flags and component macros for declared BSD targets.

These constants mirror what share/mk/bsd.sys.mk, bsd.lib.mk and bsd.prog.mk
emit for a native amd64 clang world build with SRCCONF=/dev/null (debug files
enabled, PIE enabled, SSP enabled).  otel-probe.py compares every Bazel compile
action with the matching maintained Make command and fails on unexplained
drift, so changes in share/mk are detected instead of silently diverging.
"""

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

def bsd_cflags(warns, pieo = False, prog = False, local = []):
    """Make's CFLAGS order: PIEFLAG, base, component CFLAGS, PIE, debug, std, SSP, WARNS."""
    if warns not in BSD_WARNS:
        fail("unsupported WARNS level for this pilot: %d" % warns)
    return ((BSD_PIEO_CFLAGS if pieo else []) + BSD_CFLAGS + local +
            (BSD_PROG_PIE_CFLAGS if prog else []) + BSD_DEBUG_CFLAGS + BSD_CSTD +
            BSD_SSP_CFLAGS + BSD_WARNS[warns] + BSD_TAIL_CFLAGS)

def bsd_internal_library(name, srcs, hdrs = [], warns = 6, deps = [], local_cflags = [],
                         linkopts = []):
    """INTERNALLIB: lib<name>.a and lib<name>_pie.a, as bsd.lib.mk builds them.

    `linkopts` carries the library's _DP_<name> system libraries so that
    consumers link them the way src.libnames.mk adds them to LDADD.
    No shared object exists for an INTERNALLIB; none is created here.
    Consumers add the header directory separately (Make: CFLAGS+=-I...),
    normally through a sibling header-only target.
    """
    native.cc_library(name = name, srcs = srcs, hdrs = hdrs, deps = deps,
                      copts = bsd_cflags(warns, local = local_cflags),
                      linkopts = linkopts, linkstatic = True)
    native.cc_library(name = name + "_pie", srcs = srcs, hdrs = hdrs, deps = deps,
                      copts = bsd_cflags(warns, pieo = True, local = local_cflags),
                      linkopts = linkopts, linkstatic = True)

def bsd_program(name, srcs, warns = 6, deps = [], local_cflags = [], linkopts = [],
                testonly = False):
    """Dynamic PIE program equivalent to bsd.prog.mk's PROG.full (before debug split)."""
    native.cc_binary(name = name, srcs = srcs, deps = deps, testonly = testonly,
                     copts = bsd_cflags(warns, pieo = True, prog = True, local = local_cflags),
                     linkstatic = True,
                     linkopts = BSD_DEBUG_LINKOPTS + BSD_PROG_PIE_LINKOPTS + linkopts)

def bsd_atf_test_c(name, srcs, warns = 6, deps = [], local_cflags = [], linkopts = []):
    """ATF_TESTS_C program linked with the SDK's private ATF C library (bsd.test.mk)."""
    bsd_program(name = name, srcs = srcs, warns = warns, deps = deps,
                local_cflags = local_cflags, linkopts = ["-lprivateatf-c"] + linkopts,
                testonly = True)
