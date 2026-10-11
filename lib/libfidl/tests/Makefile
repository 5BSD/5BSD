# SPDX-License-Identifier: BSD-2-Clause
.include <src.opts.mk>

PACKAGE= libfidl-tests
TESTSDIR= ${TESTSBASE}/lib/libfidl
NO_SHARED= yes
CSTD= c11
CXXSTD= c++20
WARNS?= 0

.include "../runtime-includes.mk"
CFLAGS+= -I${FIDLGEN.runtime}
CXXFLAGS+= -I${SRCTOP}/contrib/googletest/googletest/include

# The bindings are generated from runtime.fidl at build time.
BINDING_SRCS= ${FIDLGEN_SRCS.runtime}
PLAIN_TESTS_C+= c_binding_test
SRCS.c_binding_test= c_binding_test.c ${BINDING_SRCS}
.if ${MK_GOOGLETEST} != "no"
GTESTS+= runtime_test
SRCS.runtime_test= runtime_test.cc allocation_fault.cc ${BINDING_SRCS}
LIBADD.runtime_test+= gtest_main
# Static linkage is required: fault injection must cover runtime allocations.
LDFLAGS.runtime_test+= -Wl,--wrap=malloc,--wrap=_Znwm,--wrap=_Znam
.endif
LIBADD= fidl_bsd
TEST_METADATA+= timeout="180"

# Comparative IPC measurement, installed for in-VM use (not a Kyua test):
#   ipc_bench raw|cpp|c PAYLOAD CALLS WARMUP
PROGS_CXX+= ipc_bench
BINDIR_ipc_bench= ${TESTSDIR}
MAN.ipc_bench=
SRCS.ipc_bench= ipc_bench.cc ${BINDING_SRCS}
LIBADD.ipc_bench+= channel
LDFLAGS.ipc_bench+= -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free

# These binaries embed upstream code, so the test package carries its notices.
FILESGROUPS+= FIDL_NOTICE
FIDL_NOTICE= ${FUCHSIA}/LICENSE ${FUCHSIA}/PATENTS
FIDL_NOTICEDIR= /usr/share/licenses/libfidl-tests/fuchsia
FIDL_NOTICEPACKAGE= ${PACKAGE}
.if ${MK_GOOGLETEST} != "no"
FILESGROUPS+= GTEST_NOTICE
GTEST_NOTICE= ${SRCTOP}/contrib/googletest/LICENSE
GTEST_NOTICEDIR= /usr/share/licenses/libfidl-tests/googletest
GTEST_NOTICEPACKAGE= ${PACKAGE}
.endif

# Bindings generated at build time (fidl-bindings.mk).
FIDL_BINDINGS+=	runtime
FIDL_SCHEMAS.runtime=	lib/libfidl/tests/zx.fidl \
	lib/libfidl/tests/runtime.fidl
FIDL_LIBRARY.runtime=	bsd.runtime.test
.include "${SRCTOP}/lib/libfidl/fidl-bindings.mk"

.include <bsd.test.mk>

# The binding objects are shared by several programs, and bsd.progs.mk records
# no compiler dependencies for shared objects; rebuild them when the runtime
# headers, and with them class layouts, change.
FIDL_RUNTIME_HEADERS= ${SRCTOP}/lib/libfidl/include/fidl/bsd/c_bridge.h \
    ${SRCTOP}/lib/libfidl/include/fidl/bsd/descriptor.h \
    ${SRCTOP}/lib/libfidl/include/fidl/bsd/empty.h \
    ${SRCTOP}/lib/libfidl/include/fidl/bsd/endpoint.h \
    ${SRCTOP}/lib/libfidl/include/fidl/bsd/runtime.h \
    ${SRCTOP}/lib/libfidl/include/fidl/bsd/runtime_c.h \
    ${SRCTOP}/lib/libchannel/channel.h
.for obj in ${BINDING_SRCS:R:S/$/.o/}
${obj}: ${FIDL_RUNTIME_HEADERS}
.endfor
