# $FreeBSD$

.include <src.opts.mk>

PROG_CXX=	dtraced
SRCS=		dtraced.cc \
		dtraced_clientrequest.cc \
		dtraced_connection.cc \
		dtraced_directory.cc \
		dtraced_dttransport.cc \
		dtraced_errmsg.cc \
		dtraced_id.cc \
		dtraced_job.cc \
		dtraced_misc.cc \
		dtraced_state.cc


MAN=		dtraced.8
WARNS?=		3

CFLAGS+=	-I${SRCTOP}/sys/dev/dttransport

CFLAGS+=	-Wall -Wextra -Wno-c11-extensions
CXXFLAGS+=	-Wno-c11-extensions -Wno-gcc-compat -Wno-gnu-anonymous-struct -Wno-zero-length-array -Wno-c99-designator
CSTD:=c11
CXXSTD:=c++17

LIBADD=	ctf elf proc pthread crypto util cxxrt

.if ${MK_DTRACE_OPTIMIZED} != "no" && ${MACHINE_ARCH} != mips && \
    ${MACHINE_ARCH} != mips64 && ${MACHINE_ARCH} != powerpc64 && \
    ${MACHINE_ARCH} != riscv64
CFLAGS+=	-flto
LDFLAGS+=	-flto
.endif

.if ${MK_DTRACED_ASAN} != "no"
CFLAGS+=	-fsanitize=address -fsanitize=undefined
LDFLAGS+=	-fsanitize=address -fsanitize=undefined
.elif ${MK_DTRACED_TSAN} != "no"
CFLAGS+=	-fsanitize=thread
LDFLAGS+=	-fsanitize=thread
.endif

.if ${MK_DTRACED_ROBUST} != "no"
CFLAGS+=	-DDTRACED_ROBUST
CFLAGS+=	-Wall -Wextra -ggdb3 -Werror -Wpedantic -Wno-gnu-include-next -Wno-nullability-extension -Wno-gnu-empty-struct -fcxx-exceptions
.endif

.if ${MK_DTRACED_DEBUG} != "no"
CFLAGS+=	-DDTRACED_DEBUG
.endif

.include <bsd.prog.mk>
