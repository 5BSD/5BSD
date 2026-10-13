SHLIBDIR?=	/lib

.include <src.opts.mk>

.include <src.opts.mk>

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/common
.PATH: ${SRCTOP}/cddl/contrib/opensolaris/lib/libgen/common

CXXFLAGS+=	-Werror					\
		-Wall					\
		-Wextra					\
		-Wpedantic				\
		-Wno-gnu-include-next			\
		-Wno-nullability-extension		\
		-Wno-gcc-compat				\
		-Wno-unknown-pragmas			\
		-Wno-c11-extensions			\
		-Wno-zero-length-array			\
		-Wno-gnu-anonymous-struct		\
		-Wno-nested-anon-types			\
		-Wno-c99-extensions			\
		-Wno-gnu-zero-variadic-macro-arguments  \
		-Wno-variadic-macros

PACKAGE=	dtrace
LIB_CXX=	dtrace
SRCS=		dt_aggregate.c \
		dt_analysis.c \
		dt_as.c \
		dt_basic_block.cc \
		dt_benchmark.c \
		dt_buf.c \
		dt_cc.c \
		dt_cg.c \
		dt_consume.c \
		dt_decl.c \
		dt_dis.c \
		dt_dof.c \
		dt_elf.cc \
		dt_error.c \
		dt_errtags.c \
		dt_grammar.y \
		dt_handle.c \
		dt_hashmap.c \
		dt_hypertrace_linker.cc \
		dt_ident.c \
		dt_dfg.cc \
		dt_isadep.c \
		dt_inttab.c \
		dt_lex.l \
		dt_link.c \
		dt_linker_subr.cc \
		dt_list.c \
		dt_map.c \
		dt_module.c \
		dt_names.c \
		dt_open.c \
		dt_options.c \
		dt_parser.c \
		dt_pcb.c \
		dt_pid.c \
		dt_pq.c \
		dt_pragma.c \
		dt_print.c \
		dt_printf.c \
		dt_proc.c \
		dt_program.c \
		dt_provider.c \
		dt_regset.c \
		dt_resolver.c \
		dt_string.c \
		dt_strtab.c \
		dt_subr.c \
		dt_sugar.c \
		dt_typefile.cc \
		dt_typing.cc \
		dt_typing_helpers.cc \
		dt_typing_reg.cc \
		dt_typing_stack.cc \
		dt_typing_subr.cc \
		dt_typing_var.cc \
		dt_work.c \
		dt_xlator.c \
		gmatch.c

CXXSTD=	c++20

DSRCS=		errno.d			\
		io.d			\
		ip.d			\
		psinfo.d		\
		sctp.d			\
		siftr.d			\
		signal.d		\
		tcp.d			\
		socket.d		\
		udp.d			\
		udplite.d		\
		unistd.d

FILES=		${DSRCS}
FILESDIR=	/usr/lib/dtrace
FILESMODE=	${NOBINMODE}

INCSGROUPS=	INCS SYSINCS
SYSINCSDIR=	${INCLUDEDIR}/sys
INCS+=		${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/common/dtrace.h
SYSINCS+=	${SRCTOP}/sys/cddl/contrib/opensolaris/uts/common/sys/dtrace.h
SYSINCS+=	${SRCTOP}/sys/cddl/contrib/opensolaris/uts/common/sys/ctf_api.h

WARNS?=		1

CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -include ${SRCTOP}/sys/contrib/openzfs/include/os/freebsd/spl/sys/ccompile.h
CFLAGS+= -DHAVE_ISSETUGID
CXXFLAGS+=	-fno-rtti -fno-exceptions

CFLAGS+=	-I${.OBJDIR} -I${.CURDIR} \
		-I${SRCTOP}/sys/cddl/dev/dtrace/${MACHINE_ARCH} \
		-I${SRCTOP}/sys/cddl/dev/kinst \
		-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libctf/common \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libdtrace/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common \
		-I${SRCTOP}/usr.sbin/dtraced

#CFLAGS+=	-DYYDEBUG


.if ${MACHINE_CPUARCH} == "aarch64"
CFLAGS+=	-I${OPENSOLARIS_SYS_DISTDIR}/uts/aarch64
.PATH:		${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/aarch64
.PATH:		${SRCTOP}/sys/cddl/dev/dtrace/aarch64
.elif ${MACHINE_CPUARCH} == "amd64" || ${MACHINE_CPUARCH} == "i386"
CFLAGS+=	-I${SRCTOP}/sys/cddl/dev/dtrace/x86
CFLAGS+=	-I${OPENSOLARIS_SYS_DISTDIR}/uts/intel -DDIS_MEM
.PATH:		${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/i386
.PATH:		${SRCTOP}/sys/cddl/dev/dtrace/${MACHINE_ARCH}
.PATH:		${SRCTOP}/sys/cddl/dev/dtrace/x86
.elif ${MACHINE_CPUARCH} == "arm"
CFLAGS+=	-I${OPENSOLARIS_SYS_DISTDIR}/uts/arm
.PATH:		${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/arm
.PATH:		${SRCTOP}/sys/cddl/dev/dtrace/arm
.elif ${MACHINE_CPUARCH} == "powerpc"
CFLAGS+=	-I${OPENSOLARIS_SYS_DISTDIR}/uts/powerpc
.PATH:		${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/powerpc
.PATH:		${SRCTOP}/sys/cddl/dev/dtrace/powerpc
.elif ${MACHINE_CPUARCH} == "riscv"
CFLAGS+=	-I${OPENSOLARIS_SYS_DISTDIR}/uts/riscv
.PATH:		${SRCTOP}/cddl/contrib/opensolaris/lib/libdtrace/riscv
.PATH:		${SRCTOP}/sys/cddl/dev/dtrace/riscv
.else
# temporary hack
CFLAGS+=	-I${OPENSOLARIS_SYS_DISTDIR}/uts/intel
.endif

.if ${MACHINE_ARCH} == "i386" || ${MACHINE_ARCH} == "amd64"
SRCS+=		dis_tables.c instr_size.c
DSRCS+=		regs_x86.d
.endif

.if ${MACHINE_CPUARCH} == "riscv"
SRCS+=		instr_size.c
DSRCS+=		regs_riscv.d
.endif

.if ${MACHINE_CPUARCH} == "aarch64"
SRCS+=		instr_size.c
DSRCS+=		regs_aarch64.d
.endif
.if ${MK_DTRACE_BENCHMARKS} != "no"
CFLAGS+=	-D__DTRACE_RUN_BENCHMARKS__
.endif

.if ${MK_DTRACE_OPTIMIZED} != "no" && ${MACHINE_ARCH} != "mips" && \
    ${MACHINE_ARCH} != "mips64" && ${MACHINE_ARCH} != "powerpc64" && \
    ${MACHINE_ARCH} != "riscv64"
CFLAGS+=	-flto
LDFLAGS+=	-flto
.endif

YFLAGS+=-d

LIBADD=	ctf elf proc pthread rtld_db crypto xo
.if ${MK_DTRACE_ASAN} != "no"
CFLAGS+=	-fsanitize=address -fsanitize=undefined
CXXFLAGS+=	-fsanitize=address -fsanitize=undefined
LDFLAGS+=	-fsanitize=address -fsanitize=undefined
.endif

CLEANFILES=	dt_errtags.c dt_names.c

.include <bsd.lib.mk>

dt_errtags.c: ${OPENSOLARIS_USR_DISTDIR}/lib/libdtrace/common/dt_errtags.h
	sh ${OPENSOLARIS_USR_DISTDIR}/lib/libdtrace/common/mkerrtags.sh < ${.ALLSRC} > ${.TARGET}

dt_names.c: ${OPENSOLARIS_SYS_DISTDIR}/uts/common/sys/dtrace.h
	sh ${OPENSOLARIS_USR_DISTDIR}/lib/libdtrace/common/mknames.sh < ${.ALLSRC} > ${.TARGET}
